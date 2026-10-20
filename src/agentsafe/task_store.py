"""Task state store.

Authority rule (E_VERSION_PLAN Prompt 8): GitHub Actions run state + artifacts
are the authoritative execution record. The local store persists ONLY the
task_id -> run_id association (plus state cache) so the MCP service can
recover after restart. If no durable writable storage exists, use
MemoryTaskStore and accept that restarts require GitHub-side reconstruction.

task_id uses secrets.token_urlsafe - unguessable, no secrets embedded.
"""

from __future__ import annotations

import logging
import secrets
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from agentsafe.schemas import StageState, StageStatus, TaskState, TaskStatus

logger = logging.getLogger("agentSAFE.taskstore")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    task_id     TEXT PRIMARY KEY,
    address     TEXT NOT NULL,
    run_id      INTEGER,
    state       TEXT NOT NULL,
    error_code  TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS task_stages (
    task_id     TEXT NOT NULL,
    name        TEXT NOT NULL,
    state       TEXT NOT NULL,
    detail      TEXT,
    started_at  TEXT,
    finished_at TEXT,
    PRIMARY KEY (task_id, name)
);
"""

# Phase 12: payment binding columns, added by an idempotent migration.
_MIGRATION_COLUMNS = {
    "paid": "INTEGER NOT NULL DEFAULT 0",
    "payment_ref": "TEXT",
}


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def new_task_id() -> str:
    return secrets.token_urlsafe(18)  # 24 chars, 144 bits entropy


class MemoryTaskStore:
    """Non-persistent fallback. Restarts lose task_id->run_id links unless
    reconstructed from GitHub - documented limitation, never silently safe."""

    def __init__(self) -> None:
        self._tasks: dict[str, TaskStatus] = {}
        self._lock = threading.Lock()

    def create_task(self, address: str) -> TaskStatus:
        with self._lock:
            task = TaskStatus(
                task_id=new_task_id(),
                address=address,
                state=TaskState.QUEUED,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )
            self._tasks[task.task_id] = task
            return task.model_copy(deep=True)

    def mark_paid(self, task_id: str, payment_ref: str) -> None:
        with self._lock:
            t = self._tasks.get(task_id)
            if t:
                t.paid = True
                t.payment_ref = payment_ref
                t.updated_at = datetime.now(UTC)

    def get(self, task_id: str) -> TaskStatus | None:
        with self._lock:
            t = self._tasks.get(task_id)
            return t.model_copy(deep=True) if t else None

    def link_run(self, task_id: str, run_id: int) -> None:
        with self._lock:
            t = self._tasks.get(task_id)
            if t:
                t.run_id = run_id
                t.updated_at = datetime.now(UTC)

    def set_state(self, task_id: str, state: TaskState, error_code: str | None = None) -> None:
        with self._lock:
            t = self._tasks.get(task_id)
            if t:
                t.state = state
                t.error_code = error_code or t.error_code
                t.updated_at = datetime.now(UTC)

    def upsert_stage(self, task_id: str, stage: StageStatus) -> None:
        with self._lock:
            t = self._tasks.get(task_id)
            if not t:
                return
            for i, s in enumerate(t.stages):
                if s.name == stage.name:
                    t.stages[i] = stage
                    break
            else:
                t.stages.append(stage)

    def cleanup_expired(self, retention_days: int) -> int:
        with self._lock:
            cutoff = datetime.now(UTC) - timedelta(days=retention_days)
            dead = [k for k, v in self._tasks.items() if v.created_at and v.created_at < cutoff]
            for k in dead:
                del self._tasks[k]
            return len(dead)


class SqliteTaskStore:
    """Single-file durable store for task_id -> run_id associations.

    Correct under concurrent access within one process (threading.Lock) and
    safe across process restarts. Suitable only where writable storage is
    actually durable - otherwise prefer GitHub-side reconstruction.
    """

    def __init__(self, db_path: Path, *, retention_days: int = 14) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._retention_days = retention_days
        self._lock = threading.Lock()
        with self._lock, self._connect() as conn:
            conn.executescript(_SCHEMA)
            self._migrate(conn)
            conn.commit()

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Idempotent column additions (Phase 12 payment binding)."""
        existing = {row[1] for row in conn.execute("PRAGMA table_info(tasks)")}
        for name, decl in _MIGRATION_COLUMNS.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE tasks ADD COLUMN {name} {decl}")

    def _connect(self):
        """Per-operation connection: commits on success, rollbacks on error,
        and ALWAYS closes (sqlite3's own ``with conn`` only manages the
        transaction, leaking the connection handle on Windows)."""

        @contextmanager
        def _managed() -> Iterator[sqlite3.Connection]:
            conn = sqlite3.connect(self._path, timeout=10)
            conn.row_factory = sqlite3.Row
            try:
                with conn:  # transaction scope: commit / rollback
                    yield conn
            finally:
                conn.close()

        return _managed()

    def create_task(self, address: str) -> TaskStatus:
        now = datetime.now(UTC)
        task = TaskStatus(
            task_id=new_task_id(),
            address=address,
            state=TaskState.QUEUED,
            created_at=now,
            updated_at=now,
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO tasks (task_id, address, run_id, state, error_code,"
                " created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
                (
                    task.task_id,
                    task.address,
                    None,
                    task.state.value,
                    None,
                    now.isoformat(),
                    now.isoformat(),
                ),
            )
        return task

    def mark_paid(self, task_id: str, payment_ref: str) -> None:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "UPDATE tasks SET paid = 1, payment_ref = ?, updated_at = ? WHERE task_id = ?",
                (payment_ref, _now_iso(), task_id),
            )
            if cur.rowcount == 0:
                raise KeyError(f"unknown task_id: {task_id}")

    def get(self, task_id: str) -> TaskStatus | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
            if row is None:
                return None
            stages = conn.execute(
                "SELECT * FROM task_stages WHERE task_id = ? ORDER BY rowid",
                (task_id,),
            ).fetchall()
        return _row_to_task(row, stages)

    def link_run(self, task_id: str, run_id: int) -> None:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "UPDATE tasks SET run_id = ?, updated_at = ? WHERE task_id = ?",
                (run_id, _now_iso(), task_id),
            )
            if cur.rowcount == 0:
                raise KeyError(f"unknown task_id: {task_id}")

    def set_state(self, task_id: str, state: TaskState, error_code: str | None = None) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE tasks SET state = ?, error_code = COALESCE(?, error_code),"
                " updated_at = ? WHERE task_id = ?",
                (state.value, error_code, _now_iso(), task_id),
            )

    def upsert_stage(self, task_id: str, stage: StageStatus) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO task_stages (task_id, name, state, detail, started_at,"
                " finished_at) VALUES (?,?,?,?,?,?)"
                " ON CONFLICT(task_id, name) DO UPDATE SET"
                " state=excluded.state, detail=COALESCE(excluded.detail, detail),"
                " started_at=COALESCE(excluded.started_at, started_at),"
                " finished_at=COALESCE(excluded.finished_at, finished_at)",
                (
                    task_id,
                    stage.name,
                    stage.state.value,
                    stage.detail,
                    stage.started_at.isoformat() if stage.started_at else None,
                    stage.finished_at.isoformat() if stage.finished_at else None,
                ),
            )

    def cleanup_expired(self, retention_days: int | None = None) -> int:
        days = retention_days if retention_days is not None else self._retention_days
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM tasks WHERE created_at < ?", (cutoff,))
            conn.execute("DELETE FROM task_stages WHERE task_id NOT IN (SELECT task_id FROM tasks)")
            return cur.rowcount


def _row_to_task(row: sqlite3.Row, stages: list[sqlite3.Row]) -> TaskStatus:
    return TaskStatus(
        task_id=row["task_id"],
        address=row["address"],
        state=TaskState(row["state"]),
        run_id=row["run_id"],
        error_code=row["error_code"],
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
        paid=bool(row["paid"]),
        payment_ref=row["payment_ref"],
        stages=[
            StageStatus(
                name=s["name"],
                state=StageState(s["state"]),
                detail=s["detail"],
                started_at=datetime.fromisoformat(s["started_at"]) if s["started_at"] else None,
                finished_at=datetime.fromisoformat(s["finished_at"]) if s["finished_at"] else None,
            )
            for s in stages
        ],
    )


class TaskStore(Protocol):
    """Structural interface both stores satisfy; lets server code type-check."""

    def create_task(self, address: str) -> TaskStatus: ...

    def get(self, task_id: str) -> TaskStatus | None: ...

    def link_run(self, task_id: str, run_id: int) -> None: ...

    def set_state(self, task_id: str, state: TaskState, error_code: str | None = None) -> None: ...

    def mark_paid(self, task_id: str, payment_ref: str) -> None: ...

    def upsert_stage(self, task_id: str, stage: StageStatus) -> None: ...

    def cleanup_expired(self, retention_days: int) -> int: ...


def open_task_store(mode: str, db_path: Path, *, retention_days: int = 14) -> TaskStore:
    """Factory. mode: 'sqlite' (durable) | 'memory' (restart-loses-links)."""
    if mode == "sqlite":
        return SqliteTaskStore(db_path, retention_days=retention_days)
    if mode == "memory":
        return MemoryTaskStore()
    raise ValueError(f"unknown task store mode: {mode!r}")


__all__ = [
    "MemoryTaskStore",
    "SqliteTaskStore",
    "TaskStore",
    "open_task_store",
    "new_task_id",
]
