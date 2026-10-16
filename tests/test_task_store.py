"""Task store acceptance: restart recovery, cleanup, concurrency."""

import threading

import pytest

from agentsafe.schemas import StageState, StageStatus, TaskState
from agentsafe.task_store import (
    MemoryTaskStore,
    SqliteTaskStore,
    new_task_id,
    open_task_store,
)

ADDR = "0x" + "ab" * 20


class TestTaskId:
    def test_unguessable_and_wellformed(self):
        ids = {new_task_id() for _ in range(50)}
        assert len(ids) == 50
        for t in ids:
            assert 20 <= len(t) <= 32

    def test_no_secret_embedding(self):
        assert "ghp" not in new_task_id() and "sk-" not in new_task_id()


class TestSqliteStore:
    def test_create_get_roundtrip(self, tmp_path):
        store = SqliteTaskStore(tmp_path / "tasks.db")
        task = store.create_task(ADDR)
        assert task.state is TaskState.QUEUED
        fetched = store.get(task.task_id)
        assert fetched is not None and fetched.address == ADDR

    def test_unknown_task_returns_none(self, tmp_path):
        store = SqliteTaskStore(tmp_path / "tasks.db")
        assert store.get("nope") is None

    def test_restart_recovery_via_persistent_file(self, tmp_path):
        """Service restart = new store instance on the same db file."""
        db = tmp_path / "tasks.db"
        s1 = SqliteTaskStore(db)
        task = s1.create_task(ADDR)
        s1.link_run(task.task_id, 12345)
        s1.set_state(task.task_id, TaskState.RUNNING)
        s1.upsert_stage(task.task_id, StageStatus(name="fetch_source", state=StageState.COMPLETED))

        s2 = SqliteTaskStore(db)  # "restarted" service
        recovered = s2.get(task.task_id)
        assert recovered is not None
        assert recovered.run_id == 12345
        assert recovered.state is TaskState.RUNNING
        assert recovered.stages[0].name == "fetch_source"

    def test_concurrent_updates_are_serialized(self, tmp_path):
        store = SqliteTaskStore(tmp_path / "tasks.db")
        task = store.create_task(ADDR)

        def hammer(i):
            store.link_run(task.task_id, i)
            store.set_state(task.task_id, TaskState.RUNNING)
            store.upsert_stage(
                task.task_id, StageStatus(name=f"stage{i}", state=StageState.RUNNING)
            )

        threads = [threading.Thread(target=hammer, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        got = store.get(task.task_id)
        assert got.run_id is not None
        assert len(got.stages) == 8

    def test_link_run_unknown_task_raises(self, tmp_path):
        store = SqliteTaskStore(tmp_path / "tasks.db")
        with pytest.raises(KeyError):
            store.link_run("missing", 1)

    def test_cleanup_expired(self, tmp_path):
        import time

        store = SqliteTaskStore(tmp_path / "tasks.db")
        task = store.create_task(ADDR)
        time.sleep(0.02)  # guarantee created_at < cutoff (Windows clock ticks)
        assert store.cleanup_expired(retention_days=0) == 1
        assert store.get(task.task_id) is None


class TestMemoryStore:
    def test_basic_flow(self):
        store = MemoryTaskStore()
        task = store.create_task(ADDR)
        store.link_run(task.task_id, 7)
        store.set_state(task.task_id, TaskState.COMPLETED)
        got = store.get(task.task_id)
        assert got.run_id == 7 and got.state is TaskState.COMPLETED
        assert store.get("zzz") is None

    def test_cleanup(self):
        import time

        store = MemoryTaskStore()
        store.create_task(ADDR)
        time.sleep(0.02)
        assert store.cleanup_expired(retention_days=0) == 1


class TestFactory:
    def test_open_store_modes(self, tmp_path):
        assert isinstance(open_task_store("sqlite", tmp_path / "t.db"), SqliteTaskStore)
        assert isinstance(open_task_store("memory", tmp_path / "t.db"), MemoryTaskStore)
        with pytest.raises(ValueError):
            open_task_store("redis", tmp_path / "t.db")
