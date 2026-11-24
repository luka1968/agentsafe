"""Phase 9 safety/reliability tests.

Covers connection retries, retrieval degradation signalling (never present a
partial result as a full success), leg-failure resilience, malformed-record
handling, the non-destructive embedding-dimension migration guard, and the
dedup/index integrity guarantees. No live DB required.
"""

from __future__ import annotations

import pytest

from agentsafe.knowledge import db as kb_db
from agentsafe.knowledge.db import NeonKnowledgeStore, _row_to_record


# --- connection retries -----------------------------------------------------
class _Cur:
    def __init__(self, log):
        self.log = log

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.log.append(" ".join(str(sql).split()))


class _Conn:
    def __init__(self, log):
        self.log = log
        self.autocommit = False

    def cursor(self):
        return _Cur(self.log)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestConnectRetries:
    def test_retries_then_succeeds(self, monkeypatch):
        monkeypatch.setattr("time.sleep", lambda *a: None)
        calls = {"n": 0}

        def fake_connect(*a, **k):
            calls["n"] += 1
            if calls["n"] < 3:
                raise OSError("connection refused")
            return _Conn([])

        monkeypatch.setattr("psycopg.connect", fake_connect)
        conn = kb_db._connect("postgres://x/y", retries=3)
        assert conn is not None and calls["n"] == 3

    def test_raises_after_retries(self, monkeypatch):
        monkeypatch.setattr("time.sleep", lambda *a: None)
        monkeypatch.setattr("psycopg.connect",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("down")))
        with pytest.raises(OSError):
            kb_db._connect("postgres://x/y", retries=2)

    def test_statement_timeout_applied(self, monkeypatch):
        monkeypatch.setattr("time.sleep", lambda *a: None)
        log: list[str] = []
        monkeypatch.setattr("psycopg.connect", lambda *a, **k: _Conn(log))
        kb_db._connect("postgres://x/y", statement_timeout_ms=1234)
        assert any("statement_timeout = 1234" in s for s in log)


# --- retrieval degradation --------------------------------------------------
def _store(embedder):
    return NeonKnowledgeStore(dsn="postgres://x/y", vector_dim=8,
                              embedding_model=embedder, cache_capacity=4)


_ROW = {"id": "KB-1", "content_hash": "h1", "category": "reentrancy",
        "title": "t", "description": "d"}


class TestRetrievalDegradation:
    def test_vector_leg_failure_is_reported_not_silent(self, monkeypatch):
        s = _store(lambda q: [0.1] * 8)
        monkeypatch.setattr(s, "_leg_vector",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("boom")))
        monkeypatch.setattr(s, "_leg_lexical", lambda *a, **k: [dict(_ROW)])
        st: dict = {}
        hits = s.search("reentrancy q1", limit=2, status=st)
        assert hits  # still returns the lexical leg
        assert st["degraded"] is True
        assert "vector" in (st["reason"] or "")
        assert st["mode"] in ("lexical", "vector")

    def test_both_legs_fail_returns_empty_and_flags(self, monkeypatch):
        s = _store(lambda q: [0.1] * 8)
        monkeypatch.setattr(s, "_leg_vector",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("v")))
        monkeypatch.setattr(s, "_leg_lexical",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("l")))
        st: dict = {}
        assert s.search("q2", limit=2, status=st) == []
        assert st["empty"] is True and st["degraded"] is True

    def test_lexical_only_when_no_embedder_is_not_degraded(self, monkeypatch):
        s = _store(None)
        monkeypatch.setattr(s, "_leg_lexical", lambda *a, **k: [dict(_ROW)])
        st: dict = {}
        s.search("q3", limit=2, status=st)
        assert st["degraded"] is False
        assert st["vector_attempted"] is False
        assert st["mode"] == "lexical"

    def test_empty_query_returns_empty(self):
        assert _store(None).search("   ", limit=3) == []

    def test_last_search_status_exposed(self, monkeypatch):
        s = _store(None)
        monkeypatch.setattr(s, "_leg_lexical", lambda *a, **k: [dict(_ROW)])
        s.search("q4", limit=2)
        assert s._last_search_status["returned"] >= 1


# --- malformed records ------------------------------------------------------
class TestMalformedRecords:
    def test_row_to_record_survives_malformed_jsonb(self):
        rec = _row_to_record({
            "id": "x", "category": "oracle",
            "call_sequence": "{not valid json",
            "tags": "{bad", "structured_intel": "{bad",
            "preconditions": "not-a-list", "metadata": "not-a-dict"})
        assert rec["id"] == "x"
        assert isinstance(rec["tags"], list)
        assert isinstance(rec["structured_intel"], dict)


# --- migration safety -------------------------------------------------------
class _BackupCur:
    """Fake cursor driving _backup_then_drop_embeddings."""

    def __init__(self, rows: int, inserted: int, total_backed: int):
        self.rows, self.inserted, self.total_backed = rows, inserted, total_backed
        self.executed: list[str] = []
        self.rowcount = 0

    def execute(self, sql, params=None):
        s = " ".join(str(sql).split())
        self.executed.append(s)
        if s.startswith("SELECT count(*) AS c FROM knowledge_embeddings\n") or \
                "FROM knowledge_embeddings" in s and "backup_dim" not in s:
            self._next = {"c": self.rows}
        elif s.startswith("INSERT INTO knowledge_embeddings_backup_dim"):
            self.rowcount = self.inserted
        elif "FROM knowledge_embeddings_backup_dim" in s:
            self._next = {"c": self.total_backed}
        else:
            self.rowcount = 0

    def fetchone(self):
        return getattr(self, "_next", {"c": 0})


class TestMigrationSafety:
    def test_refuses_to_drop_without_complete_backup(self):
        cur = _BackupCur(rows=5, inserted=3, total_backed=3)
        with pytest.raises(RuntimeError):
            kb_db._backup_then_drop_embeddings(cur, 2048, 1024)
        assert not any(s.startswith("DROP TABLE") for s in cur.executed)

    def test_drops_after_complete_backup(self):
        cur = _BackupCur(rows=5, inserted=5, total_backed=5)
        kb_db._backup_then_drop_embeddings(cur, 2048, 1024)
        assert any(s.startswith("DROP TABLE knowledge_embeddings") for s in cur.executed)

    def test_empty_table_drops_without_backup(self):
        cur = _BackupCur(rows=0, inserted=0, total_backed=0)
        kb_db._backup_then_drop_embeddings(cur, 2048, 1024)
        assert any(s.startswith("DROP TABLE") for s in cur.executed)
        assert not any("INSERT INTO knowledge_embeddings_backup_dim" in s
                       for s in cur.executed)


# --- dedup / index integrity ------------------------------------------------
class TestIntegrity:
    def test_unique_dedup_constraints_present(self):
        schema = kb_db._SCHEMA
        assert "content_hash       text NOT NULL UNIQUE" in schema
        # (source_id, external_record_id) uniqueness is created by migrate()
        import inspect
        src = inspect.getsource(kb_db.NeonKnowledgeStore.migrate)
        assert "vk_source_eid_idx" in src and "UNIQUE" in src
