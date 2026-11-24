"""Embedding-integrity report + safe back-fill tests (no live DB)."""

from __future__ import annotations

from agentsafe.knowledge.integrity import (
    backfill_missing_embeddings,
    embedding_integrity,
)


class _Cursor:
    def __init__(self, store):
        self.store = store
        self._row = None
        self._rows = []
        self.rowcount = 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        s = " ".join(sql.split())
        self._rows = []
        if s.startswith("SELECT embedding_model"):
            self._rows = [
                {"embedding_model": r.get("model", r.get("embedding_model")),
                 "dimensions": r.get("dim", r.get("dimensions")),
                 "c": r.get("count", r.get("c"))}
                for r in self.store.stored]
        elif "FROM knowledge_embeddings" in s and "embedding IS NULL" in s \
                and s.startswith("SELECT count"):
            self._rows = [{"c": self.store.null_vecs}]
        elif s.startswith("SELECT count(*) c FROM knowledge_embeddings"):
            self._rows = [{"c": self.store.total}]
        elif "LEFT JOIN knowledge_embeddings" in s and s.startswith("SELECT count"):
            self._rows = [{"c": len(self.store.missing_rows)}]
        elif "HAVING count(*)>1" in s:
            self._rows = [{"c": 0}]
        elif "to_regclass" in s:
            self._rows = [{"t": self.store.hnsw}]
        elif "LEFT JOIN knowledge_embeddings" in s and "SELECT vk.id" in s:
            self._rows = [dict(r) for r in self.store.missing_rows]
        self._row = self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._row


class _Conn:
    def __init__(self, store):
        self.store = store

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cursor(self):
        return _Cursor(self.store)


class _Store:
    def __init__(self, *, stored=None, total=0, null_vecs=0, missing=None,
                 hnsw="ke_hnsw_idx"):
        self.vector_dim = 8
        self.stored = stored if stored is not None else [
            {"model": "nvidia/nemotron-3.5-embed-1b", "dim": 8, "count": 10}]
        self.total = total
        self.null_vecs = null_vecs
        self.missing_rows = missing or []
        self.hnsw = hnsw

    def _connect(self):
        return _Conn(self)


class _Emb:
    name = "nvidia/nemotron-3.5-embed-1b"

    def __init__(self, dim=8):
        self.dim = dim

    def embed(self, texts):
        return [[0.1] * self.dim for _ in texts]


class TestIntegrityReport:
    def test_ok_when_consistent(self):
        store = _Store(total=10, missing=[])
        rep = embedding_integrity(store, _Emb(dim=8))
        assert rep["ok"] is True
        assert rep["mismatches"] == []
        assert rep["hnsw_index_present"] is True

    def test_dim_mismatch_detected(self):
        store = _Store(total=10)
        rep = embedding_integrity(store, _Emb(dim=2048))
        assert rep["ok"] is False
        assert any("dim" in m for m in rep["mismatches"])

    def test_no_embedder_detected(self):
        rep = embedding_integrity(_Store(total=5), None)
        assert rep["ok"] is False
        assert any("no embedder" in m for m in rep["mismatches"])

    def test_missing_vectors_flagged(self):
        store = _Store(total=10, missing=[{"id": 1}, {"id": 2}])
        rep = embedding_integrity(store, _Emb(dim=8))
        assert rep["records_without_embedding"] == 2
        assert rep["ok"] is False

    def test_multiple_models_detected(self):
        store = _Store(stored=[
            {"model": "a", "dim": 8, "count": 5},
            {"model": "b", "dim": 8, "count": 5}], total=10)
        rep = embedding_integrity(store, _Emb(dim=8))
        assert any("multiple embedding models" in m for m in rep["mismatches"])


class TestBackfill:
    def test_embeds_only_missing(self):
        rows = [{"id": 1, "title": "t", "description": "d", "root_cause": None,
                 "preconditions": [], "impact": None, "remediation": None}]
        store = _Store(total=0, missing=rows)
        summary = backfill_missing_embeddings(store, _Emb(dim=8))
        assert summary.missing == 1 and summary.embedded == 1 and not summary.failed

    def test_no_embedder_is_reported(self):
        s = backfill_missing_embeddings(_Store(), None)
        assert s.errors and s.embedded == 0
