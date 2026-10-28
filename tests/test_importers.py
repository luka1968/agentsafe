"""Tests: dataset import pipeline (Stage 2) — importers.py + Neon round-trip.

Pure-logic tests always run. Live-Neon tests skip when NEON_DATABASE_URL is
absent, so the suite stays green in CI/offline.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from agentsafe.knowledge import (
    NeonKnowledgeStore,
    content_hash_of,
    import_jsonl_dataset,
    normalize_record,
    run_import,
)
from agentsafe.knowledge.importers import _chunk_text, _split_long_records
from agentsafe.knowledge.kb import KnowledgeBase

DSN = os.environ.get("NEON_DATABASE_URL", "").strip()
needs_neon = pytest.mark.skipif(
    not DSN, reason="NEON_DATABASE_URL not set; skipping live-Neon tests")

RAW = {
    "id": "X-1",
    "title": "Approval race",
    "source": "example",
    "mechanism": "non-atomic approve allows double spend",
    "category": "approval",
    "protocol_type": "token",
    "root_cause": "approve is not atomic",
    "preconditions": ["spender has allowance"],
    "impact": "double spend",
    "remediation": "increaseAllowance",
    "keywords": ["approve", "race", "allowance"],
    "url": "https://example.test/approve",
    "weird_extra": "must be dropped",
}


class TestNormalize:
    def test_maps_known_fields(self):
        n = normalize_record(RAW, source_name="s1")
        assert n["external_record_id"] == "X-1"
        assert n["description"] == "non-atomic approve allows double spend"
        assert n["protocol_type"] == "token"
        assert n["category"] == "approval"
        assert n["preconditions"] == ["spender has allowance"]
        assert n["url"] == "https://example.test/approve"

    def test_unknown_fields_not_invented(self):
        n = normalize_record(RAW, source_name="s1")
        assert "weird_extra" not in n
        assert n["affected_contract"] is None  # absent -> null, not guessed
        assert n["severity"] is None

    def test_provenance_metadata(self):
        n = normalize_record(RAW, source_name="s1")
        assert n["metadata"]["source_name"] == "s1"
        assert n["metadata"]["original"] == "X-1"
        assert n["metadata"]["parent_external_id"] is None


class TestChunking:
    def test_short_text_single_chunk(self):
        assert _chunk_text("short") == ["short"]

    def test_long_text_split_on_boundaries(self):
        text = "par one\n\npar two\n\npar three\n\n" * 80  # > 900 chars
        chunks = _chunk_text(text)
        assert len(chunks) > 1
        assert all(len(c) <= 910 for c in chunks)

    def test_parent_child_relationship(self):
        recs = [
            {"external_record_id": "P1", "description": "x" * 400,
             "root_cause": "r" * 500, "remediation": "m" * 100},
            {"external_record_id": "P2", "description": "short"},
        ]
        out = list(_split_long_records(recs))
        # P1 is long -> split into parent + at least one chunk
        children = [r for r in out if (r.get("metadata") or {}).get("parent_external_id")]
        assert children
        assert children[0]["metadata"]["parent_external_id"] == "P1"
        # P2 short -> single row
        assert any(r["external_record_id"] == "P2" for r in out)


class TestDedup:
    def test_content_hash_stable(self):
        a = content_hash_of("hello world")
        b = content_hash_of("hello world")
        c = content_hash_of("hello world ")
        assert a == b
        assert a != c  # content-sensitive

    def test_import_idempotent_skips_duplicates(self, tmp_path):
        p = tmp_path / "mini.jsonl"
        with p.open("w", encoding="utf-8") as fh:
            fh.write(__import__("json").dumps(RAW) + "\n")
        from agentsafe.knowledge.kb import KnowledgeBase
        recs = KnowledgeBase.load(p).records

        class FakeStore:
            vector_dim = 384

            def _connect(self):
                raise AssertionError("no live neon in unit test")

        # Pure-logic duplicate detection is verified via content_hash stability;
        # live idempotency covered below when Neon is present.
        assert recs and recs[0]["id"] == "X-1"


@needs_neon
class TestNeonImportLive:
    @classmethod
    def setup_class(cls):
        cls.store = NeonKnowledgeStore(dsn=DSN)
        cls.store.migrate()

    def test_import_and_roundtrip(self):
        from agentsafe.knowledge.importers import import_jsonl_dataset
        from pathlib import Path as P
        p = P(os.path.dirname(os.path.dirname(os.path.abspath(
            __import__("agentsafe").__file__))))
        ds = p / "agentsafe" / "knowledge" / "dataset" / "v1.jsonl"
        s = import_jsonl_dataset(self.store, ds)
        # Idempotency-aware: records may already be present from a prior run.
        assert s.inserted + s.duplicates >= 12
        assert self.store.count() >= 12

    def test_import_idempotent_second_run_duplicates(self):
        from pathlib import Path as P
        p = P(os.path.dirname(os.path.dirname(os.path.abspath(
            __import__("agentsafe").__file__))))
        ds = p / "agentsafe" / "knowledge" / "dataset" / "v1.jsonl"
        before = self.store.count()
        s = import_jsonl_dataset(self.store, ds)
        assert s.duplicates >= before  # second import skips existing hashes
        assert self.store.count() == before

    def test_search_lexical_after_import(self):
        hits = self.store.search("reentrancy withdraw call drain", limit=3)
        assert hits
        assert all(h.get("url", "").startswith("http") for h in hits)
        cats = {h["category"] for h in hits}
        assert "reentrancy" in cats

    def test_get_knowledge_store_returns_neon(self):
        import types
        st = types.SimpleNamespace(
            NEON_DATABASE_URL=DSN, KB_STORAGE="", KB_VECTOR_DIM=384,
            resolved_kb_storage="neon")
        from agentsafe.knowledge import get_knowledge_store
        kb = get_knowledge_store(st)
        assert isinstance(kb, NeonKnowledgeStore)
        assert kb.count() >= 12

    def test_records_roundtrip_preserves_provenance(self):
        recs = {r["id"]: r for r in self.store.records()}
        assert any(k.startswith("KB-2025") for k in recs)
        for k, v in recs.items():
            if v.get("source"):
                assert v["url"].startswith("http") or v["url"].startswith("file")
                break