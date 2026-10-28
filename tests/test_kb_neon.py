"""Tests: Neon persistence layer for the security knowledge base (G+).

Live-Neon tests skip automatically when NEON_DATABASE_URL is not set or the
DB is unreachable, so the suite stays green in CI/offline. When the DSN IS
available they exercise real migration, seeding, and hybrid search against
Postgres + pgvector.
"""

from __future__ import annotations

import os
import types

import pytest

from agentsafe.knowledge import NeonKnowledgeStore, get_knowledge_store
from agentsafe.knowledge.kb import KnowledgeBase

DSN = os.environ.get("NEON_DATABASE_URL", "").strip()


def _make_settings(dsn: str = DSN, kb_storage: str = ""):
    return types.SimpleNamespace(
        NEON_DATABASE_URL=dsn,
        KB_STORAGE=kb_storage,
        KB_VECTOR_DIM=384,
        resolved_kb_storage=(kb_storage or ("neon" if dsn else "jsonl")),
    )


needs_neon = pytest.mark.skipif(
    not DSN, reason="NEON_DATABASE_URL not set; skipping live-Neon tests")


class TestFallbackNoNeon:
    def test_no_dsn_falls_back_to_jsonl(self):
        kb = get_knowledge_store(_make_settings(dsn=""))
        assert isinstance(kb, KnowledgeBase)
        assert len(kb.records) >= 12

    def test_unreachable_neon_falls_back(self):
        # A bogus DSN should never raise out of the factory.
        kb = get_knowledge_store(
            _make_settings(dsn="postgresql://nobody:x@127.0.0.1:1/nope",
                           kb_storage="neon"))
        assert isinstance(kb, KnowledgeBase)

    def test_explicit_kb_storage_jsonl_ignores_dsn(self):
        kb = get_knowledge_store(
            _make_settings(dsn=DSN or "x", kb_storage="jsonl"))
        assert isinstance(kb, KnowledgeBase)


@needs_neon
class TestNeonLive:
    def test_migrate_and_seed(self):
        store = NeonKnowledgeStore(dsn=DSN)
        store.migrate()
        n = store.seed_from_jsonl(
            __import__("pathlib").Path(
                __import__("agentsafe").__file__).parent
            / "knowledge" / "dataset" / "v1.jsonl")
        assert n >= 12
        assert store.count() >= 12

    def test_search_lexical_returns_related(self):
        store = NeonKnowledgeStore(dsn=DSN)
        hits = store.search("reentrancy withdraw call drain", limit=3)
        assert hits
        cats = {h["category"] for h in hits}
        assert "reentrancy" in cats
        # provenance is preserved
        assert all(h.get("url", "").startswith("http") for h in hits)

    def test_search_no_query_empty(self):
        store = NeonKnowledgeStore(dsn=DSN)
        assert store.search("   ", limit=3) == []

    def test_records_roundtrip_preserves_provenance(self):
        store = NeonKnowledgeStore(dsn=DSN)
        recs = {r["id"]: r for r in store.records}
        assert "KB-2025-001" in recs
        assert recs["KB-2025-001"]["source"]
        assert isinstance(recs["KB-2025-001"]["keywords"], list)

    def test_get_knowledge_store_returns_neon(self):
        kb = get_knowledge_store(_make_settings())
        assert isinstance(kb, NeonKnowledgeStore)
        assert kb.count() >= 12