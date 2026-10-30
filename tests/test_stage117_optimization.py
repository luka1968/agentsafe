"""Stage 11.7 — performance optimization controls.

Covers the cost/latency optimizations shipped to close the live-LLM gaps:
- Session-scoped retrieval cache on NeonKnowledgeStore: same (query, focus,
  limit) within one audit is served from cache (deep-copied), eliminating
  repeated embedder + Neon round-trips; results identical.
- Scheduler default parallelism now reads SCHEDULER_MAX_CONCURRENT (agent
  parallelism within one audit, independent of MAX_CONCURRENT_AUDITS).
- Settings.provider property (primary provider) so the live benchmark path
  (eval_suite --llm live) actually works instead of raising AttributeError.
"""

from __future__ import annotations

import json

import pytest

from agentsafe.config import Settings
from agentsafe.knowledge.db import NeonKnowledgeStore


class _SlowFakeEmbedder:
    """Mimics the NVIDIA embedder cost: counts calls; returns deterministic
    vectors so identical queries produce identical results (cache invariant)."""

    def __init__(self) -> None:
        self.calls = 0

    def embed_query(self, q: str) -> list[float]:
        self.calls += 1
        h = abs(hash(q))
        # 8-dim deterministic vector, normalized enough for a stable cosine.
        v = [float((h >> (i * 4)) & 0xF) + 1.0 for i in range(8)]
        n = sum(x * x for x in v) ** 0.5
        return [x / n for x in v]


class _StubStore(NeonKnowledgeStore):
    """Subclass that never touches Postgres: _leg_lexical/_leg_vector return
    scripted rows so we can test caching behavior deterministically."""

    def __init__(self, embedder) -> None:
        super().__init__(dsn="postgresql://x:x@localhost/x", vector_dim=8,
                         embedding_model=embedder, cache_capacity=8)
        self._vec_queries: list[str] = []
        self._lex_queries: list[str] = []

    def _leg_vector(self, query: str, limit: int):
        self._vec_queries.append(query)
        return [{"id": f"v{i}", "content_hash": f"h{i}", "description": query + str(i)}
                for i in range(3)]

    def _leg_lexical(self, query: str, limit: int):
        self._lex_queries.append(query)
        return [{"id": f"l{i}", "content_hash": f"h{i}", "description": query + str(i)}
                for i in range(3)]

    def _connect(self):  # pragma: no cover - not used by search stub
        raise AssertionError("search stub must not touch the DB")


class TestRetrievalCache:
    def test_same_query_served_from_cache(self):
        emb = _SlowFakeEmbedder()
        s = _StubStore(emb)
        a = s.search("reentrancy", limit=2)
        b = s.search("reentrancy", limit=2)
        assert a == b  # identical rows (deep-copy of same cached payload)
        assert s._vec_queries == ["reentrancy"]  # Neon/embedder hit once only

    def test_different_query_misses_cache(self):
        emb = _SlowFakeEmbedder()
        s = _StubStore(emb)
        s.search("a", limit=1)
        s.search("b", limit=1)
        assert s._vec_queries == ["a", "b"]  # distinct queries both miss

    def test_different_limit_is_distinct_key(self):
        emb = _SlowFakeEmbedder()
        s = _StubStore(emb)
        s.search("q", limit=2)
        s.search("q", limit=3)
        assert s._vec_queries == ["q", "q"]  # (query, limit) tuple keys cache

    def test_capacity_evicts_oldest(self):
        emb = _SlowFakeEmbedder()
        s = _StubStore(emb)
        s._cache_capacity = 2
        for q in ("a", "b", "c"):
            s.search(q, limit=1)
        # 'a' evicted -> re-queried
        s.search("a", limit=1)
        assert s._vec_queries == ["a", "b", "c", "a"]

    def test_cache_result_is_immutable_to_caller(self):
        emb = _SlowFakeEmbedder()
        s = _StubStore(emb)
        r1 = s.search("q", limit=1)
        r1[0]["_retrieval"]["rrf_score"] = 999.0  # mutate caller's copy
        r2 = s.search("q", limit=1)
        assert r2[0]["_retrieval"]["rrf_score"] != 999.0  # unaffected


class TestSchedulerConcurrency:
    def test_default_uses_scheduler_field(self):
        from agentsafe.agents.scheduler import MultiAgentScheduler
        from agentsafe.config import Settings

        s = MultiAgentScheduler(router=None)
        assert s._max_concurrent == Settings().SCHEDULER_MAX_CONCURRENT
        assert Settings().SCHEDULER_MAX_CONCURRENT >= 1

    def test_explicit_max_concurrent_overrides(self):
        from agentsafe.agents.scheduler import MultiAgentScheduler

        s = MultiAgentScheduler(router=None, max_concurrent=1)
        assert s._max_concurrent == 1


class TestSettingsProvider:
    def test_provider_returns_first(self):
        s = Settings(LLM_PROVIDERS_JSON=json.dumps([
            {"name": "p1", "base_url": "https://a.io/v1", "api_key": "k1",
             "model": "m1", "rpm_limit": 10},
            {"name": "p2", "base_url": "https://b.io/v1", "api_key": "k2",
             "model": "m2", "rpm_limit": 10},
        ]))
        assert s.provider.name == "p1"

    def test_provider_empty_raises(self):
        with pytest.raises(Exception):
            Settings(LLM_PROVIDERS_JSON="[]").provider

    def test_provider_matches_list_first(self):
        s = Settings(LLM_PROVIDERS_JSON=json.dumps([
            {"name": "x", "base_url": "https://a.io/v1", "api_key": "k",
             "model": "m", "rpm_limit": 10},
        ]))
        assert s.provider.model == s.llm_providers()[0].model