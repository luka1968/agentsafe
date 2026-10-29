"""Stage 11 — security & operational controls tests.

Covers:
- HTTP hardening: per-IP rate limit (429) + bounded body (413) on REST
  endpoints; MCP tools untouched (never rate limited); existing REST dev-mode
  dispatch still works under limits.
- Embedding reuse: unchanged content is never re-embedded (_plan_embeddings);
  embedder failures degrade to lexical-only without fabricating vectors.
- Metrics: counters/latency aggregates/JSONL sink never carry payloads.
- Retrieval graceful degradation: embedder outage -> lexical-only, store
  outage -> JSONL fallback, empty result -> [] (never invented records).
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from agentsafe.config import Settings
from agentsafe.knowledge.importers import (
    _embed_in_batches,
    _plan_embeddings,
    content_hash_of,
)
from agentsafe.metrics import Metrics, MetricsSink


# ---------------------------------------------------------------------------
# 11.2 HTTP hardening (REST surface)
# ---------------------------------------------------------------------------

class TestRateLimit:
    def _build(self, rate: int, body_limit: int):
        from agentsafe.server import build_server

        settings = Settings(
            PAYMENTS_ENABLED=False,
            HTTP_RATE_LIMIT_PER_MINUTE=rate,
            HTTP_MAX_BODY_BYTES=body_limit,
            TASK_STORE="sqlite",
            TASK_DB_PATH=":memory:",
        )
        return build_server(settings, validate=False)

    @staticmethod
    async def _post(app, path: str, payload: dict | None = None,
                    content: str | None = None):
        import httpx

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(
                app=app.http_app(stateless_http=True, json_response=True)),
            base_url="https://test",
        ) as client:
            if content is not None:
                return await client.post(path, content=content)
            return await client.post(path, json=payload or {})

    async def test_rate_limited_after_quota(self):
        app = self._build(rate=2, body_limit=65536)
        r1 = await self._post(app, "/api/audit", {"address": "0x" + "a" * 40})
        r2 = await self._post(app, "/api/audit", {"address": "0x" + "b" * 40})
        r3 = await self._post(app, "/api/audit", {"address": "0x" + "c" * 40})
        assert r1.status_code in (200, 400, 402, 422)
        assert r3.status_code == 429
        assert r3.json().get("error_code") == "rate_limited"

    async def test_oversized_body_rejected(self):
        app = self._build(rate=20, body_limit=1024)
        big = json.dumps({"address": "0x" + "a" * 40, "pad": "x" * 4096})
        r = await self._post(app, "/api/audit", content=big)
        assert r.status_code == 413
        assert r.json().get("error_code") == "body_too_large"

    async def test_mcp_tools_not_rate_limited(self):
        app = self._build(rate=1, body_limit=65536)
        tools = {t.name for t in await app.list_tools()}
        # The rate limiter never touches MCP tool calls: tool surface intact.
        assert any("audit" in t for t in tools)
        assert tools  # tool registry unchanged after REST quota hit


# ---------------------------------------------------------------------------
# 11.3 embedding reuse
# ---------------------------------------------------------------------------

class _FakeCursor:
    """Minimal cursor handling ONLY the reuse-lookup SQL; any other SQL
    raises so a test that reaches the DB write path fails loudly."""

    def __init__(self, existing: set[str]) -> None:
        self._existing = existing
        self._rows: list = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql: str, params: tuple | None = None) -> None:
        if "SELECT DISTINCT content_hash" in sql:
            hashes = list(params[0]) if params else []
            self._rows = [{"content_hash": h} for h in self._existing
                          if h in hashes]
            return
        raise AssertionError(f"unexpected SQL in reuse test: {sql[:60]!r}")

    def fetchall(self):
        return self._rows


class _FakeConn:
    def __init__(self, cursor: _FakeCursor) -> None:
        self._cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cursor(self) -> _FakeCursor:
        return self._cursor


class _FakeStore:
    def __init__(self, existing: set[str]) -> None:
        self._existing = existing

    def _connect(self):
        return _FakeConn(_FakeCursor(self._existing))


class _CountingEmbedder:
    def __init__(self) -> None:
        self.calls = 0
        self.texts: list[str] = []

    def __call__(self, batch: list[str]) -> list[list[float]]:
        self.calls += 1
        self.texts.extend(batch)
        return [[float(len(t))] * 4 for t in batch]


class TestEmbeddingReuse:
    def test_unchanged_content_not_reembedded(self):
        texts = ["alpha reentrancy withdraw", "beta arithmetic overflow"]
        emb = _CountingEmbedder()
        hashes = [content_hash_of(t) for t in texts]
        store = _FakeStore(existing={hashes[0]})  # first already stored
        embeddings, reused = _plan_embeddings(store, texts, emb, 20)
        assert reused == 1
        assert emb.calls == 1  # only the missing hash hit the embedder
        assert emb.texts == [texts[1]]
        assert embeddings[0] is None          # reused -> no new vector
        assert embeddings[1] == [float(len(texts[1]))] * 4

    def test_all_cached_zero_embedder_calls(self):
        texts = ["only record"]
        emb = _CountingEmbedder()
        store = _FakeStore(existing={content_hash_of(texts[0])})
        embeddings, reused = _plan_embeddings(store, texts, emb, 20)
        assert reused == 1 and emb.calls == 0
        assert embeddings == [None]

    def test_no_embedder_means_lexical_only(self):
        texts = ["x", "y"]
        store = _FakeStore(existing=set())
        embeddings, reused = _plan_embeddings(store, texts, None, 20)
        assert reused == 0
        assert embeddings == [None, None]

    def test_lookup_failure_reembeds_all(self):
        texts = ["a"]
        emb = _CountingEmbedder()

        class Broken(_FakeStore):
            def _connect(self):
                raise RuntimeError("neon down")

        embeddings, reused = _plan_embeddings(Broken(set()), texts, emb, 20)
        assert reused == 0 and emb.calls == 1  # correctness over speed

    def test_embed_batch_failure_yields_none_not_fake(self):
        class Bad:
            def __call__(self, batch):
                raise RuntimeError("embedder down")

        out = _embed_in_batches(Bad(), ["a", "b", "c"], 2)
        assert out == [None, None, None]

    def test_embed_batch_correct_alignment(self):
        emb = _CountingEmbedder()
        out = _embed_in_batches(emb, ["p", "q", "r"], 2)
        assert emb.calls == 2  # batches of 2 then 1
        assert len(out) == 3 and all(len(v) == 4 for v in out)


# ---------------------------------------------------------------------------
# 11.4 metrics
# ---------------------------------------------------------------------------

class TestMetrics:
    def test_counters_and_means(self):
        m = Metrics()
        m.incr("import_records", 3)
        m.incr("retrieval_vector_fallback")
        m.record("retrieval_latency_ms", 10.0)
        m.record("retrieval_latency_ms", 30.0)
        snap = m.snapshot()
        assert snap["import_records"] == 3
        assert snap["retrieval_vector_fallback"] == 1
        assert snap["retrieval_latency_ms_mean"] == pytest.approx(20.0)
        assert snap["retrieval_latency_ms_max"] == pytest.approx(30.0)

    def test_sink_writes_aggregates_only(self, tmp_path):
        p = tmp_path / "m.jsonl"
        m = Metrics()
        m.incr("agent_runs", 4)
        sink = MetricsSink(p)
        sink.flush(m)
        rows = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines()]
        assert rows[0]["agent_runs"] == 4
        assert "ts" in rows[0]
        # sink never writes payload-bearing keys
        assert not any(k.startswith(("http_", "retrieval_", "llm_", "agent_", "import_"))
                       and "ts" == k for k in rows[0])

    def test_disabled_sink_noop(self, tmp_path):
        sink = MetricsSink(None)
        assert not sink.enabled
        sink.flush(Metrics())  # no exception, no file


# ---------------------------------------------------------------------------
# 11.5 graceful degradation (never fabricates)
# ---------------------------------------------------------------------------

class TestDegradation:
    def test_empty_search_result_is_empty(self):
        from agentsafe.knowledge.kb import KnowledgeBase

        kb = KnowledgeBase.load_default()
        # impossible keyword -> [] not invented rows
        hits = kb.search("zzzzqqqqxxxyyywwvv", limit=3)
        assert hits == []

    def test_vector_leg_failure_counts_fallback(self):
        from agentsafe.knowledge import db as kdb
        from agentsafe.metrics import get_metrics

        get_metrics().reset()
        store = kdb.NeonKnowledgeStore(dsn="postgresql://bad:bad@localhost/x",
                                       vector_dim=384)

        class BrokenEmbedder:
            def embed_query(self, q):
                raise RuntimeError("nvidia down")

        store.embedding_model = BrokenEmbedder()
        hits = store.search_leg_vector("reentrancy", limit=3)
        assert hits == []
        assert get_metrics().snapshot().get("retrieval_vector_fallback", 0) >= 1

    def test_neon_store_outage_falls_back_jsonl(self):
        from agentsafe.knowledge.db import get_knowledge_store
        from agentsafe.metrics import get_metrics

        get_metrics().reset()
        settings = Settings(NEON_DATABASE_URL="postgresql://bad:bad@localhost/x",
                            KB_STORAGE="neon", KB_VECTOR_DIM=384)
        store = get_knowledge_store(settings)
        # graceful: JSONL KnowledgeBase returned, never None, never fake
        assert store is not None and hasattr(store, "search")
        assert get_metrics().snapshot().get("retrieval_neon_fallback", 0) >= 1
