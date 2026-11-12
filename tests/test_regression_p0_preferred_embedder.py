"""P0 regression tests: preferred-provider routing + embedder attachment.

Covers the two verified bottlenecks:
  1. LLMRouter must select the `preferred: true` provider on the first
     attempt while preserving the existing fallback rotation on failures.
  2. get_knowledge_store() must attach the configured embedder to
     NeonKnowledgeStore so production retrieval uses the stored vectors,
     and must degrade to lexical-only when no embedder is available.

No network / no live Neon dependency (router uses respx; the store wiring
is exercised by stubbing get_embedder and the store constructor).
"""

import json
import types

import httpx
import respx
from pydantic import BaseModel

from agentsafe.config import LLMProviderConfig
from agentsafe.llm.router import LLMRouter


# ---------------------------------------------------------------------------
# Router: preferred provider honored on first attempt, rotation preserved
# ---------------------------------------------------------------------------

PROV_A = LLMProviderConfig(
    name="prov-a", base_url="https://a.test/v1", api_key="sk-a", model="m1", rpm_limit=60
)
PROV_B = LLMProviderConfig(
    name="prov-b", base_url="https://b.test/v1", api_key="sk-b", model="m2",
    rpm_limit=60, preferred=True,
)
PROV_A_NOPREF = LLMProviderConfig(
    name="prov-a", base_url="https://a.test/v1", api_key="sk-a", model="m1", rpm_limit=60
)
PROV_B_NOPREF = LLMProviderConfig(
    name="prov-b", base_url="https://b.test/v1", api_key="sk-b", model="m2", rpm_limit=60
)


class _FakeClock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def advance(self, d: float) -> None:
        self.t += d


async def _sleep(_d: float) -> None:
    return None


def _ok_body(content: dict) -> dict:
    return {
        "choices": [{"message": {"content": json.dumps(content)}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }


class _Ok(BaseModel):
    answer: str


def _router(providers, *, retries=2):
    return LLMRouter(
        providers,
        global_rpm=60,
        request_timeout_seconds=5.0,
        max_retries_per_call=retries,
        http_client=httpx.AsyncClient(),
        sleeper=_sleep,
        clock=_FakeClock(),
    )


@respx.mock
async def test_preferred_provider_selected_on_first_attempt():
    """When one provider is preferred, the first attempt goes to it (prov-b)."""
    router = _router([PROV_A, PROV_B])
    budget = router.start_audit(max_calls=5, deadline_seconds=60)
    respx.post("https://b.test/v1/chat/completions").mock(
        return_value=httpx.Response(200, json=_ok_body({"answer": "b"}))
    )
    payload, call = await router.complete_json(
        budget, [{"role": "user", "content": "hi"}], _Ok
    )
    assert payload.answer == "b"
    assert call.provider == "prov-b"


@respx.mock
async def test_preferred_failure_rotates_to_fallback():
    """When the preferred provider fails (429), the router rotates to the
    next provider — fallback/retry behavior is preserved."""
    router = _router([PROV_A, PROV_B])
    budget = router.start_audit(max_calls=5, deadline_seconds=60)
    respx.post("https://b.test/v1/chat/completions").mock(
        return_value=httpx.Response(429, json={})
    )
    respx.post("https://a.test/v1/chat/completions").mock(
        return_value=httpx.Response(200, json=_ok_body({"answer": "a"}))
    )
    payload, call = await router.complete_json(
        budget, [{"role": "user", "content": "hi"}], _Ok
    )
    assert payload.answer == "a"
    assert call.provider == "prov-a"


@respx.mock
async def test_no_preferred_keeps_list_order_first():
    """Without a preferred flag, the first provider in list order is used
    first (unchanged default behavior)."""
    router = _router([PROV_A_NOPREF, PROV_B_NOPREF])
    budget = router.start_audit(max_calls=5, deadline_seconds=60)
    respx.post("https://a.test/v1/chat/completions").mock(
        return_value=httpx.Response(200, json=_ok_body({"answer": "a"}))
    )
    payload, call = await router.complete_json(
        budget, [{"role": "user", "content": "hi"}], _Ok
    )
    assert payload.answer == "a"
    assert call.provider == "prov-a"


# ---------------------------------------------------------------------------
# Knowledge store: embedder attached; lexical fallback preserved
# ---------------------------------------------------------------------------

def _make_settings(dsn: str, dim: int = 384) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        NEON_DATABASE_URL=dsn,
        KB_STORAGE="",
        KB_VECTOR_DIM=dim,
        resolved_kb_storage="neon",
    )


def test_get_knowledge_store_attaches_embedder(monkeypatch):
    """get_knowledge_store must pass the configured embedder into
    NeonKnowledgeStore as embedding_model."""
    from agentsafe.knowledge import db as kb_db

    captured: dict = {}

    class _FakeEmbedder:
        dim = 384

        def embed_query(self, text):
            return [0.0] * 384

    class _FakeStore:
        def __init__(self, dsn, vector_dim, embedding_model=None):
            captured["embedding_model"] = embedding_model
            captured["vector_dim"] = vector_dim

        def migrate(self):
            return None

        def count(self):
            return 1

    monkeypatch.setattr("agentsafe.knowledge.embeddings.get_embedder", lambda: _FakeEmbedder())
    monkeypatch.setattr(kb_db, "NeonKnowledgeStore", _FakeStore)

    store = kb_db.get_knowledge_store(_make_settings("postgres://x/y"))
    assert captured["embedding_model"] is not None
    assert captured["embedding_model"].dim == captured["vector_dim"] == 384


def test_get_knowledge_store_no_embedder_stays_lexical(monkeypatch):
    """When get_embedder() is unavailable (None), the store is still built
    with embedding_model=None so retrieval degrades to lexical, not fails."""
    from agentsafe.knowledge import db as kb_db

    captured: dict = {}

    class _FakeStore:
        def __init__(self, dsn, vector_dim, embedding_model=None):
            captured["embedding_model"] = embedding_model

        def migrate(self):
            return None

        def count(self):
            return 1

    import agentsafe.knowledge.embeddings as _emb

    monkeypatch.setattr(_emb, "get_embedder", lambda: None)
    monkeypatch.setattr(kb_db, "NeonKnowledgeStore", _FakeStore)

    kb_db.get_knowledge_store(_make_settings("postgres://x/y"))
    assert captured["embedding_model"] is None