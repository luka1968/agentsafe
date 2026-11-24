"""Section 9 — knowledge-base retrieval: config, rationale, and reach.

Pins the fixes and the guarantees:

- the embedding configuration is read from BOTH env and settings (the settings
  merge no longer drops keys after the first), and unconfigured -> None
  (lexical fallback, never a fabricated vector);
- ``get_knowledge_store`` passes the settings through to the embedder;
- every retrieved record states WHY it is relevant (target-context match, or a
  fallback retrieval basis) so unrelated records are never appended;
- retrieval results actually reach the agents' prompts.
"""

from __future__ import annotations

import asyncio
import inspect

from agentsafe.agents.base import AnalysisMaterial
from agentsafe.agents.specialists import ReentrancyAgent
from agentsafe.intel.render import render_kb_snippets
from agentsafe.knowledge.context import derive_context, retrieve_for_agents
from agentsafe.knowledge.db import get_knowledge_store
from agentsafe.knowledge.embeddings import get_embedder


class _Settings:
    NVIDIA_API_KEY = "nvapi-cfg"
    NVIDIA_BASE_URL = "https://cfg.example/v1"
    NVIDIA_EMBED_MODEL = "cfg-model"
    EMBED_DIM = "512"


def _clear_embed_env(monkeypatch):
    for k in ("NVIDIA_API_KEY", "NVIDIA_BASE_URL", "NVIDIA_EMBED_MODEL", "EMBED_DIM"):
        monkeypatch.delenv(k, raising=False)


class TestEmbedderConfig:
    def test_settings_are_merged_in_full(self, monkeypatch):
        _clear_embed_env(monkeypatch)
        emb = get_embedder(_Settings())
        assert emb is not None
        assert emb.api_key == "nvapi-cfg"
        assert emb.base_url == "https://cfg.example/v1"
        assert emb.model == "cfg-model"
        assert emb.dim == 512  # every key applied, not just the first

    def test_environment_wins_over_settings(self, monkeypatch):
        _clear_embed_env(monkeypatch)
        monkeypatch.setenv("NVIDIA_API_KEY", "env-key")
        emb = get_embedder(_Settings())
        assert emb is not None and emb.api_key == "env-key"

    def test_unconfigured_is_none(self, monkeypatch):
        _clear_embed_env(monkeypatch)

        class _Empty:
            pass

        assert get_embedder(_Empty()) is None
        assert get_embedder(None) is None

    def test_store_passes_settings_to_embedder(self):
        src = inspect.getsource(get_knowledge_store)
        assert "get_embedder(settings)" in src


class TestWhyRelevant:
    def test_context_match_is_stated(self):
        rec = {
            "id": "KB-1", "category": "reentrancy", "root_cause": "cei",
            "_retrieval": {"context_signals": ["function withdraw", "trait:defi"]},
        }
        out = render_kb_snippets([rec])
        assert "why retrieved: target-context match" in out
        assert "function withdraw" in out

    def test_fallback_basis_is_stated(self):
        rec = {"id": "KB-2", "category": "oracle", "root_cause": "stale"}
        out = render_kb_snippets([rec])
        assert "why retrieved:" in out
        # never presented without a reason
        assert "lexical relevance" in out


class _FakeKB:
    def __init__(self, records):
        self._records = records
        self.calls: list[dict] = []

    def search(self, query, focus="", limit=3, profile=None, **kw):
        self.calls.append({"query": query, "profile": profile, **kw})
        return [dict(r) for r in self._records]


class TestRetrievalAnnotation:
    def test_unmatched_record_gets_a_reason(self):
        kb = _FakeKB([{"id": "KB-9", "category": "reentrancy", "root_cause": "x"}])
        ctx = derive_context(None, "")
        recs = retrieve_for_agents(kb, ctx, chunk="contract V { }", keywords=("reentrancy",))
        assert recs
        assert recs[0]["_retrieval"].get("reason") or recs[0]["_retrieval"].get("context_signals")
        # context-aware call passed solc/context through
        assert kb.calls and "context" in kb.calls[0]

    def test_context_object_carries_contract_vocabulary(self):
        from agentsafe.intel.extract import extract_contract_intel

        intel = extract_contract_intel(
            {"V.sol": "contract V { mapping(address=>uint) balances; "
                      "function withdraw(uint a) external { balances[msg.sender]-=a; } }"}
        )
        ctx = derive_context(intel, intel.raw_text() if hasattr(intel, "raw_text") else "")
        assert "withdraw" in ctx.functions


class _CapturingRouter:
    def __init__(self):
        self.sent: list[list[dict]] = []

    async def complete_json(self, budget, messages, schema):
        from agentsafe.agents.base import LLMFindingsPayload

        self.sent.append(messages)
        return LLMFindingsPayload(findings=[]), None


class TestRetrievalReachesAgents:
    def test_kb_context_and_rationale_appear_in_the_prompt(self):
        kb = _FakeKB([{
            "id": "KB-1", "category": "reentrancy", "protocol_type": "defi",
            "root_cause": "state updated after external call",
            "mechanism": "reentrancy via callback", "impact": "funds drained",
            "remediation": "CEI", "source": "code4rena", "url": "https://x/1",
        }])
        router = _CapturingRouter()
        agent = ReentrancyAgent(router)
        material = AnalysisMaterial(
            kind="source",
            segments={"V.sol": "contract V { function withdraw() external {} }"},
            kb=kb,
        )
        asyncio.run(agent.analyze(object(), material))
        assert router.sent, "the agent made no LLM call"
        user = router.sent[0][1]["content"]
        assert "KB CONTEXT" in user
        assert "why retrieved:" in user
