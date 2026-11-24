"""Phase 7 retrieval-interface tests.

The interface is the stable, structured entry point: discovery + validation,
normalized response, explicit metadata, honest supporting-evidence framing.
"""

from __future__ import annotations

import json
from pathlib import Path

from agentsafe.knowledge.interface import (
    KnowledgeRequest,
    describe,
    retrieve,
)

ROOT = Path(__file__).resolve().parents[1]


class _NeonLike:
    def __init__(self):
        self.embedding_model = object()  # marks a hybrid store
        self.calls = []

    def search(self, query, *, focus="", limit=3, profile=None, kb_groups=None,
               categories=None, tags=None, sources=None, solc=None,
               context=None, min_relevance=0.0, status=None):
        self.calls.append({"focus": focus, "limit": limit, "profile": profile,
                           "solc": solc, "context": context})
        if status is not None:
            status.clear()
            status.update({"cached": False, "mode": "hybrid", "degraded": False,
                           "vector_used": True, "lexical_used": True,
                           "reason": None, "returned": 1})
        return [{
            "id": "KB-1", "title": "Stale oracle", "category": "oracle",
            "subcategory": "freshness", "severity": "High",
            "verification_status": "curated", "quality_status": "VALIDATED",
            "quality_claim": "curated", "source_name": "docs", "source_url": "u",
            "root_cause": "no freshness check", "mechanism": "reads stale price",
            "preconditions": ["stale feed"], "attack_scenario": "wait then act",
            "impact": "bad debt", "remediation": "check updatedAt",
            "vulnerable_code": "p=feed.latest()", "corrected_code": "check()",
            "_retrieval": {"why": ["vector rank 1"], "context_signals": []},
        }]


class _FallbackKB:
    def __init__(self):
        self.called = False

    def search(self, query, *, focus="", limit=3, profile=None, kb_groups=None,
               categories=None):
        self.called = True
        return [{"id": "jsonl-1", "mechanism": "readonly reentrancy",
                 "category": "reentrancy"}]


class TestInterface:
    def test_discovery_request_returns_normalized_response(self):
        kb = _NeonLike()
        req = KnowledgeRequest(agent="oracle", category="oracle",
                               query="stale price", code="feed.latest()",
                               functions=["getPrice"], state_vars=["price"],
                               solc="0.8", depth=3, intent="discovery")
        resp = retrieve(kb, req)
        assert resp.metadata["mode"] == "hybrid"
        assert resp.metadata["intent"] == "discovery"
        assert resp.metadata["supporting_evidence"] is True
        r = resp.records[0]
        assert r["id"] == "KB-1"
        assert r["validation_status"] == "curated"
        assert r["technical_explanation"] == "no freshness check"
        assert r["exploit_pattern"]["attack_scenario"] == "wait then act"
        assert r["source"]["url"] == "u"
        assert "retrieval" in r
        # context-aware kwargs reached the store
        assert kb.calls[0]["solc"] == "0.8"
        assert kb.calls[0]["context"]["functions"]

    def test_validation_intent_uses_validation_focus_and_filters(self):
        kb = _NeonLike()
        resp = retrieve(kb, KnowledgeRequest(
            agent="validation", category="token-transfer",
            query="send failure", code="to.send(1);", intent="validation"))
        assert kb.calls[0]["focus"] == "validation"
        assert [v["id"] for v in resp.validated()] == ["KB-1"]

    def test_fallback_kb_without_context_kwargs(self):
        kb = _FallbackKB()
        resp = retrieve(kb, KnowledgeRequest(query="reentrancy",
                                             category="reentrancy", depth=2))
        assert kb.called
        assert resp.records[0]["id"] == "jsonl-1"
        assert resp.metadata["mode"] == "lexical"

    def test_title_fallback_for_legacy_records(self):
        kb = _FallbackKB()
        resp = retrieve(kb, KnowledgeRequest(query="x", category="reentrancy"))
        assert resp.records[0]["title"]  # mechanism used as label

    def test_no_kb_yields_error_metadata(self):
        resp = retrieve(None, KnowledgeRequest(query="x"))
        assert resp.metadata.get("error")

    def test_describe_shape(self):
        d = describe()
        assert d["interface_version"]
        assert "discovery" in d["intents"] and "validation" in d["intents"]
        assert "records" in d["response_fields"]
        assert set(d["request_fields"]) >= {"agent", "category", "solc", "depth"}
        json.dumps(d)


class TestDataFlowLock:
    """The interface is only useful if real callers consume KB data. Lock the
    verified caller paths so a future edit cannot silently orphan retrieval."""

    def test_specialist_base_consumes_kb(self):
        text = (ROOT / "src" / "agentsafe" / "agents" / "base.py").read_text(
            encoding="utf-8")
        assert "retrieve_for_agents" in text
        assert "retrieve_counterexamples" in text
        assert "material" in text and "kb" in text

    def test_orchestrator_corroborates_findings_with_kb(self):
        text = (ROOT / "src" / "agentsafe" / "orchestrator.py").read_text(
            encoding="utf-8")
        assert "kb.search(" in text
        assert 'profile="validation"' in text
