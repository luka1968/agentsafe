"""Phase 6 false-positive / counterexample tests.

Counterexamples are detected from target signals, retrieved from the curated
FP records, and rendered as a checklist that must NOT auto-reject findings.
"""

from __future__ import annotations

import json
from pathlib import Path

from agentsafe.knowledge.falsepositives import (
    FP_TRIGGERS,
    detect_fp_triggers,
    render_counterexamples,
    retrieve_counterexamples,
)

ROOT = Path(__file__).resolve().parents[1]


class TestDataset:
    def test_fp_dataset_is_valid_jsonl_and_group_e(self):
        path = ROOT / "src" / "agentsafe" / "knowledge" / "dataset" / "fp_v1.jsonl"
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()]
        assert len(rows) >= 7
        for r in rows:
            assert r["kb_group"] == "E"
            assert r["verification_status"] == "curated"
            assert r.get("evidence_required")
            assert r.get("fp_patterns")
            assert r.get("url")  # provenance preserved

    def test_seed_wires_fp_dataset(self):
        text = (ROOT / "src" / "agentsafe" / "knowledge" / "db.py").read_text(
            encoding="utf-8")
        assert "agentsafe-fp-v1.jsonl" in text and "fp_v1.jsonl" in text


class TestDetectTriggers:
    def test_detects_call_and_send(self):
        trig = detect_fp_triggers("function x() { (bool ok,)=to.call{value:1}(\"\"); to.send(1); }")
        labels = [t["label"] for t in trig]
        assert any("call()" in x for x in labels)
        assert len(trig) <= 3

    def test_detects_mapping_and_decimals(self):
        trig = detect_fp_triggers("mapping(address=>uint) balances; uint d = token.decimals();")
        labels = " ".join(t["label"] for t in trig)
        assert "mapping" in labels or "decimals" in labels

    def test_no_signals_returns_empty(self):
        assert detect_fp_triggers("just a comment about nothing") == []

    def test_triggers_are_bounded(self):
        assert len(FP_TRIGGERS) >= 7


class _NeonLike:
    def __init__(self):
        self.captured = {}

    def search(self, query, *, focus="", limit=3, profile=None, kb_groups=None,
               solc=None, context=None):
        self.captured = {"kb_groups": kb_groups, "profile": profile,
                         "query": query}
        return [{"id": "KB-2025-602", "title": "send() FP",
                 "fp_patterns": ["send() not detected"],
                 "why_safe": "result is checked",
                 "evidence_required": ["ok ignored and state finalized"],
                 "known_limitations": ["does not cover call()"]}]


class _FallbackKB:
    def __init__(self):
        self.called = False

    def search(self, query, *, focus="", limit=3, profile=None, kb_groups=None):
        self.called = True
        return [{"id": "KB-E-1", "title": "fallback", "fp_patterns": ["x"]}]


class TestRetrieve:
    def test_hard_filters_to_fp_groups(self):
        kb = _NeonLike()
        recs = retrieve_counterexamples(
            kb, text="(bool ok,) = to.send(1);", category="token-transfer")
        assert kb.captured["kb_groups"] == ("E", "F")
        assert kb.captured["profile"] == "false_positive"
        assert recs[0]["_retrieval"]["fp_triggers"]

    def test_falls_back_on_plain_kb(self):
        kb = _FallbackKB()
        recs = retrieve_counterexamples(kb, text="to.send(1);")
        assert kb.called and recs[0]["id"] == "KB-E-1"

    def test_no_signals_no_category_returns_empty(self):
        assert retrieve_counterexamples(_NeonLike(), text="nothing here") == []


class TestRender:
    def test_render_is_a_checklist_not_a_verdict(self):
        recs = [{"id": "KB-2025-603", "title": "call() FP",
                 "fp_patterns": ["call assumed to revert"],
                 "why_safe": "success is required",
                 "evidence_required": ["success flag ignored"],
                 "known_limitations": ["return data not validated"]}]
        out = render_counterexamples(recs, [{"label": "low-level call()"}])
        assert "FALSE-POSITIVE" in out and "call()" in out
        assert "Do NOT reject a real finding" in out
        assert "evidence required to overturn" in out
        assert "known limitations" in out

    def test_empty_records_render_empty(self):
        assert render_counterexamples([], []) == ""
