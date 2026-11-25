"""Sections 15–16 — quality gates and reliability/model policy.

Pins:
- the quality-gate evaluator reports the ACTUAL measurement of every release
  target from real artifacts, and does NOT hide an unmet gate;
- the model policy uses stronger models for complex domains and never downgrades
  to reduce calls;
- deterministic finding ids + duplicate collapse (reliability).
"""

from __future__ import annotations

import sys
from pathlib import Path

BENCH = Path(__file__).resolve().parents[1] / "benchmarks"
sys.path.insert(0, str(BENCH))

import quality_gates as Q  # noqa: E402

from agentsafe.agents.classification import SPECIALISTS, classify_contract  # noqa: E402
from agentsafe.llm.model_policy import (  # noqa: E402
    COMPLEX_DOMAINS,
    model_policy_snapshot,
    reasoning_tier_for,
    select_model,
)
from agentsafe.report import merge_findings  # noqa: E402
from agentsafe.schemas import Finding, FindingStatus  # noqa: E402


class TestQualityGates:
    def test_every_gate_reports_target_and_measurement(self):
        r = Q.evaluate_gates()
        assert r["summary"]["n_gates"] == 9
        for name, g in r["gates"].items():
            assert set(g) == {"target", "measured", "passed", "note"}, name
            assert isinstance(g["passed"], bool)

    def test_core_targets_are_met_with_measured_values(self):
        g = Q.evaluate_gates()["gates"]
        assert g["recall_critical_high"]["passed"]
        assert g["recall_critical_high"]["measured"] >= 0.90
        assert g["precision_confirmed"]["passed"]
        assert g["precision_confirmed"]["measured"] >= 0.85
        assert g["evm_rollback_false_positives"]["measured"] == 0
        assert g["evm_rollback_false_positives"]["passed"]
        assert g["unsupported_proxy_classification"]["measured"] == 0
        assert g["coverage_accounting"]["passed"]
        assert g["failed_skipped_agent_handling"]["passed"]
        assert g["no_fabricated_results"]["passed"]
        assert g["severity_confidence_consistency"]["passed"]

    def test_poc_gate_reflects_the_backend_honestly(self):
        from agentsafe.validation.evm_poc import evm_backend_available

        r = Q.evaluate_gates()
        g = r["gates"]["reproducible_poc"]
        if evm_backend_available():
            # a real EVM backend is present -> the PoC gate is met (measured 1.0)
            assert g["passed"] is True and g["measured"] == 1.0
        else:
            # absent backend -> reported NOT met, with the reason, never faked
            assert g["passed"] is False and g["measured"] == 0.0
            assert "backend" in g["note"]
        # commercially_ready is exactly "every gate met" (never asserted blindly)
        assert r["summary"]["commercially_ready"] == all(
            x["passed"] for x in r["gates"].values()
        )


class TestModelPolicy:
    def test_complex_domains_use_complex_tier(self):
        for name in ("accounting", "oracle", "cross_function", "validation"):
            assert reasoning_tier_for(name) == "complex"

    def test_standard_domains(self):
        for name in ("reentrancy", "access_control", "arithmetic", "proxy_upgrade",
                     "general_discovery", None, "unknown_agent"):
            assert reasoning_tier_for(name) == "standard"

    def test_selection_never_downgrades(self):
        assert select_model("complex", default="small", complex_model="big") == "big"
        # complex with no complex model configured -> the configured default
        assert select_model("complex", default="small", complex_model=None) == "small"
        # standard always uses the default
        assert select_model("standard", default="small", complex_model="big") == "small"

    def test_snapshot_is_reproducible(self):
        snap = model_policy_snapshot(default_model="m1", complex_model="m2")
        assert snap["resolved"] == {"standard": "m1", "complex": "m2"}
        assert snap["weakens_to_reduce_calls"] is False
        assert set(COMPLEX_DOMAINS) <= set(snap["complex_domains"])


class TestReliability:
    def test_deterministic_finding_id(self):
        kw = dict(title="t", severity="high", status=FindingStatus.POTENTIAL,
                  source=["s"], description="d", evidence="e", file_path="A.sol",
                  line_start=3)
        a = Finding(**kw)
        b = Finding(**kw)
        assert a.finding_id and a.finding_id == b.finding_id

    def test_duplicate_detection_collapses_same_root_cause(self):
        kw = dict(title="Reentrancy in withdraw()", severity="high",
                  status=FindingStatus.CONFIRMED, source=["reentrancy"],
                  description="external call before state update", evidence="x",
                  file_path="A.sol", line_start=10)
        f1 = Finding(**{**kw, "source": ["reentrancy"]})
        f2 = Finding(**{**kw, "source": ["fund_flow"]})
        merged = merge_findings([f1], [f2])
        assert len(merged) == 1

    def test_baseline_specialists_are_never_reduced(self):
        # An empty/uncertain contract still routes every baseline specialist.
        p = classify_contract(None, "contract A { }")
        for name in ("general_discovery", "access_control"):
            assert name in SPECIALISTS
            assert p.should_run(name)
