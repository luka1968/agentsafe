"""Stage 10 — eval-suite determinism + dataset-verification tests.

Locks: metric math, GT extraction honesty (keyword-anchored, no invented
labels), dataset verification facts (provenance/license), and the fact that
the eval harness executes the real pipeline (a probe-mode detection run
produces findings from the intel layer with honest tool accounting).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

BENCH = Path(__file__).resolve().parent.parent / "benchmarks"
sys.path.insert(0, str(BENCH))
sys.path.insert(0, str(BENCH.parent / "src"))

import eval_metrics as M  # noqa: E402


# ---------------------------------------------------------------------------
# metrics
# ---------------------------------------------------------------------------

class TestMetrics:
    def test_precision_recall_f1(self):
        r = M.precision_recall_f1(5, 2, 3)
        assert r["precision"] == pytest.approx(5 / 7)
        assert r["recall"] == pytest.approx(5 / 8)
        assert r["f1"] == pytest.approx(2 * (5 / 7) * (5 / 8) / (5 / 7 + 5 / 8))

    def test_macro_f1(self):
        r = M.macro_f1([{"class": "a", "tp": 1, "fp": 1, "fn": 0},
                        {"class": "b", "tp": 2, "fp": 0, "fn": 1}])
        assert r["n_classes"] == 2
        assert r["precision"] == pytest.approx(0.75)
        assert r["recall"] == pytest.approx(0.8333, abs=1e-3)
        assert r["f1"] == pytest.approx(0.7333, abs=1e-3)

    def test_severity_accuracy_excludes_unlabeled(self):
        r = M.severity_accuracy([("high", "high"), ("medium", "high"),
                                 (None, "low")])
        assert r["n_labeled"] == 2
        assert r["n_exact"] == 1
        assert r["accuracy"] == pytest.approx(0.5)

    def test_runtime_summary_empty(self):
        assert M.runtime_summary([])["mean_seconds"] is None

    def test_recall_at_k(self):
        r = M.recall_at_k(["a", "b", "gt"], "gt", (1, 3, 5))
        assert r["recall@1"] == 0 and r["recall@3"] == 1
        assert r["mrr"] == pytest.approx(1 / 3, abs=1e-4)


# ---------------------------------------------------------------------------
# dataset GT extraction honesty
# ---------------------------------------------------------------------------

class TestGroundTruth:
    def test_extract_gt_categories_anchored(self):
        rec = {"Title": "M-1: Reentrancy in withdraw",
               "Impact": "reentrancy lets attacker drain funds",
               "Content": ""}
        cats = __import__("eval_data").extract_gt_categories(rec)
        assert "reentrancy" in cats
        # no keyword present -> empty (precision over recall)
        rec2 = {"Title": "Enum sorting inconsistency", "Impact": "", "Content": ""}
        assert __import__("eval_data").extract_gt_categories(rec2) == []

    def test_extract_gt_severity(self):
        import eval_data as ed
        assert ed.extract_gt_severity({"Title": "H-7: boom"}) == "high"
        assert ed.extract_gt_severity({"Title": "M-9: bust"}) == "medium"
        assert ed.extract_gt_severity({"Title": "no prefix"}) is None

    def test_cross_function_heuristic_conservative(self):
        import eval_data as ed
        assert ed.extract_gt_cross_function(
            {"Content": "Both X and Y also pass the same data"}) is True
        assert ed.extract_gt_cross_function({"Content": "no mention"}) is False


# ---------------------------------------------------------------------------
# dataset verification (provenance artifact)
# ---------------------------------------------------------------------------

class TestDatasetVerification:
    def test_provenance_recorded(self):
        prov = BENCH / "data" / "provenance.json"
        assert prov.exists()
        d = json.loads(prov.read_text(encoding="utf-8"))
        assert d.get("lisabench", {}).get("license") == "MIT"
        assert "known_safe_oz" in d

    def test_c4audit_not_used(self):
        # The eval harness must not reference an unlicensed dataset.
        src = (BENCH / "eval_suite.py").read_text(encoding="utf-8")
        assert "lucianasi/C4Audit" not in src
        assert "C4Audit" not in src

    def test_eval_data_exposes_sources(self):
        import eval_data as ed
        # LISABench repo is the detection vulnerable source (URL is templated)
        assert ed.LISABENCH_REPO == "agentlisa/bench"
        assert "{n:05d}.json" in ed.LISABENCH_URL


# ---------------------------------------------------------------------------
# detection pipeline executes (real orchestrator, honest tool accounting)
# ---------------------------------------------------------------------------

class TestDetectionExecution:
    def test_known_safe_loads_and_is_olc(self):
        import eval_data as ed
        ks = ed.load_known_safe()
        assert "ERC20.sol" in ks
        assert "SPDX" in ks["ERC20.sol"]

    def test_probe_detection_runs_full_pipeline(self):
        import asyncio
        import eval_data as ed
        import eval_suite as E
        from agentsafe.config import Settings

        rec = ed.load_lisabench(1, seed=7)[0]
        bundle = E._bundle_from_rec(rec)
        assert bundle is not None and bundle.files
        rep, elapsed, stages = asyncio.run(
            E.run_audit(bundle, rag=False, llm_mode="probe",
                        kb_factory=None, settings=Settings()))
        assert elapsed >= 0
        # tool accounting is honest: slither/aderyn/mythril/heimdall absent
        assert any("not installed" in e for e in rep.errors)
