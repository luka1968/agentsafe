"""Phase 8 benchmark self-tests: metric correctness and required coverage.

The benchmark itself runs against the live KB; these tests lock the pure metric
logic and assert the case list covers every required vulnerability class.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "kb_retrieval_bench", ROOT / "benchmarks" / "kb_retrieval_bench.py")
bench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bench)


class TestMetrics:
    CASE = {"expected": ("reentrancy",)}

    def test_precision_recall_mrr(self):
        hits = [
            {"id": "KB-1", "category": "reentrancy", "url": "u"},   # relevant + in set
            {"id": "KB-9", "category": "oracle"},                   # irrelevant
            {"id": "KB-2", "category": "reentrancy"},              # relevant, not in set
        ]
        m = bench._metrics(hits, self.CASE, relevant={"KB-1", "KB-2"})
        assert m["precision@k"] == round(2 / 3, 4)
        assert m["recall@k"] == 1.0            # both relevant ids found
        assert m["mrr"] == 1.0                 # first hit relevant
        assert m["hit"] is True
        assert m["source_refs_preserved"] == round(1 / 3, 4)

    def test_no_relevant_records_recall_is_none(self):
        hits = [{"id": "x", "category": "oracle"}]
        m = bench._metrics(hits, self.CASE, relevant=set())
        assert m["recall@k"] is None          # metric not measurable
        assert m["precision@k"] == 0.0

    def test_empty_hits(self):
        m = bench._metrics([], self.CASE, relevant={"KB-1"})
        assert m["precision@k"] == 0.0 and m["mrr"] == 0.0


class TestCaseCoverage:
    def test_required_classes_present(self):
        ids = {c["id"] for c in bench.CASES}
        required = {
            "reentrancy", "cross_function_reentrancy", "accounting",
            "access_control", "arithmetic", "oracle_manipulation",
            "token_integration", "signature_validation", "denial_of_service",
            "cross_contract", "business_logic", "evm_rollback_counterexample",
            "solc_version_specific", "false_positive_examples"}
        assert required <= ids

    def test_two_counterexample_cases(self):
        ce = [c for c in bench.CASES if c["kind"] == "counterexample"]
        assert len(ce) == 2
        assert all(c.get("code") for c in ce)  # code markers drive FP detection

    def test_ground_truth_not_taken_from_titles(self):
        # guard: queries must be class-level prose, not record titles
        for c in bench.CASES:
            assert c["query"] and not c["query"].startswith("KB-")
