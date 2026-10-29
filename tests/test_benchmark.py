"""Regression tests for the retrieval benchmark machinery (Stage 7).

Keeps metric math + id normalization deterministic without touching the
live Neon DB / NVIDIA API. The full protocol runs via
`benchmarks/retrieval_bench.py` against the live store.
"""

from __future__ import annotations

from agentsafe.knowledge import db as db_mod

from benchmarks.retrieval_bench import (
    discriminative,
    evaluate,
    norm_id,
    summarize,
)


class TestNormId:
    def test_collapses_chunk_variants(self):
        assert norm_id("c4:2022-02-hubble:127#chunk2") == "c4:2022-02-hubble:127"
        assert norm_id("c4:2022-02-hubble:127#chunk") == "c4:2022-02-hubble:127"
        assert norm_id("c4:2022-02-hubble:127") == "c4:2022-02-hubble:127"

    def test_strips_whitespace(self):
        assert norm_id("  c4:x:1  ") == "c4:x:1"


class TestDiscriminative:
    def test_rejects_generic_and_short(self):
        assert not discriminative("QA Report")
        assert not discriminative("QA Summary")
        assert not discriminative("N/A")
        assert not discriminative("short")  # < 8 chars
        assert not discriminative("  low/  ")

    def test_accepts_specific_titles(self):
        assert discriminative("latestAnswer doesn't check freshness")
        assert discriminative("Unchecked oracle return value")


class TestEvaluate:
    def test_hit_at_rank_1(self):
        r = evaluate(["c4:2022-02-hubble:127", "other"], "c4:2022-02-hubble:127")
        assert r["hit"] and r["rank"] == 1
        assert r["recall1"] == r["recall3"] == r["recall5"] == 1
        assert r["mrr"] == 1.0

    def test_hit_at_rank_3(self):
        r = evaluate(["a", "b", "c4:x:9#chunk1", "d"], "c4:x:9")
        assert r["hit"] and r["rank"] == 3
        assert r["recall1"] == 0 and r["recall3"] == 1 and r["recall5"] == 1
        assert abs(r["mrr"] - 1 / 3) < 1e-9

    def test_miss(self):
        r = evaluate(["a", "b"], "c4:gt:1")
        assert not r["hit"] and r["rank"] is None
        assert r["recall1"] == r["recall3"] == r["recall5"] == 0
        assert r["mrr"] == 0.0

    def test_chunk_variant_matches_gt(self):
        # ground truth id vs retrieved chunk of same finding -> hit
        r = evaluate(["c4:2022-02-hubble:127#chunk2"], "c4:2022-02-hubble:127")
        assert r["hit"] and r["rank"] == 1


class TestSummarize:
    def test_averages(self):
        res = [
            evaluate(["gt:1", "x"], "gt:1"),          # rank1 mrr 1
            evaluate(["a", "gt:2", "b"], "gt:2"),      # rank2 mrr .5
            evaluate(["a", "b"], "gt:3"),              # miss
        ]
        s = summarize(res)
        assert s["n"] == 3
        assert s["recall@1"] == round(1 / 3, 4)
        assert s["recall@3"] == round(2 / 3, 4)
        assert s["mrr"] == round(1.5 / 3, 4)
        assert s["hits"] == 2 and s["misses"] == 1


class TestLegSurfaces:
    def test_search_leg_methods_exist(self):
        assert hasattr(db_mod.NeonKnowledgeStore, "search_leg_vector")
        assert hasattr(db_mod.NeonKnowledgeStore, "search_leg_lexical")

    def test_leg_vector_offline_empty(self):
        # no embedder configured -> vector leg degrades to [] (no fake vectors)
        st = db_mod.NeonKnowledgeStore(dsn="postgresql://x@y/z", vector_dim=2048,
                                       embedding_model=None)
        assert st._leg_vector("anything", 5) == []
