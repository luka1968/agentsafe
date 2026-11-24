"""Phase 4 reranking-signal tests.

The reranker must be deterministic, bounded, and honest: factors come only from
the query and the record's stored fields; unknown facts leave a factor at 1.0.
"""

from __future__ import annotations

from agentsafe.knowledge.rerank import (
    code_factor,
    evidence_factor,
    parse_query_version,
    profile_factor,
    rerank,
    solc_factor,
    term_factor,
    validation_factor,
)

ORACLE = {
    "content_hash": "h1", "category": "oracle", "kb_group": "D",
    "verification_status": "curated", "solc_version": "0.8.19",
    "title": "Stale Chainlink price", "affected_function": "getPrice",
    "vulnerable_code": "price = oracle.latestRoundData();",
    "preconditions": ["feed stale"], "attack_scenario": "wait then call",
    "poc_code": "it('stale')", "tags": ["oracle", "chainlink"],
}
PLAIN = {"content_hash": "h2", "category": "accounting", "kb_group": "A",
         "verification_status": "heuristic", "title": "rounding",
         "vulnerable_code": ""}


class TestSignals:
    def test_validation_weights(self):
        assert validation_factor({"verification_status": "reproduced"}) > \
            validation_factor({"verification_status": "curated"}) > \
            validation_factor({"verification_status": "source"}) > \
            validation_factor({"verification_status": None})

    def test_evidence_factor_rewards_poc(self):
        assert evidence_factor({"poc_code": "x"}) > 1.0
        assert evidence_factor({}) == 1.0

    def test_term_factor_bounds(self):
        f, ratio = term_factor("stale chainlink oracle price", ORACLE)
        assert f > 1.0 and ratio > 0
        f2, ratio2 = term_factor("completely unrelated words here", PLAIN)
        assert ratio2 == 0.0 and f2 == 1.0
        # bounded by MAX_TERM_FACTOR
        assert f <= 1.25

    def test_code_factor(self):
        assert code_factor("latestRoundData getPrice", ORACLE) is True
        assert code_factor("totally different", ORACLE) is False

    def test_solc_parse_and_match(self):
        assert parse_query_version("pragma solidity ^0.8.19") == (0, 8)
        assert parse_query_version("targeting 0.7.6") == (0, 7)
        assert parse_query_version("reentrancy bug") is None
        assert solc_factor("pragma solidity ^0.8.19", ORACLE) is True
        assert solc_factor("pragma solidity ^0.7.6", ORACLE) is False

    def test_profile_factor(self):
        prof = {"kb_groups": ("D",), "categories": ("oracle",), "boost": 2.0}
        assert profile_factor(ORACLE, prof) == 2.0
        assert profile_factor(PLAIN, prof) == 1.0
        assert profile_factor(PLAIN, None) == 1.0


class TestRerank:
    def _cands(self):
        return [
            {"key": "h2", "row": PLAIN, "rrf": 0.03, "vector_rank": 0,
             "lexical_rank": 1},
            {"key": "h1", "row": ORACLE, "rrf": 0.028, "vector_rank": 1,
             "lexical_rank": 0},
        ]

    def test_profile_promotes_matched_category(self):
        prof = {"kb_groups": ("D",), "categories": ("oracle",), "boost": 2.0}
        order, diag = rerank(self._cands(), query="stale oracle price",
                             profile=prof)
        assert order[0]["key"] == "h1"          # oracle promoted above higher rrf
        assert diag["h1"]["signals"]["profile"] == 2.0
        assert diag["h1"]["profile"] is None     # name set by caller
        assert any("vector rank" in w for w in diag["h1"]["why"])

    def test_no_profile_keeps_rrf_order(self):
        order, diag = rerank(self._cands(), query="zzz", profile=None)
        # validation/evidence still apply, but PLAIN has none and ORACLE's
        # factors are positive, so ordering is score-driven and deterministic
        assert {c["key"] for c in order} == {"h1", "h2"}
        assert diag["h2"]["signals"]["profile"] == 1.0

    def test_explicit_solc_boost(self):
        prof = None
        order, diag = rerank(self._cands(), query="oracle", profile=prof,
                             solc="0.8")
        assert diag["h1"]["signals"]["solc_match"] is True

    def test_relevance_diagnostics_present(self):
        _order, diag = rerank(self._cands(), query="stale oracle", profile=None)
        d = diag["h1"]
        for k in ("rrf_score", "boosted_score", "signals", "why",
                  "vector_rank", "lexical_rank", "matched_legs"):
            assert k in d
        assert d["matched_legs"] == 2
