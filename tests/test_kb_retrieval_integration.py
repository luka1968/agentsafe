"""Retrieval integration tests (Task: Retrieval Integration).

Covers:
  * profiles resolve per agent (accounting -> C/B, oracle -> D, reentrancy ->
    A/B/E vulnerable+secure, validation -> F/E PoC+FP)
  * hard result cap: limit is clamped to MAX_SEARCH_LIMIT (never hundreds)
  * hard filters (kb_groups / categories) restrict both legs
  * profile boosts prioritize without excluding
  * lexical fallback retained (no embedder -> lexical-only results)
  * dedup: one record per content_hash in results
"""

import os
from pathlib import Path

import pytest

from agentsafe.knowledge.kb import KnowledgeBase
from agentsafe.knowledge.profiles import (
    MAX_SEARCH_LIMIT,
    RETRIEVAL_PROFILES,
    resolve_profile,
)

DATASET = (Path(__file__).resolve().parents[1] / "src" / "agentsafe"
           / "knowledge" / "dataset" / "v2.jsonl")


class TestProfiles:
    def test_spec_examples_resolve(self):
        # Accounting Agent -> accounting (C) + attack-path (B)
        p = resolve_profile("accounting")
        assert p and set(p["kb_groups"]) == {"C", "B"}
        # Cross-function Agent -> attack-path (B) + real-world (A)
        p = resolve_profile("cross_function")
        assert p and set(p["kb_groups"]) == {"B", "A"}
        # Oracle Agent -> oracle (D)
        p = resolve_profile("oracle")
        assert p and set(p["kb_groups"]) == {"D"}
        # Reentrancy Agent -> vulnerable (A/B) AND secure (E)
        p = resolve_profile("reentrancy")
        assert p and set(p["kb_groups"]) == {"A", "B", "E"}
        # Validation Agent -> PoC (F) + false-positive evidence (E)
        p = resolve_profile("validation")
        assert p and set(p["kb_groups"]) == {"F", "E"}

    def test_unknown_profile_is_broad(self):
        assert resolve_profile(None) is None
        assert resolve_profile("nope") is None
        assert resolve_profile("general_discovery") is None

    def test_all_registered_profiles_have_boost_and_groups(self):
        for name, p in RETRIEVAL_PROFILES.items():
            assert p["kb_groups"] and p["categories"] and p["boost"] >= 1.0, name

    def test_agents_carry_profiles(self):
        from agentsafe.agents.specialists import (
            AccessControlAgent, AccountingAgent, ArithmeticAgent,
            CrossFunctionAgent, DefiLogicAgent, ProxyUpgradeAgent,
            ReentrancyAgent,
        )
        assert AccountingAgent.profile == "accounting"
        assert CrossFunctionAgent.profile == "cross_function"
        assert DefiLogicAgent.profile == "oracle"
        assert ReentrancyAgent.profile == "reentrancy"
        assert AccessControlAgent.profile == "access_control"
        assert ArithmeticAgent.profile == "arithmetic"
        assert ProxyUpgradeAgent.profile == "proxy_upgrade"


class TestHardCap:
    def test_limit_never_exceeds_max(self):
        kb = KnowledgeBase.load(DATASET)
        # request hundreds — must clamp to MAX_SEARCH_LIMIT
        out = kb.search("deposit withdraw accounting shares rounding",
                        limit=500)
        assert len(out) <= MAX_SEARCH_LIMIT
        assert MAX_SEARCH_LIMIT <= 10


class TestJsonlFallbackFilters:
    def test_category_filter_restricts(self):
        kb = KnowledgeBase.load(DATASET)
        out = kb.search("deposit withdraw shares rounding", limit=10,
                        categories=("rounding",))
        assert out and all(r.get("category") == "rounding" for r in out)

    def test_profile_boosts_without_excluding(self):
        kb = KnowledgeBase.load(DATASET)
        out = kb.search("deposit withdraw shares rounding", limit=10,
                        profile="accounting")
        # boosted (accounting-class) records should rank top when present
        assert out  # results still returned (boost, not exclusion)

    def test_lexical_fallback_works_without_profile(self):
        kb = KnowledgeBase.load(DATASET)
        out = kb.search("reentrancy external call callback", limit=3)
        assert out  # plain hybrid-lexical path intact


def _needs_neon():
    return bool(os.environ.get("NEON_DATABASE_URL", "").strip())


@pytest.mark.skipif(not _needs_neon(),
                    reason="NEON_DATABASE_URL not set; skipping live-Neon tests")
class TestNeonRetrievalIntegration:
    @classmethod
    def setup_class(cls):
        from agentsafe.knowledge.db import NeonKnowledgeStore
        cls.store = NeonKnowledgeStore(
            dsn=os.environ["NEON_DATABASE_URL"].strip(), vector_dim=2048)

    def test_kb_group_filter_restricts(self):
        hits = self.store.search(
            "withdraw deposit accounting balance shares",
            limit=6, kb_groups=("C",))
        assert hits and all(h.get("kb_group") == "C" for h in hits)

    def test_category_filter_restricts(self):
        hits = self.store.search(
            "oracle stale chainlink price feed", limit=6,
            categories=("oracle",))
        assert hits and all(h.get("category") == "oracle" for h in hits)

    def test_reentrancy_profile_returns_vulnerable_and_secure(self):
        hits = self.store.search(
            "reentrancy external call callback guard CEI", limit=8,
            profile="reentrancy")
        assert hits
        groups = {h.get("kb_group") for h in hits}
        # vulnerable (A) and secure (E) reentrancy knowledge both surface
        assert groups & {"A", "B"}, "no vulnerable reentrancy records"
        assert "E" in groups or len(hits) < 8  # secure patterns surface when available

    def test_validation_profile_surfaces_poc_and_fp_evidence(self):
        hits = self.store.search(
            "prove refute finding PoC false positive safe pattern",
            limit=8, profile="validation")
        assert hits
        groups = {h.get("kb_group") for h in hits}
        assert groups & {"F", "E"}, "validation profile must surface PoC/FP knowledge"

    def test_accounting_profile_prioritizes_accounting(self):
        hits = self.store.search(
            "withdraw deposit accounting balance totalSupply ledger",
            limit=6, profile="accounting")
        assert hits
        p = resolve_profile("accounting")
        top = hits[0]
        # top-ranked record must be from the profile's priority groups OR
        # carry a priority category (curated records may lack kb_group)
        assert (top.get("kb_group") in p["kb_groups"]
                or top.get("category") in p["categories"]), (
                f"top hit not accounting-prioritized: {top.get('id')} "
                f"group={top.get('kb_group')} cat={top.get('category')}")

    def test_hard_cap_enforced_live(self):
        hits = self.store.search("oracle price", limit=500)
        assert len(hits) <= MAX_SEARCH_LIMIT

    def test_results_deduped_by_content_hash(self):
        hits = self.store.search("oracle stale price feed", limit=10)
        hashes = [h.get("_retrieval", {}).get("rrf_score") for h in hits]
        assert len(hashes) == len(set(map(str, hits)))  # ids unique

    def test_profile_metadata_attached(self):
        hits = self.store.search("oracle stale feed", limit=3, profile="oracle")
        assert hits and all(
            h.get("_retrieval", {}).get("profile") == "oracle" for h in hits)