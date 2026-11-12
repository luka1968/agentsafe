"""Category D (oracle-vulnerability) and Category E (secure-code /
false-positive) knowledge tests.

Covers:
  D: KB groups registry (D = oracle); v5.jsonl loads with the oracle fields
     (oracle_type, price_source, freshness_requirements, price_validation)
     plus vulnerable code / preconditions / exploit / remediation / evidence;
     normalize + _row_to_record round-trip; renderer shows the oracle block;
     live import idempotent + retrievable.
  E: KB groups registry (E = secure-code-fp); v6.jsonl loads with the
     secure-pattern fields (security_pattern, safe_code, required_assumptions,
     why_safe, known_limitations, related_vuln_classes, fp_patterns,
     evidence_required); renderer shows the secure-code block (why-safe +
     false-positive shapes + evidence required); live import idempotent.
"""

import os
from pathlib import Path

import pytest

from agentsafe.knowledge.db import _row_to_record
from agentsafe.knowledge.enrich import KB_GROUPS
from agentsafe.knowledge.kb import KnowledgeBase
from agentsafe.knowledge.importers import normalize_record
from agentsafe.intel.render import render_kb_snippets

V5 = Path(__file__).resolve().parents[1] / "src" / "agentsafe" / "knowledge" / "dataset" / "v5.jsonl"
V6 = Path(__file__).resolve().parents[1] / "src" / "agentsafe" / "knowledge" / "dataset" / "v6.jsonl"

D_FIELDS = ("oracle_type", "price_source", "freshness_requirements",
            "price_validation")
E_FIELDS = ("security_pattern", "safe_code", "required_assumptions", "why_safe",
            "known_limitations", "related_vuln_classes", "fp_patterns",
            "evidence_required")
REQ = ("id", "source", "url", "category", "mechanism", "root_cause",
       "preconditions", "impact", "remediation", "keywords")


class TestKBGroupsDE:
    def test_groups_d_and_e_registered(self):
        assert KB_GROUPS["D"] == "oracle"
        assert KB_GROUPS["E"] == "secure-code-fp"

    def test_all_six_groups_present(self):
        assert set(KB_GROUPS) == {"A", "B", "C", "D", "E", "F"}


class TestV5Oracle:
    def test_loads_with_oracle_fields(self):
        kb = KnowledgeBase.load(V5)
        assert len(kb.records) >= 6
        for r in kb.records:
            missing = [f for f in D_FIELDS if not r.get(f)]
            assert not missing, f"{r['id']} missing {missing}"
            assert all(r.get(k) for k in REQ), f"{r['id']} missing quality fields"
            assert r.get("code_evidence") and r.get("corrected_code")

    def test_cover_oracle_focus_areas(self):
        kb = KnowledgeBase.load(V5)
        titles = " ".join((r["title"] or "") + " " + (r["mechanism"] or "")
                          for r in kb.records).lower()
        for topic in ("stale", "twap", "spot", "sequencer", "decimal",
                      "fallback", "feed", "deviation", "freshness"):
            assert topic in titles, f"v5 missing oracle focus area: {topic}"

    def test_normalize_maps_oracle_fields(self):
        kb = KnowledgeBase.load(V5)
        n = normalize_record(kb.records[0], source_name="agentsafe-v5.jsonl")
        assert n["kb_group"] == "D"
        assert n["oracle_type"] and n["price_source"]
        assert n["freshness_requirements"] and n["price_validation"]
        assert n["vulnerable_code"] and n["corrected_code"]


class TestV6SecureCode:
    def test_loads_with_secure_pattern_fields(self):
        kb = KnowledgeBase.load(V6)
        assert len(kb.records) >= 7
        for r in kb.records:
            missing = [f for f in E_FIELDS if not r.get(f)]
            assert not missing, f"{r['id']} missing {missing}"
            assert all(r.get(k) for k in REQ), f"{r['id']} missing quality fields"

    def test_covers_named_patterns(self):
        kb = KnowledgeBase.load(V6)
        patterns = {r.get("security_pattern") for r in kb.records}
        for p in ("checks-effects-interactions", "reentrancy-guard",
                  "access-control", "safe-token-transfer", "safe-arithmetic",
                  "initialization-protection", "signature-verification",
                  "secure-upgrade", "low-level-call-usage"):
            assert p in patterns, f"missing safe pattern: {p}"

    def test_false_positive_guidance_present(self):
        kb = KnowledgeBase.load(V6)
        for r in kb.records:
            assert r.get("fp_patterns"), f"{r['id']} missing fp_patterns"
            assert r.get("evidence_required"), f"{r['id']} missing evidence_required"
        # The IMPORTANT requirement: not every external/low-level call is a vuln
        fp = "\n".join(
            (r["fp_patterns"] if isinstance(r["fp_patterns"], str)
             else "\n".join(r["fp_patterns"]))
            for r in kb.records).lower()
        assert "not" in fp and "finding" in fp


class TestRowToRecordDE:
    def test_oracle_fields_survive_reshape(self):
        row = {"external_record_id": "KB-2025-401", "description": "m",
               "oracle_type": "chainlink",
               "price_source": "latestRoundData()",
               "freshness_requirements": "within MAX_STALE",
               "price_validation": "price>0, round>0",
               "metadata": "{}", "score": None}
        rec = _row_to_record(row)
        assert rec["oracle_type"] == "chainlink"
        assert rec["price_source"] == "latestRoundData()"
        assert rec["freshness_requirements"] == "within MAX_STALE"
        assert rec["price_validation"] == "price>0, round>0"

    def test_secure_fields_survive_reshape(self):
        row = {"external_record_id": "KB-2025-501", "description": "m",
               "security_pattern": "checks-effects-interactions",
               "why_safe": "state finalized before call",
               "fp_patterns": "call at end is not a finding",
               "evidence_required": "show a post-call state write",
               "metadata": "{}", "score": None}
        rec = _row_to_record(row)
        assert rec["security_pattern"] == "checks-effects-interactions"
        assert rec["why_safe"] == "state finalized before call"
        assert rec["fp_patterns"] == "call at end is not a finding"
        assert rec["evidence_required"] == "show a post-call state write"


class TestRendererDE:
    def test_oracle_block_rendered(self):
        rec = {"id": "KB-2025-401", "category": "oracle", "protocol_type": "defi",
               "mechanism": "m", "root_cause": "r", "preconditions": ["p"],
               "impact": "i", "remediation": "r", "source": "s",
               "url": "https://x.test/1", "oracle_type": "chainlink",
               "price_source": "latestRoundData()",
               "freshness_requirements": "within MAX_STALE",
               "price_validation": "price > 0"}
        out = render_kb_snippets([rec])
        assert "oracle type: chainlink" in out
        assert "price source: latestRoundData()" in out
        assert "freshness required: within MAX_STALE" in out
        assert "price validation: price > 0" in out

    def test_secure_block_rendered(self):
        rec = {"id": "KB-2025-501", "category": "reentrancy",
               "protocol_type": "generic", "mechanism": "m", "root_cause": "r",
               "preconditions": ["p"], "impact": "i", "remediation": "r",
               "source": "s", "url": "https://x.test/1",
               "security_pattern": "checks-effects-interactions",
               "why_safe": "state finalized before the call",
               "known_limitations": "does not cover read-only reentrancy",
               "fp_patterns": "a trailing call is not a finding",
               "evidence_required": "show a post-call state write"}
        out = render_kb_snippets([rec])
        assert "security pattern: checks-effects-interactions" in out
        assert "why safe: state finalized before the call" in out
        assert "false-positive shapes: a trailing call is not a finding" in out
        assert "evidence required to report" in out


def _needs_neon():
    return bool(os.environ.get("NEON_DATABASE_URL", "").strip())


@pytest.mark.skipif(not _needs_neon(),
                    reason="NEON_DATABASE_URL not set; skipping live-Neon tests")
class TestCategoryDELive:
    @classmethod
    def setup_class(cls):
        from agentsafe.knowledge.db import NeonKnowledgeStore
        cls.store = NeonKnowledgeStore(
            dsn=os.environ["NEON_DATABASE_URL"].strip(), vector_dim=2048)

    def test_v5_v6_import_idempotent(self):
        from agentsafe.knowledge.importers import import_jsonl_dataset
        before = self.store.count()
        s5 = import_jsonl_dataset(self.store, V5, source_name="agentsafe-v5.jsonl")
        mid = self.store.count()
        s6 = import_jsonl_dataset(self.store, V6, source_name="agentsafe-v6.jsonl")
        after = self.store.count()
        s5b = import_jsonl_dataset(self.store, V5, source_name="agentsafe-v5.jsonl")
        s6b = import_jsonl_dataset(self.store, V6, source_name="agentsafe-v6.jsonl")
        assert s5.inserted >= 6 and s6.inserted >= 7
        assert s5b.inserted == 0 and s6b.inserted == 0
        assert self.store.count() == after

    def test_group_d_e_rows_structured_and_retrievable(self):
        with self.store._connect() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT count(*) FROM vulnerability_knowledge
                WHERE source_id='agentsafe-v5.jsonl' AND kb_group='D'
            """)
            assert cur.fetchone()["count"] >= 6
            cur.execute("""
                SELECT count(*) FROM vulnerability_knowledge
                WHERE source_id='agentsafe-v6.jsonl' AND kb_group='E'
            """)
            assert cur.fetchone()["count"] >= 7
        hits = self.store.search(
            "oracle stale chainlink latestRoundData freshness", limit=3)
        d = [h for h in hits if str(h.get("id", "")).startswith("KB-2025-4")]
        assert d and all(h.get("oracle_type") for h in d)