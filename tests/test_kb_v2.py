"""KB upgrade (v2 curated dataset) tests.

Covers:
  1. v2.jsonl is a valid, loadable dataset with all required provenance and
     structured fields (mechanism, root_cause, preconditions, exploit
     sequence, impact, remediation, vulnerable_code, corrected_code).
  2. `_row_to_record` preserves attack_scenario / vulnerable_code /
     corrected_code so the renderer and agents see exploit walk-throughs.
  3. `render_kb_snippets` surfaces the attack scenario + vulnerable/corrected
     code (the decision-relevant fields) within the budget cap.
  4. v2 seeding in get_knowledge_store is idempotent (only imported when the
     source is absent).
"""

import os
from pathlib import Path

import pytest

from agentsafe.knowledge.db import NeonKnowledgeStore, _row_to_record
from agentsafe.knowledge.kb import KnowledgeBase
from agentsafe.knowledge.importers import import_jsonl_dataset, normalize_record
from agentsafe.intel.render import render_kb_snippets

DSN = os.environ.get("NEON_DATABASE_URL", "").strip()
needs_neon = pytest.mark.skipif(
    not DSN, reason="NEON_DATABASE_URL not set; skipping live-Neon tests")

V2 = Path(__file__).resolve().parents[1] / "src" / "agentsafe" / "knowledge" / "dataset" / "v2.jsonl"

REQUIRED = ("id", "source", "url", "category", "mechanism", "root_cause",
            "preconditions", "impact", "remediation", "keywords")


class TestV2Dataset:
    def test_loads_with_all_required_fields(self):
        kb = KnowledgeBase.load(V2)
        assert len(kb.records) >= 10
        for r in kb.records:
            missing = [k for k in REQUIRED if not r.get(k)]
            assert not missing, f"{r.get('id')} missing {missing}"

    def test_covers_gap_categories(self):
        kb = KnowledgeBase.load(V2)
        cats = {r["category"] for r in kb.records}
        # the categories that failed in the WETH9 audit must be represented
        assert "accounting" in cats
        assert "reentrancy" in cats
        assert "oracle" in cats
        assert "access-control" in cats

    def test_every_record_has_attack_walkthrough_and_code(self):
        kb = KnowledgeBase.load(V2)
        for r in kb.records:
            assert r.get("exploit_sequence") or r.get("attack_scenario"), (
                f"{r['id']} missing exploit_sequence")
            assert r.get("code_evidence") or r.get("vulnerable_code"), (
                f"{r['id']} missing code_evidence")

    def test_normalize_maps_v2_fields(self):
        kb = KnowledgeBase.load(V2)
        n = normalize_record(kb.records[0], source_name="agentsafe-v2.jsonl")
        # exploit_sequence -> attack_scenario (the column the schema stores)
        assert n["attack_scenario"]
        # code_evidence -> vulnerable_code
        assert n["vulnerable_code"]

    def test_no_chunk_splitting_for_concise_records(self):
        # Concise records should not be split into chunk children, so the
        # parent retains full provenance (root_cause etc. not nulled).
        kb = KnowledgeBase.load(V2)
        norms = [normalize_record(r, source_name="agentsafe-v2.jsonl") for r in kb.records]
        from agentsafe.knowledge.importers import _split_long_records
        expanded = list(_split_long_records(norms))
        assert len(expanded) == len(norms)


class TestRowToRecordPreservesStructuredFields:
    def test_attack_scenario_survives_reshape(self):
        row = {
            "external_record_id": "X1", "category": "accounting",
            "protocol_domain": "vault", "description": "mech",
            "root_cause": "rc", "preconditions": ["p"], "impact": "i",
            "remediation": "r", "attack_scenario": "attacker does A then B",
            "vulnerable_code": "bad();", "corrected_code": "good();",
            "source_name": "s1", "source_url": "https://x.test/1",
            "metadata": {}, "score": 0.9,
        }
        rec = _row_to_record(row)
        assert rec["attack_scenario"] == "attacker does A then B"
        assert rec["vulnerable_code"] == "bad();"
        assert rec["corrected_code"] == "good();"

    def test_exploit_sequence_alias_maps_to_attack_scenario(self):
        row = {
            "external_record_id": "X2", "description": "mech",
            "exploit_sequence": "step1; step2", "metadata": {}, "score": None,
        }
        rec = _row_to_record(row)
        assert rec["attack_scenario"] == "step1; step2"


class TestRendererSurfacesDecisionFields:
    def test_attack_scenario_included(self):
        rec = {
            "id": "KB-1", "category": "accounting", "protocol_type": "vault",
            "mechanism": "ledger drift", "root_cause": "rc",
            "preconditions": ["p"], "impact": "insolvency",
            "remediation": "single source of truth",
            "attack_scenario": "deposit, force-send, withdraw",
            "vulnerable_code": "totalSupply() { return this.balance; }",
            "corrected_code": "totalSupply() { return _supply; }",
            "source": "s", "url": "https://x.test/1",
        }
        out = render_kb_snippets([rec])
        assert "attack scenario" in out
        assert "deposit, force-send, withdraw" in out
        assert "vulnerable code" in out
        assert "corrected code" in out

    def test_budget_still_capped(self):
        rec = {
            "id": "KB-1", "category": "accounting", "protocol_type": "vault",
            "mechanism": "m" * 900, "root_cause": "r" * 600,
            "preconditions": ["p" * 300], "impact": "i" * 400,
            "remediation": "r" * 500, "attack_scenario": "a" * 600,
            "vulnerable_code": "v" * 400, "corrected_code": "c" * 400,
            "source": "s", "url": "https://x.test/1",
        }
        out = render_kb_snippets([rec])
        from agentsafe.intel.render import KB_BUDGET_CHARS
        # whole snippet list bounded by the hard budget; per-body content is
        # separately capped by KB_SNIPPET_CHARS inside the renderer.
        assert len(out) <= KB_BUDGET_CHARS


@needs_neon
class TestV2SeedingLive:
    @classmethod
    def setup_class(cls):
        cls.store = NeonKnowledgeStore(dsn=DSN, vector_dim=2048)
        cls.store.migrate()

    def test_v2_import_idempotent(self):
        """Importing v2 twice adds nothing the second time (dedup by hash)."""
        before = self.store.count()
        s1 = import_jsonl_dataset(self.store, V2, source_name="agentsafe-v2.jsonl")
        mid = self.store.count()
        s2 = import_jsonl_dataset(self.store, V2, source_name="agentsafe-v2.jsonl")
        after = self.store.count()
        # second run: all duplicates, count unchanged
        assert s1.inserted >= 10
        assert s2.inserted == 0 or s2.duplicates >= mid - before
        assert after == mid

    def test_v2_records_searchable_and_structured(self):
        hits = self.store.search(
            "withdraw deposit accounting balance totalSupply ledger drift",
            focus="fund_flow", limit=3)
        # at least one structured v2 accounting record is retrievable with
        # its attack scenario intact
        found = [h for h in hits if str(h.get("id", "")).startswith("KB-2025-1")]
        assert found, "no v2 record retrieved for accounting query"
        assert all(h.get("attack_scenario") for h in found)
        assert all(h.get("vulnerable_code") for h in found)