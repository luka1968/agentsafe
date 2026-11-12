"""Category C (accounting-vulnerability knowledge) tests.

Covers:
  1. KB six-group registry: C = accounting.
  2. v4.jsonl loads with the Category C fields on every record (vulnerable
     formula/code, expected invariant, actual incorrect behavior,
     preconditions, financial impact, exploit sequence, safe implementation,
     verification evidence) plus the shared quality fields.
  3. Focus areas coverage: accounting / rounding / oracle (exchange-rate,
     valuation) / token-transfer (fee-on-transfer accounting).
  4. normalize_record maps Category C fields; _row_to_record round-trips
     them (invariant / incorrect_behavior / verification_evidence).
  5. render_kb_snippets includes the accounting block (expected invariant +
     incorrect behavior + verification evidence).
  6. Live-Neon (gated): v4 import idempotent; group-C rows structured and
     retrievable.
"""

import json
import os
from pathlib import Path

import pytest

from agentsafe.knowledge.db import _row_to_record
from agentsafe.knowledge.enrich import KB_GROUPS
from agentsafe.knowledge.kb import KnowledgeBase
from agentsafe.knowledge.importers import normalize_record
from agentsafe.intel.render import render_kb_snippets

V4 = Path(__file__).resolve().parents[1] / "src" / "agentsafe" / "knowledge" / "dataset" / "v4.jsonl"

C_FIELDS = (
    "invariant", "incorrect_behavior", "verification_evidence",
    "code_evidence", "exploit_sequence",
)


class TestKBGroupsC:
    def test_group_c_registered(self):
        assert KB_GROUPS["C"] == "accounting"

    def test_all_six_groups_present(self):
        assert set(KB_GROUPS) == {"A", "B", "C", "D", "E", "F"}


class TestV4Dataset:
    def test_loads_with_category_c_fields(self):
        kb = KnowledgeBase.load(V4)
        assert len(kb.records) >= 8
        for r in kb.records:
            missing = [f for f in C_FIELDS if not r.get(f)]
            assert not missing, f"{r['id']} missing {missing}"

    def test_required_quality_fields_present(self):
        kb = KnowledgeBase.load(V4)
        req = ("id", "source", "url", "category", "mechanism", "root_cause",
               "preconditions", "impact", "remediation", "keywords")
        for r in kb.records:
            assert all(r.get(k) for k in req), f"{r['id']} missing quality fields"

    def test_focus_areas_covered(self):
        kb = KnowledgeBase.load(V4)
        cats = {r["category"] for r in kb.records}
        # accounting (balance/ledger), rounding (shares/precision),
        # oracle (exchange-rate / valuation), token-transfer (fee-on-transfer)
        assert "accounting" in cats
        assert "rounding" in cats
        assert "oracle" in cats
        assert "token-transfer" in cats

    def test_each_record_has_vulnerable_and_safe_code(self):
        kb = KnowledgeBase.load(V4)
        for r in kb.records:
            assert r.get("code_evidence"), f"{r['id']} missing code_evidence"
            assert r.get("corrected_code"), f"{r['id']} missing corrected_code"

    def test_normalize_maps_category_c_fields(self):
        kb = KnowledgeBase.load(V4)
        n = normalize_record(kb.records[0], source_name="agentsafe-v4.jsonl")
        assert n["kb_group"] == "C"
        assert n["invariant"]
        assert n["incorrect_behavior"]
        assert n["verification_evidence"]
        assert n["vulnerable_code"]          # code_evidence -> vulnerable_code
        assert n["attack_scenario"]           # exploit_sequence -> attack_scenario


class TestRowToRecordCategoryC:
    def test_accounting_fields_survive_reshape(self):
        row = {
            "external_record_id": "KB-2025-301", "description": "mech",
            "invariant": "shares(assets)*rate == assets",
            "incorrect_behavior": "rounds to zero",
            "verification_evidence": "foundry test",
            "metadata": "{}", "score": None,
        }
        rec = _row_to_record(row)
        assert rec["invariant"] == "shares(assets)*rate == assets"
        assert rec["incorrect_behavior"] == "rounds to zero"
        assert rec["verification_evidence"] == "foundry test"

    def test_missing_accounting_fields_stay_none(self):
        rec = _row_to_record({"external_record_id": "X", "description": "m",
                              "metadata": "{}", "score": None})
        assert rec["invariant"] is None
        assert rec["incorrect_behavior"] is None
        assert rec["verification_evidence"] is None


class TestRendererCategoryC:
    def test_accounting_block_rendered(self):
        rec = {
            "id": "KB-2025-301", "category": "rounding",
            "protocol_type": "vault", "mechanism": "share inflation",
            "root_cause": "rc", "preconditions": ["p"], "impact": "loss",
            "remediation": "rem", "source": "s", "url": "https://x.test/1",
            "invariant": "no value transfer between depositors",
            "incorrect_behavior": "victim shares round to zero",
            "verification_evidence": "foundry: attacker redeem > victim deposit",
        }
        out = render_kb_snippets([rec])
        assert "expected invariant" in out
        assert "no value transfer between depositors" in out
        assert "incorrect behavior" in out
        assert "victim shares round to zero" in out
        assert "verification evidence" in out

    def test_no_accounting_fields_no_block(self):
        rec = {
            "id": "KB-1", "category": "reentrancy", "protocol_type": "defi",
            "mechanism": "m", "root_cause": "r", "preconditions": ["p"],
            "impact": "i", "remediation": "r", "source": "s",
            "url": "https://x.test/1",
        }
        out = render_kb_snippets([rec])
        assert "expected invariant" not in out


def _needs_neon():
    return bool(os.environ.get("NEON_DATABASE_URL", "").strip())


@pytest.mark.skipif(not _needs_neon(),
                    reason="NEON_DATABASE_URL not set; skipping live-Neon tests")
class TestCategoryCLive:
    @classmethod
    def setup_class(cls):
        from agentsafe.knowledge.db import NeonKnowledgeStore
        cls.store = NeonKnowledgeStore(
            dsn=os.environ["NEON_DATABASE_URL"].strip(), vector_dim=2048)

    def test_v4_import_idempotent(self):
        from agentsafe.knowledge.importers import import_jsonl_dataset
        before = self.store.count()
        s1 = import_jsonl_dataset(self.store, V4, source_name="agentsafe-v4.jsonl")
        mid = self.store.count()
        s2 = import_jsonl_dataset(self.store, V4, source_name="agentsafe-v4.jsonl")
        after = self.store.count()
        assert s1.inserted >= 8
        assert s2.inserted == 0 or s2.duplicates >= mid - before
        assert after == mid

    def test_group_c_rows_structured_and_retrievable(self):
        with self.store._connect() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT count(*) FROM vulnerability_knowledge
                WHERE source_id='agentsafe-v4.jsonl' AND kb_group='C'
            """)
            assert cur.fetchone()["count"] >= 8
        hits = self.store.search(
            "share inflation first depositor invariant rounding", limit=3)
        c = [h for h in hits if str(h.get("id", "")).startswith("KB-2025-3")]
        assert c, "no Category C record retrieved for accounting query"
        assert all(h.get("invariant") for h in c)
        assert all(h.get("incorrect_behavior") for h in c)