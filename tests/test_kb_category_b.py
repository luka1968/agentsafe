"""Category B (attack-path knowledge) tests.

Covers:
  1. KB six-group registry: B = attack-paths.
  2. v3.jsonl loads with all Category B fields on every record (entry point,
     call sequence, internal/external calls, state vars/deps, attacker
     permissions, tx conditions, cross-function/contract deps, PoC ref).
  3. normalize_record maps Category B fields onto the import shape.
  4. _row_to_record surfaces Category B fields (round-trip through the
     renderer/consumer surface).
  5. render_kb_snippets includes the attack-path block (entry + sequence +
     state vars + cross-contract deps).
  6. Live-Neon (gated): v3 import idempotent; group-B records carry the
     organization columns and are retrievable with path fields intact.
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

V3 = Path(__file__).resolve().parents[1] / "src" / "agentsafe" / "knowledge" / "dataset" / "v3.jsonl"

B_FIELDS = (
    "attack_entry", "call_sequence", "internal_calls", "external_calls",
    "state_vars", "state_deps", "attacker_permissions", "tx_conditions",
    "cross_function_deps", "cross_contract_deps", "poc_reference",
)


class TestKBGroupsB:
    def test_group_b_registered(self):
        assert KB_GROUPS["B"] == "attack-paths"

    def test_all_six_groups_present(self):
        assert set(KB_GROUPS) == {"A", "B", "C", "D", "E", "F"}


class TestV3Dataset:
    def test_loads_with_category_b_fields(self):
        kb = KnowledgeBase.load(V3)
        assert len(kb.records) >= 8
        for r in kb.records:
            missing = [f for f in B_FIELDS if f not in r]
            assert not missing, f"{r['id']} missing {missing}"

    def test_required_quality_fields_present(self):
        kb = KnowledgeBase.load(V3)
        req = ("id", "source", "url", "category", "mechanism", "root_cause",
               "preconditions", "impact", "remediation", "keywords")
        for r in kb.records:
            assert all(r.get(k) for k in req), f"{r['id']} missing quality fields"

    def test_path_fields_are_populated(self):
        kb = KnowledgeBase.load(V3)
        for r in kb.records:
            assert r.get("attack_entry"), f"{r['id']} empty attack_entry"
            assert r.get("call_sequence"), f"{r['id']} empty call_sequence"
            assert r.get("cross_contract_deps") or r.get("cross_function_deps"), (
                f"{r['id']} no dependency fields")

    def test_normalize_maps_category_b_fields(self):
        kb = KnowledgeBase.load(V3)
        n = normalize_record(kb.records[0], source_name="agentsafe-v3.jsonl")
        assert n["kb_group"] == "B"
        assert n["verification_status"] == "curated"
        assert n["attack_entry"]
        assert isinstance(n["call_sequence"], list) and n["call_sequence"]
        assert isinstance(n["state_vars"], list)
        assert isinstance(n["tx_conditions"], list)
        assert n["poc_reference"]


class TestRowToRecordCategoryB:
    def test_path_fields_survive_reshape(self):
        row = {
            "external_record_id": "KB-2025-201", "description": "mech",
            "attack_entry": "splitDAO()", "call_sequence": '["a","b"]',
            "state_vars": '["balances[addr]"]', "cross_contract_deps": '["d"]',
            "metadata": "{}", "score": None,
        }
        rec = _row_to_record(row)
        assert rec["attack_entry"] == "splitDAO()"
        assert rec["call_sequence"] == ["a", "b"]
        assert rec["state_vars"] == ["balances[addr]"]
        assert rec["cross_contract_deps"] == ["d"]
        assert rec["poc_reference"] is None  # absent stays null

    def test_path_fields_default_to_empty_lists(self):
        rec = _row_to_record({"external_record_id": "X", "description": "m",
                              "metadata": "{}", "score": None})
        assert rec["call_sequence"] == []
        assert rec["state_vars"] == []
        assert rec["internal_calls"] == []


class TestRendererCategoryB:
    def test_attack_path_block_rendered(self):
        rec = {
            "id": "KB-2025-201", "category": "reentrancy",
            "protocol_type": "dao", "mechanism": "recursive split",
            "root_cause": "rc", "preconditions": ["p"], "impact": "drain",
            "remediation": "rem", "source": "s", "url": "https://x.test/1",
            "attack_entry": "splitDAO()",
            "call_sequence": ["splitDAO", "fallback reentry", "drain"],
            "state_vars": ["balances[addr]"],
            "cross_contract_deps": ["DAO <- child"],
        }
        out = render_kb_snippets([rec])
        assert "attack entry: splitDAO()" in out
        assert "call sequence: splitDAO -> fallback reentry -> drain" in out
        assert "state vars: balances[addr]" in out
        assert "cross-contract deps: DAO <- child" in out

    def test_no_path_fields_no_path_block(self):
        rec = {
            "id": "KB-1", "category": "oracle", "protocol_type": "defi",
            "mechanism": "m", "root_cause": "r", "preconditions": ["p"],
            "impact": "i", "remediation": "r", "source": "s",
            "url": "https://x.test/1",
        }
        out = render_kb_snippets([rec])
        assert "attack entry" not in out
        assert "call sequence" not in out


def _needs_neon():
    return bool(os.environ.get("NEON_DATABASE_URL", "").strip())


@pytest.mark.skipif(not _needs_neon(),
                    reason="NEON_DATABASE_URL not set; skipping live-Neon tests")
class TestCategoryBLive:
    @classmethod
    def setup_class(cls):
        from agentsafe.knowledge.db import NeonKnowledgeStore
        cls.store = NeonKnowledgeStore(
            dsn=os.environ["NEON_DATABASE_URL"].strip(), vector_dim=2048)

    def test_v3_import_idempotent(self):
        from agentsafe.knowledge.importers import import_jsonl_dataset
        before = self.store.count()
        s1 = import_jsonl_dataset(self.store, V3, source_name="agentsafe-v3.jsonl")
        mid = self.store.count()
        s2 = import_jsonl_dataset(self.store, V3, source_name="agentsafe-v3.jsonl")
        after = self.store.count()
        assert s1.inserted >= 8
        assert s2.inserted == 0 or s2.duplicates >= mid - before
        assert after == mid

    def test_group_b_rows_structured_and_retrievable(self):
        with self.store._connect() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT count(*) FROM vulnerability_knowledge
                WHERE source_id='agentsafe-v3.jsonl' AND kb_group='B'
            """)
            assert cur.fetchone()["count"] >= 8
        hits = self.store.search(
            "reentrancy split DAO call sequence cross-contract", limit=3)
        b = [h for h in hits if str(h.get("id", "")).startswith("KB-2025-2")]
        assert b, "no Category B record retrieved for attack-path query"
        assert all(h.get("attack_entry") for h in b)
        assert all(h.get("call_sequence") for h in b)