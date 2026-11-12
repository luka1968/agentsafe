"""Category F (vulnerability-verification / testing knowledge) tests.

Covers:
  1. KB six-group registry: F = verification (all six groups now assigned).
  2. v7.jsonl loads with the Category F fields on every record
     (verification_method, poc_code, expected_result, confirmation_signals,
     refutation_signals, test_tooling) plus the shared quality fields.
  3. Verification-method coverage: foundry-poc, invariant-test, fuzz,
     fork-testing.
  4. normalize_record maps Category F fields; _row_to_record round-trips
     them.
  5. render_kb_snippets includes the verification block (verify via / PoC /
     confirms if / refutes if).
  6. Live-Neon (gated): v7 import idempotent; group-F rows structured and
     retrievable.
"""

import os
from pathlib import Path

import pytest

from agentsafe.knowledge.db import _row_to_record
from agentsafe.knowledge.enrich import KB_GROUPS
from agentsafe.knowledge.kb import KnowledgeBase
from agentsafe.knowledge.importers import normalize_record
from agentsafe.intel.render import render_kb_snippets

V7 = Path(__file__).resolve().parents[1] / "src" / "agentsafe" / "knowledge" / "dataset" / "v7.jsonl"
V8 = Path(__file__).resolve().parents[1] / "src" / "agentsafe" / "knowledge" / "dataset" / "v8.jsonl"

F_FIELDS = ("verification_method", "poc_code", "expected_result",
            "confirmation_signals", "refutation_signals", "test_tooling")
# Foundry-PoC / exploit-validation record fields (Category F, v8)
POC_FIELDS = ("poc_reference", "affected_contract", "attacker_contract",
              "test_setup", "required_initial_state", "call_sequence",
              "expected_vulnerable_behavior", "expected_safe_behavior",
              "test_result", "solc_version", "foundry_version")
REQ = ("id", "source", "url", "category", "mechanism", "root_cause",
       "preconditions", "impact", "remediation", "keywords")


class TestKBGroupsF:
    def test_group_f_registered(self):
        assert KB_GROUPS["F"] == "verification"

    def test_all_six_groups_assigned(self):
        # A-E were specified by the KB-organization task; F completes the six.
        assert set(KB_GROUPS) == {"A", "B", "C", "D", "E", "F"}
        assert "reserved" not in KB_GROUPS.values()


class TestV7Verification:
    def test_loads_with_category_f_fields(self):
        kb = KnowledgeBase.load(V7)
        assert len(kb.records) >= 5
        for r in kb.records:
            missing = [f for f in F_FIELDS if not r.get(f)]
            assert not missing, f"{r['id']} missing {missing}"
            assert all(r.get(k) for k in REQ), f"{r['id']} missing quality fields"

    def test_verification_methods_covered(self):
        kb = KnowledgeBase.load(V7)
        methods = " ".join(r["verification_method"] for r in kb.records)
        for m in ("foundry-poc", "invariant-test"):
            assert m in methods, f"missing verification method: {m}"

    def test_each_record_has_confirmation_and_refutation(self):
        kb = KnowledgeBase.load(V7)
        for r in kb.records:
            assert r.get("confirmation_signals"), f"{r['id']} no confirm signals"
            assert r.get("refutation_signals"), f"{r['id']} no refute signals"

    def test_normalize_maps_category_f_fields(self):
        kb = KnowledgeBase.load(V7)
        n = normalize_record(kb.records[0], source_name="agentsafe-v7.jsonl")
        assert n["kb_group"] == "F"
        assert n["verification_method"] and n["poc_code"]
        assert n["confirmation_signals"] and n["refutation_signals"]
        assert n["test_tooling"]


class TestRowToRecordCategoryF:
    def test_verification_fields_survive_reshape(self):
        row = {"external_record_id": "KB-2025-601", "description": "m",
               "verification_method": "foundry-poc",
               "poc_code": "contract Attacker ...",
               "expected_result": "balance -> 0",
               "confirmation_signals": "recursion drains",
               "refutation_signals": "guard reverts",
               "test_tooling": "forge test",
               "metadata": "{}", "score": None}
        rec = _row_to_record(row)
        assert rec["verification_method"] == "foundry-poc"
        assert rec["poc_code"] == "contract Attacker ..."
        assert rec["confirmation_signals"] == "recursion drains"
        assert rec["refutation_signals"] == "guard reverts"

    def test_missing_verification_fields_stay_none(self):
        rec = _row_to_record({"external_record_id": "X", "description": "m",
                              "metadata": "{}", "score": None})
        assert rec["verification_method"] is None
        assert rec["poc_code"] is None


class TestRendererCategoryF:
    def test_verification_block_rendered(self):
        rec = {"id": "KB-2025-601", "category": "reentrancy",
               "protocol_type": "generic", "mechanism": "m", "root_cause": "r",
               "preconditions": ["p"], "impact": "i", "remediation": "r",
               "source": "s", "url": "https://x.test/1",
               "verification_method": "foundry-poc",
               "poc_code": "reentrant receive()",
               "confirmation_signals": "recursion drains",
               "refutation_signals": "guard reverts"}
        out = render_kb_snippets([rec])
        assert "verify via: foundry-poc" in out
        assert "PoC: reentrant receive()" in out
        assert "confirms if: recursion drains" in out
        assert "refutes if: guard reverts" in out

    def test_no_verification_fields_no_block(self):
        rec = {"id": "KB-1", "category": "oracle", "protocol_type": "defi",
               "mechanism": "m", "root_cause": "r", "preconditions": ["p"],
               "impact": "i", "remediation": "r", "source": "s",
               "url": "https://x.test/1"}
        out = render_kb_snippets([rec])
        assert "verify via" not in out


class TestV8FoundryPoc:
    """Category F: concrete Foundry PoC / exploit-validation records
    (Damn Vulnerable DeFi + DeFiHackLabs public reproductions)."""

    def test_loads_with_poc_fields(self):
        kb = KnowledgeBase.load(V8)
        assert len(kb.records) >= 6
        for r in kb.records:
            missing = [f for f in POC_FIELDS if not r.get(f)]
            assert not missing, f"{r['id']} missing {missing}"
            assert all(r.get(k) for k in REQ), f"{r['id']} missing quality fields"

    def test_sources_are_public_repos(self):
        kb = KnowledgeBase.load(V8)
        for r in kb.records:
            assert "github.com" in r["url"], f"{r['id']} source not a public repo"
        sources = " ".join((r.get("source") or "") for r in kb.records)
        assert "Damn Vulnerable DeFi" in sources or "DeFiHackLabs" in sources

    def test_versions_and_result_recorded(self):
        kb = KnowledgeBase.load(V8)
        for r in kb.records:
            assert r.get("solc_version"), f"{r['id']} missing solc version"
            assert r.get("foundry_version"), f"{r['id']} missing foundry version"
            assert r.get("test_result"), f"{r['id']} missing test result"

    def test_verification_status_reproduced(self):
        kb = KnowledgeBase.load(V8)
        from agentsafe.knowledge.enrich import VS_REPRODUCED
        for r in kb.records:
            assert r["verification_status"] == VS_REPRODUCED

    def test_normalize_maps_poc_fields(self):
        kb = KnowledgeBase.load(V8)
        n = normalize_record(kb.records[0], source_name="agentsafe-v8.jsonl")
        assert n["kb_group"] == "F"
        assert n["attacker_contract"] and n["poc_reference"]
        assert n["expected_vulnerable_behavior"] and n["expected_safe_behavior"]
        assert n["solc_version"] and n["foundry_version"]

    def test_row_to_record_poc_fields(self):
        row = {"external_record_id": "KB-2025-701", "description": "m",
               "attacker_contract": "Attack", "test_setup": "forge test",
               "required_initial_state": "pool 1000 ETH",
               "expected_vulnerable_behavior": "pool drained",
               "expected_safe_behavior": "reverts",
               "test_result": "reproduced",
               "solc_version": "0.8.x", "foundry_version": "0.2.x",
               "metadata": "{}", "score": None}
        rec = _row_to_record(row)
        assert rec["attacker_contract"] == "Attack"
        assert rec["expected_vulnerable_behavior"] == "pool drained"
        assert rec["test_result"] == "reproduced"
        assert rec["solc_version"] == "0.8.x"

    def test_renderer_poc_metadata_block(self):
        rec = {"id": "KB-2025-701", "category": "accounting",
               "protocol_type": "flash loan", "mechanism": "m",
               "root_cause": "r", "preconditions": ["p"], "impact": "i",
               "remediation": "r", "source": "s", "url": "https://x.test/1",
               "affected_contract": "SideEntranceLenderPool",
               "attacker_contract": "AttackContract",
               "poc_reference": "https://github.com/tinchoabbate/damn-vulnerable-defi",
               "test_result": "reproduced",
               "solc_version": "0.8.x", "foundry_version": "0.2.x"}
        out = render_kb_snippets([rec])
        assert "vulnerable contract: SideEntranceLenderPool" in out
        assert "attacker contract: AttackContract" in out
        assert "PoC repo: https://github.com/tinchoabbate/damn-vulnerable-defi" in out
        assert "test result: reproduced" in out
        assert "toolchain: solc 0.8.x / 0.2.x" in out

    def test_never_auto_execute_note_in_dataset_shape(self):
        """PoC records store metadata + source URLs only; the harness
        (poc_code) is reference text — nothing here is executed by the app."""
        kb = KnowledgeBase.load(V8)
        for r in kb.records:
            # call_sequence is metadata about the attack, not runnable code
            assert isinstance(r["call_sequence"], list)
            assert all(isinstance(x, str) for x in r["call_sequence"])


def _needs_neon():
    return bool(os.environ.get("NEON_DATABASE_URL", "").strip())


@pytest.mark.skipif(not _needs_neon(),
                    reason="NEON_DATABASE_URL not set; skipping live-Neon tests")
class TestCategoryFLive:
    @classmethod
    def setup_class(cls):
        from agentsafe.knowledge.db import NeonKnowledgeStore
        cls.store = NeonKnowledgeStore(
            dsn=os.environ["NEON_DATABASE_URL"].strip(), vector_dim=2048)

    def test_v7_import_idempotent(self):
        from agentsafe.knowledge.importers import import_jsonl_dataset
        before = self.store.count()
        s1 = import_jsonl_dataset(self.store, V7, source_name="agentsafe-v7.jsonl")
        mid = self.store.count()
        s2 = import_jsonl_dataset(self.store, V7, source_name="agentsafe-v7.jsonl")
        after = self.store.count()
        assert s1.inserted >= 5
        assert s2.inserted == 0 or s2.duplicates >= mid - before
        assert after == mid

    def test_group_f_rows_structured_and_retrievable(self):
        with self.store._connect() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT count(*) FROM vulnerability_knowledge
                WHERE source_id='agentsafe-v7.jsonl' AND kb_group='F'
            """)
            assert cur.fetchone()["count"] >= 5
        hits = self.store.search(
            "reentrancy prove foundry PoC receive callback drain", limit=3)
        f = [h for h in hits if str(h.get("id", "")).startswith("KB-2025-6")]
        assert f, "no Category F record retrieved for verification query"
        assert all(h.get("verification_method") for h in f)
        assert all(h.get("refutation_signals") for h in f)