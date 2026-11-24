"""Phase 3 structured-intelligence projection tests.

Locks the honest-partial contract: fields map from the record's existing
columns, missing facts stay null (never invented), and the store pass writes
only the additive projection.
"""

from __future__ import annotations

import json

from agentsafe.knowledge.structured import (
    SCHEMA,
    build_structured_intel,
    coverage,
    source_reference,
    structure_store,
)

FULL = {
    "id": 42, "source_id": "speca-code4rena",
    "external_record_id": "code4rena:2022-01-x-findings:7", "title": "Stale oracle",
    "description": "reads a stale price", "category": "oracle",
    "subcategory": "freshness", "cwe_id": None, "swc_id": "SWC-107",
    "severity": "High", "verification_status": "source",
    "quality_status": "VALIDATED", "quality_claim": "unverified-source",
    "source_url": "https://code4rena.com/x", "metadata": {"contest": "x"},
    "root_cause": "no freshness check", "vulnerable_code": "p = oracle.latest()",
    "corrected_code": "p = fresh()", "affected_function": "peek",
    "affected_contract": "Oracle", "state_vars": ["lastPrice"],
    "external_calls": ["oracle.latestRoundData"], "internal_calls": [],
    "solc_version": "0.8.19", "attack_entry": "peek()", "attacker_permissions": [],
    "preconditions": ["feed is stale"], "attack_scenario": "1. wait; 2. call",
    "exploit_sequence": None, "call_sequence": ["peek()"], "tx_conditions": ["same block"],
    "state_deps": ["lastPrice"], "cross_contract_deps": ["oracle"], "impact": "mint cheap",
    "poc_code": "it('x', ...)", "poc_reference": None, "test_setup": "foundry",
    "test_tooling": None, "test_result": "confirmed", "verification_evidence": "tx",
    "fp_patterns": ["fresh feed is safe"], "refutation_signals": None,
    "security_pattern": "use fresh price", "safe_code": None, "known_limitations": None,
    "remediation": "check freshness", "related_vuln_classes": "oracle-staleness",
}


class TestBuild:
    def test_maps_existing_fields(self):
        s = build_structured_intel(FULL)
        assert s["identification"]["record_id"] == 42
        assert s["identification"]["swc_id"] == "SWC-107"
        assert s["identification"]["source_reference"] == "https://code4rena.com/x"
        assert s["root_cause"]["root_cause"] == "no freshness check"
        assert s["root_cause"]["affected_function"] == "peek"
        assert s["exploit_intelligence"]["attack_entry"] == "peek()"
        assert s["exploit_intelligence"]["attack_sequence"] == "1. wait; 2. call"
        assert s["remediation"]["root_cause_remediation"] == "check freshness"

    def test_exploitability_conditions_combine_preconditions_and_tx(self):
        s = build_structured_intel(FULL)
        assert s["exploit_intelligence"]["exploitability_conditions"] == [
            "feed is stale", "same block"]

    def test_missing_facts_are_null_not_invented(self):
        s = build_structured_intel({"id": 1, "title": "t"})
        assert s["identification"]["cwe_id"] is None
        assert s["root_cause"]["evm_semantics"] is None
        assert s["exploit_intelligence"]["attacker_model"] is None
        assert s["exploit_intelligence"]["required_capital"] is None
        assert s["verification"]["proof_of_concept"] is None
        assert s["remediation"]["related_records"] is None

    def test_source_reference_falls_back_to_id(self):
        rec = {"external_record_id": "sherlock:sentiment-update:M-4",
               "metadata": {"source_platform": "sherlock",
                            "contest": "sentiment-update", "issue_id": "M-4"}}
        assert source_reference(rec) == "sherlock:sentiment-update:M-4"

    def test_schema_shape_stable(self):
        s = build_structured_intel({"id": 1})
        for section, fields in SCHEMA.items():
            assert set(fields) == set(s[section])

    def test_coverage_counts(self):
        c = coverage(build_structured_intel(FULL))
        assert c["root_cause"]["filled"] >= 5
        assert c["verification"]["total"] == len(SCHEMA["verification"])


# --- fake store -------------------------------------------------------------
class _Cursor:
    def __init__(self, store):
        self.store = store
        self._rows = []
        self.rowcount = 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self._rows = [dict(r) for r in self.store.rows]
        self.rowcount = 1

    def executemany(self, sql, seq):
        seq = list(seq)
        self.store.updates.extend(seq)
        self.rowcount = len(seq)

    def fetchall(self):
        return list(self._rows)


class _Conn:
    def __init__(self, store):
        self.store = store

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cursor(self):
        return _Cursor(self.store)


class _Store:
    def __init__(self, rows):
        self.rows = rows
        self.updates = []

    def _connect(self):
        return _Conn(self)


class TestStorePass:
    def test_writes_projection_only(self):
        store = _Store([FULL, {"id": 2, "title": "minimal"}])
        summary = structure_store(store)
        assert summary.scanned == 2 and summary.written == 2
        # update tuple = (intel_json, id); content columns untouched
        for payload, _rid in store.updates:
            intel = json.loads(payload)
            assert set(intel) == set(SCHEMA)
        ids = {rid for _p, rid in store.updates}
        assert ids == {42, 2}
        assert summary.section_fill["exploit_intelligence"]["total"] > 0
