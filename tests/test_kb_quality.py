"""Phase 2 knowledge data-quality classification tests.

The classifier annotates records without touching the source fields. These
tests lock the rubric per class and the non-destructive store pass.
"""

from __future__ import annotations

import json

from agentsafe.knowledge.quality import (
    DUPLICATE,
    INCOMPLETE,
    INVALID,
    NEEDS_REVIEW,
    VALIDATED,
    assess_record,
    assess_store,
    base_record_id,
    category_supported,
    claim_status,
    find_near_duplicates,
    looks_like_code,
)

GOOD_DESC = (
    "The pool reads a Chainlink oracle price without checking round freshness, "
    "so a stale price can be used to mint collateral at the wrong value.")


def _valid_row(**kw):
    base = {
        "id": 1, "source_id": "speca-code4rena",
        "external_record_id": "code4rena:x-findings:1", "title": "Stale oracle",
        "description": GOOD_DESC, "category": "oracle", "severity": "High",
        "root_cause": "no freshness check on the oracle round",
        "attack_scenario": "1. wait for a stale round; 2. mint at the stale price",
        "preconditions": ["oracle feed is stale", "no freshness check"],
        "vulnerable_code": "price = oracle.latestAnswer();", "corrected_code": None,
        "solc_version": None, "swc_id": "SWC-107",
        "tags": ["oracle", "chainlink"], "source_url": "https://code4rena.com/x",
        "metadata": {"contest": "x"}, "verification_status": "source",
    }
    base.update(kw)
    return base


class TestHelpers:
    def test_category_supported(self):
        assert category_supported("reentrancy via callback", "reentrancy") is True
        assert category_supported("a totally unrelated note", "oracle") is False
        assert category_supported("x", "not-a-category") is None

    def test_looks_like_code(self):
        assert looks_like_code("function f() { x = 1; }") is True
        assert looks_like_code("5e18 * 262800 / 1e21 = 1.25e17") is False
        assert looks_like_code("") is True

    def test_base_record_id_strips_chunk(self):
        assert base_record_id("c4:x:1#chunk2") == "c4:x:1"
        assert base_record_id("c4:x:1") == "c4:x:1"

    def test_claim_status_honest(self):
        assert claim_status("reproduced") == "reproduced"
        assert claim_status("curated") == "curated"
        assert claim_status("source") == "unverified-source"
        assert claim_status(None) == "unverified-source"


class TestAssessRecord:
    def test_complete_record_is_validated(self):
        a = assess_record(_valid_row())
        assert a.status == VALIDATED, a.flags
        assert a.claim == "unverified-source"

    def test_missing_category_is_incomplete(self):
        a = assess_record(_valid_row(category=None))
        assert a.status == INCOMPLETE
        assert "missing_category" in a.flags

    def test_short_description_is_incomplete(self):
        a = assess_record(_valid_row(description="too short"))
        assert a.status == INCOMPLETE
        assert "short_description" in a.flags

    def test_missing_preconditions_is_incomplete(self):
        a = assess_record(_valid_row(preconditions=[]))
        assert a.status == INCOMPLETE
        assert "missing_preconditions" in a.flags

    def test_invalid_when_no_title_desc_or_source(self):
        a = assess_record({"id": 9, "title": None, "description": None,
                           "external_record_id": None, "source_url": None,
                           "metadata": {}})
        assert a.status == INVALID

    def test_missing_attack_scenario_needs_review(self):
        a = assess_record(_valid_row(attack_scenario=None))
        assert a.status == NEEDS_REVIEW
        assert "missing_attack_scenario" in a.flags

    def test_unknown_severity_needs_review(self):
        a = assess_record(_valid_row(severity="SuperHigh"))
        assert a.status == NEEDS_REVIEW
        assert "unknown_severity" in a.flags

    def test_non_solidity_snippet_needs_review(self):
        a = assess_record(_valid_row(
            vulnerable_code="9 * 100 / 1000 = 0"))
        assert a.status == NEEDS_REVIEW
        assert "non_solidity_code_snippet" in a.flags

    def test_possible_misclassification(self):
        # category says oracle, but the text only evidences reentrancy
        a = assess_record(_valid_row(
            title="Reentrancy drain",
            category="oracle",
            description="A reentrancy bug: an external call before the state "
                        "update lets the attacker re-enter and drain funds.",
            root_cause="external call before state update (CEI violation)"))
        assert "possible_misclassification" in a.flags

    def test_missing_source_url_is_informational(self):
        # The reference is still recoverable from the external id, so a missing
        # URL is flagged for transparency but does not downgrade the record.
        a = assess_record(_valid_row(source_url=None))
        assert "missing_source_url" in a.flags
        assert a.status == VALIDATED


class TestNearDuplicates:
    def test_distinct_ids_same_content_is_duplicate(self):
        a = _valid_row(id=1, external_record_id="c4:x:1")
        b = _valid_row(id=2, external_record_id="c4:y:2")
        dups = find_near_duplicates([a, b])
        assert dups.get(2) == 1

    def test_parent_and_chunk_are_not_duplicates(self):
        parent = _valid_row(id=1, external_record_id="c4:x:1")
        chunk = _valid_row(id=2, external_record_id="c4:x:1#chunk1")
        assert find_near_duplicates([parent, chunk]) == {}


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
        self.store.updates.extend(list(seq))
        self.rowcount = len(list(seq))

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


class TestAssessStore:
    def test_writes_classification_without_touching_content(self):
        rows = [_valid_row(id=1), _valid_row(id=2, category=None)]
        store = _Store(rows)
        summary = assess_store(store)
        assert summary.scanned == 2
        assert summary.by_status.get(VALIDATED) == 1
        assert summary.by_status.get(INCOMPLETE) == 1
        assert len(store.updates) == 2
        # update tuple = (status, flags_json, claim, id)
        statuses = {u[3]: u[0] for u in store.updates}
        assert statuses[1] == VALIDATED and statuses[2] == INCOMPLETE

    def test_duplicate_status_assigned_in_store_pass(self):
        rows = [_valid_row(id=1, external_record_id="a:1"),
                _valid_row(id=2, external_record_id="b:2")]
        store = _Store(rows)
        summary = assess_store(store)
        assert summary.by_status.get(DUPLICATE) == 1
        assert summary.duplicates and summary.duplicates[0]["duplicate_of"] == 1
        flags = json.loads([u for u in store.updates if u[3] == 2][0][1])
        assert any(str(f).startswith("near_duplicate_of") for f in flags)
