"""LLM-structured KB enrichment tests (Task: knowledge-base intelligence).

Covers the non-destructive contract:
  * defensive JSON parsing (fenced/prose, invalid input, out-of-vocabulary
    category, clamped confidence, capped/lowercased tags, SWC validation);
  * plan_update fills only NULL/empty fields and never overwrites;
  * provenance of derived fields recorded in metadata.llm_enrichment;
  * the store pass enriches parents and propagates shared intelligence to
    chunk children, skipping curated/reproduced rows.
"""

import json

import pytest

from agentsafe.knowledge.enrich_llm import (
    VS_LLM_ENRICHED,
    ExtractedIntel,
    build_messages,
    enrich_group_a_llm,
    parse_extracted,
    plan_update,
    providers_from_env,
)

GOOD = {
    "root_cause": "withdraw() sends ETH before zeroing balances (violates CEI)",
    "attack_scenario": "attacker deposits, calls withdraw, re-enters via "
                       "receive() before balances are cleared, drains pool",
    "preconditions": ["withdraw sends ETH before state update",
                      "no reentrancy guard"],
    "impact": "complete loss of pooled funds",
    "remediation": "zero balances before the external call / add a guard",
    "category": "reentrancy",
    "subcategory": "single-function-cei",
    "swc_id": "SWC-107",
    "tags": ["Reentrancy", "withdraw", "CEI", "reentrancy"],
    "confidence": 1.7,
}


class TestParseExtracted:
    def test_parses_json_object(self):
        out = parse_extracted(json.dumps(GOOD))
        assert out.category == "reentrancy"
        assert out.swc_id == "SWC-107"
        assert out.root_cause and "CEI" in out.root_cause

    def test_parses_fenced_and_prose_wrapped(self):
        wrapped = "Here you go:\n```json\n" + json.dumps(GOOD) + "\n```\nDone."
        out = parse_extracted(wrapped)
        assert out.category == "reentrancy"
        assert out.attack_scenario

    def test_out_of_vocabulary_category_is_nulled(self):
        bad = dict(GOOD, category="some-new-taxonomy")
        assert parse_extracted(json.dumps(bad)).category is None

    def test_invalid_input_raises(self):
        with pytest.raises(ValueError):
            parse_extracted("no json here at all")

    def test_confidence_clamped_and_tags_normalised(self):
        out = parse_extracted(json.dumps(GOOD))
        assert out.confidence == 1.0                 # 1.7 clamped
        assert out.tags[0] == out.tags[0].lower()    # lowercased
        assert out.tags.count("reentrancy") == 1     # deduped
        assert len(out.tags) <= 8

    def test_bad_swc_nulled(self):
        bad = dict(GOOD, swc_id="CWE-79")
        assert parse_extracted(json.dumps(bad)).swc_id is None

    def test_null_strings_become_none(self):
        bad = dict(GOOD, root_cause="null", attack_scenario="N/A")
        out = parse_extracted(json.dumps(bad))
        assert out.root_cause is None and out.attack_scenario is None


class TestBuildMessages:
    def test_contains_title_categories_and_cap(self):
        msgs = build_messages("T", "x" * 50_000)
        joined = " ".join(m["content"] for m in msgs)
        assert "T" in joined and "reentrancy" in joined
        # report text is capped well below the raw size
        assert len(joined) < 20_000


class TestPlanUpdateNonDestructive:
    ROW = {
        "id": 1, "root_cause": None, "attack_scenario": None,
        "exploit_sequence": None, "impact": "EXISTING IMPACT",
        "remediation": None, "category": None, "preconditions": [],
        "subcategory": None, "swc_id": None, "tags": [], "confidence": None,
        "metadata": {}, "verification_status": "source",
    }

    def test_fills_nulls_only(self):
        intel = parse_extracted(json.dumps(GOOD))
        sets = plan_update(self.ROW, intel, model="m1", now="2026-01-01T00:00:00Z")
        assert sets["root_cause"]
        assert sets["category"] == "reentrancy"
        assert sets["verification_status"] == VS_LLM_ENRICHED
        assert "impact" not in sets                 # existing value untouched
        assert json.loads(sets["metadata"])["llm_enrichment"]["model"] == "m1"
        assert "impact" not in json.loads(sets["metadata"])["llm_enrichment"][
            "derived_fields"]

    def test_returns_empty_when_nothing_to_add(self):
        row = {
            "id": 2, "root_cause": "rc", "attack_scenario": "as",
            "exploit_sequence": "as", "impact": "i", "remediation": "r",
            "category": "oracle", "preconditions": ["p"], "subcategory": "s",
            "swc_id": "SWC-1", "tags": ["t"], "confidence": 0.5,
            "metadata": {}, "verification_status": "source",
        }
        intel = ExtractedIntel(root_cause="other", category="reentrancy")
        assert plan_update(row, intel) == {}


# --- fake store for the pass ------------------------------------------------
class _FakeCursor:
    def __init__(self, store):
        self.store = store
        self._rows = []
        self.rowcount = 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        s = " ".join(sql.split())
        self.store.executed.append((s, params))
        if s.startswith("SELECT") and "metadata->>'parent_external_id' = %s" in s:
            self._rows = [dict(r) for r in self.store.children.get(params[1], [])]
        elif s.startswith("SELECT") and "FROM vulnerability_knowledge" in s:
            self._rows = [dict(r) for r in self.store.parent_rows]
        elif s.startswith("UPDATE"):
            self.rowcount = 1
            self.store.updates.append((s, params))
            self._rows = []
        else:
            self._rows = []

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None


class _FakeConn:
    def __init__(self, store):
        self.store = store

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cursor(self):
        return _FakeCursor(self.store)


class _FakeStore:
    def __init__(self, parent_rows, children=None):
        self.parent_rows = parent_rows
        self.children = children or {}
        self.updates = []
        self.executed = []

    def _connect(self):
        return _FakeConn(self)


def _row(**kw):
    base = {
        "id": 1, "source_id": "speca-code4rena", "external_record_id": "c4:x:1",
        "title": "Reentrancy in withdraw", "description": "d",
        "category": None, "root_cause": None, "attack_scenario": None,
        "exploit_sequence": None, "impact": None, "remediation": None,
        "preconditions": [], "subcategory": None, "swc_id": None, "tags": [],
        "confidence": None, "metadata": {}, "verification_status": "source",
    }
    base.update(kw)
    return base


class TestEnrichPass:
    def test_enriches_parents_and_propagates_to_children(self):
        parent = _row(id=1, external_record_id="c4:x:1")
        child = _row(id=2, external_record_id="c4:x:1#chunk1",
                     metadata={"parent_external_id": "c4:x:1"})
        store = _FakeStore([parent], {"c4:x:1": [child]})
        calls = {"n": 0}

        def fake_llm(messages):
            calls["n"] += 1
            return json.dumps(GOOD)

        summary = enrich_group_a_llm(store, llm=fake_llm, limit=10)
        assert calls["n"] == 1
        assert summary.enriched == 1
        assert summary.children_updated >= 1
        # parent update carries root_cause; child update fills shared fields
        assert any("root_cause" in s for s, _p in store.updates)
        assert summary.fields_written.get("root_cause") == 1

    def test_skips_verified_rows(self):
        row = _row(id=5, verification_status="curated")
        store = _FakeStore([row])
        summary = enrich_group_a_llm(
            store, llm=lambda m: json.dumps(GOOD), limit=10)
        assert summary.skipped_verified == 1
        assert summary.enriched == 0
        assert store.updates == []

    def test_llm_failure_is_counted_not_fatal(self):
        rows = [_row(id=1, external_record_id="c4:x:1"),
                _row(id=3, external_record_id="c4:y:2")]

        def flaky(messages):
            raise RuntimeError("provider down")

        summary = enrich_group_a_llm(_FakeStore(rows), llm=flaky, limit=10)
        assert summary.failed == 2 and summary.enriched == 0


class TestProvidersFromEnv:
    def test_empty_when_unset(self, monkeypatch):
        monkeypatch.delenv("LLM_PROVIDERS_JSON", raising=False)
        assert providers_from_env() == []

    def test_preferred_first_and_skips_keyless(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDERS_JSON", json.dumps([
            {"name": "a", "base_url": "http://a", "api_key": "k", "model": "ma"},
            {"name": "b", "base_url": "http://b", "api_key": "k",
             "model": "mb", "preferred": True},
            {"name": "c", "base_url": "http://c", "api_key": "", "model": "mc"},
        ]))
        provs = providers_from_env()
        assert [p["name"] for p in provs] == ["b", "a"]
