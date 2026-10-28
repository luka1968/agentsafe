"""Tests: security knowledge base (kb.py + dataset integrity)."""

from __future__ import annotations

from agentsafe.knowledge import DATASET_VERSION, KnowledgeBase


def _make_kb():
    return KnowledgeBase.load_default()


class TestDatasetIntegrity:
    def test_dataset_loads_and_is_versioned(self):
        kb = _make_kb()
        assert kb.version == DATASET_VERSION
        assert len(kb.records) >= 12

    def test_every_record_has_full_provenance(self):
        kb = _make_kb()
        required = ("id", "source", "url", "license", "category", "protocol_type",
                    "mechanism", "root_cause", "preconditions", "impact",
                    "remediation", "keywords")
        for r in kb.records:
            for k in required:
                assert r.get(k) not in (None, ""), f"{r['id']} missing {k}"
            assert isinstance(r["keywords"], list) and r["keywords"]
            assert r["url"].startswith("http")

    def test_categories_cover_agent_focuses(self):
        kb = _make_kb()
        cats = {r["category"] for r in kb.records}
        assert {"reentrancy", "access-control", "proxy", "oracle",
                "governance", "approval", "rounding", "initialization",
                "unhandled-return"} <= cats


class TestRetrieval:
    def test_keyword_retrieval_finds_related(self):
        kb = _make_kb()
        hits = kb.search("reentrancy withdraw call drain balance", focus="fund_flow",
                         limit=3)
        assert hits, "no hits"
        assert any("reentrancy" in h["category"] for h in hits)

    def test_focus_rerank_boosts_category(self):
        kb = _make_kb()
        ff = kb.search("transfer withdraw", focus="fund_flow", limit=3)
        ff_cats = {h["category"] for h in ff}
        assert ff_cats <= {"reentrancy", "unhandled-return", "token-transfer",
                           "cei", "accounting"}

    def test_no_query_returns_empty(self):
        kb = _make_kb()
        assert kb.search("", focus="") == []
        assert kb.search("the a an and", focus="") == []  # stopwords only

    def test_retrieval_orders_by_relevance(self):
        kb = _make_kb()
        hits = kb.search("approve race allowance front-run spend", limit=3)
        assert hits and hits[0]["category"] == "approval"


class TestLoaderValidation:
    def test_missing_provenance_fails_fast(self, tmp_path):
        p = tmp_path / "bad.jsonl"
        p.write_text('{"id":"x","mechanism":"m"}\n', encoding="utf-8")
        try:
            KnowledgeBase.load(p)
            assert False, "should have raised"
        except ValueError as e:
            assert "provenance" in str(e)

    def test_bad_json_fails_fast(self, tmp_path):
        p = tmp_path / "bad.jsonl"
        p.write_text("{not json}\n", encoding="utf-8")
        try:
            KnowledgeBase.load(p)
            assert False, "should have raised"
        except ValueError:
            pass

    def test_keywords_must_be_list(self, tmp_path):
        p = tmp_path / "bad.jsonl"
        rec = {"id": "x", "source": "s", "url": "u", "license": "l",
               "category": "c", "protocol_type": "p", "mechanism": "m",
               "root_cause": "r", "preconditions": [], "impact": "i",
               "remediation": "x", "keywords": "notalist"}
        p.write_text(__import__("json").dumps(rec) + "\n", encoding="utf-8")
        try:
            KnowledgeBase.load(p)
            assert False, "should have raised"
        except ValueError as e:
            assert "list" in str(e)

    def test_missing_file_loads_empty(self, tmp_path):
        kb = KnowledgeBase.load(tmp_path / "nope.jsonl")
        assert kb.records == []
        assert kb.search("anything") == []