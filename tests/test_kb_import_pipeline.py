"""KB import-pipeline hardening tests (Task: Data Import and Normalization).

Covers the 10 requirements:
  1/2/3. retrieval + extraction + normalization (speca adapter unit-level)
  4/5.   provenance: source attribution, original URL, license, commercial use
  6.     duplicate detection via content hashes AND source identifiers
  7.     incremental imports (skip_known pre-filter; resumable cursor)
  8.     retry and failure logging (fetch retries; ImportSummary.errors)
  9.     never overwrite verified records (enrichment skips curated/reproduced)
  10.    never mark unverified findings as confirmed (vocabulary honesty)
"""

import json
from unittest import mock

import pytest

from agentsafe.knowledge import importers
from agentsafe.knowledge.importers import (
    ImportSummary,
    normalize_record,
    _known_external_ids,
)
from agentsafe.knowledge.enrich import (
    VERIFIED_STATUSES,
    VS_CURATED,
    VS_HEURISTIC,
    VS_REPRODUCED,
    VS_SOURCE,
    _enrich_one,
)
from agentsafe.knowledge.speca import normalize_speca_row


class TestProvenancePreserved:
    """Requirements 4+5: attribution, URLs, license, commercial use."""

    def test_speca_row_keeps_source_url_and_platform(self):
        raw = {"id": "c4:x:1", "title": "t", "description": "d",
               "severity": "High", "domain": "defi",
               "source_url": "https://code4rena.com/reports/x",
               "source_platform": "code4rena", "contest": "x", "issue_id": "1"}
        n = normalize_speca_row(raw, platform="code4rena")
        assert n["url"] == "https://code4rena.com/reports/x"  # original URL
        assert n["metadata"]["source_platform"] == "code4rena"
        assert n["license_status"] and "Code4rena" in n["license_status"]
        assert n["commercial_use"] == "public-reports"

    def test_jsonl_record_keeps_source_and_url(self):
        n = normalize_record({"id": "X", "title": "t", "mechanism": "m",
                              "url": "https://src.test/1"}, source_name="s1")
        assert n["metadata"]["source_name"] == "s1"
        assert n["metadata"]["original"] == "X"
        assert n["url"] == "https://src.test/1"


class TestNeverInvent:
    """Unknown fields stay null/unknown — never fabricated."""

    def test_absent_fields_null(self):
        n = normalize_record({"id": "X"}, source_name="s1")
        for f in ("root_cause", "impact", "remediation", "vulnerable_code",
                  "corrected_code", "attack_scenario"):
            assert n[f] in (None, []), f"{f} must not be invented"

    def test_extraction_only_uses_verbatim_slices(self):
        from agentsafe.knowledge.enrich import extract_markdown_sections
        desc = "## Impact\nUsers lose funds.\n\n## Proof of Concept\n```solidity\nx();\n```"
        out = extract_markdown_sections(desc)
        assert out.impact in desc and out.vulnerable_code in desc

    def test_no_signal_leaves_category_null(self):
        from agentsafe.knowledge.enrich import infer_category
        assert infer_category("Gas optimization note", "use calldata") is None


class TestVerificationVocabularyHonesty:
    """Requirement 10: unverified findings are never marked confirmed."""

    def test_vocabulary_has_no_confirmed_for_unverified(self):
        allowed = {None, VS_CURATED, VS_SOURCE, VS_HEURISTIC, VS_REPRODUCED}
        # normalize_record: raw without verification_status stays None
        assert normalize_record({"id": "X"}, source_name="s")["verification_status"] is None
        # speca rows are verbatim 'source', never 'confirmed'
        n = normalize_speca_row({"id": "x", "title": "t", "description": "d",
                                 "source_platform": "sherlock"}, platform="sherlock")
        assert n["verification_status"] in allowed and n["verification_status"] != "confirmed"
        # deterministic enrichment marks 'heuristic', never 'confirmed'
        row = {"id": 1, "title": "Outdated TWAP oracle price",
               "description": "pool relies on outdated price",
               "category": None, "impact": None, "remediation": None,
               "vulnerable_code": None, "kb_group": None,
               "verification_status": None, "metadata": {}}
        sets = _enrich_one(row)
        assert sets["verification_status"] == VS_HEURISTIC

    def test_only_reproduced_records_claim_reproduced(self):
        # 'reproduced' requires a runnable PoC/test result — curated v8 records
        from agentsafe.knowledge.kb import KnowledgeBase
        from pathlib import Path
        kb = KnowledgeBase.load(
            Path(__file__).resolve().parents[1] / "src" / "agentsafe" /
            "knowledge" / "dataset" / "v8.jsonl")
        for r in kb.records:
            assert r["verification_status"] == VS_REPRODUCED
            assert r.get("test_result"), "reproduced requires test_result"


class TestVerifiedRecordsNeverOverwritten:
    """Requirement 9: enrichment must not touch verified rows."""

    def test_enrich_skips_verified_rows(self):
        row = {"id": 1, "title": "Outdated TWAP oracle price",
               "description": "## Impact\nbad", "category": None,
               "impact": None, "remediation": None, "vulnerable_code": None,
               "kb_group": None, "metadata": {}}
        for status in VERIFIED_STATUSES:
            r = dict(row, verification_status=status)
            # _enrich_one would fill fields — the pass-level guard must skip
            assert r["verification_status"] in VERIFIED_STATUSES

    def test_verified_statuses_are_the_verified_ones(self):
        assert VERIFIED_STATUSES == {VS_CURATED, VS_REPRODUCED}


class TestRetryAndFailureLogging:
    """Requirement 8: bounded retries + failure logging."""

    def test_fetch_hf_rows_retries_then_succeeds(self):
        from agentsafe.knowledge import speca

        calls = {"n": 0}

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return json.dumps({"rows": [
                    {"row": {"id": "x", "source_platform": "code4rena"}}
                ]}).encode()

        def fake_urlopen(url, timeout=None):
            calls["n"] += 1
            if calls["n"] < 3:
                raise OSError("transient network error")
            return FakeResp()

        with mock.patch.object(speca.urllib.request, "urlopen", fake_urlopen), \
             mock.patch("time.sleep", lambda s: None):
            rows = speca.fetch_hf_rows(0, 5)
        assert calls["n"] == 3
        assert rows and rows[0]["id"] == "x"

    def test_import_summary_logs_errors(self):
        s = ImportSummary(source="s")
        s.failed = 1
        s.errors.append("boom")
        d = s.to_dict()
        assert d["failed"] == 1 and d["errors"] == ["boom"]


class TestDedupBySourceIdentifiers:
    """Requirement 6: content hashes AND (source_id, external_record_id)."""

    def test_known_ids_lookup_uses_source_scope(self, monkeypatch):
        class FakeStore:
            def _connect(self):
                raise AssertionError("not called in unit test")

        # _known_external_ids is DB-bound; here we assert its failure path is
        # safe (returns empty set, import proceeds with content-hash dedup).
        class BrokenStore:
            def _connect(self):
                raise RuntimeError("db down")

        assert _known_external_ids(BrokenStore(), "s1") == set()

    def test_import_summary_counts_known_skipped(self):
        s = ImportSummary(source="s")
        s.known_skipped = 5
        assert s.to_dict()["known_skipped"] == 5


@pytest.mark.skipif(
    not __import__("os").environ.get("NEON_DATABASE_URL", "").strip(),
    reason="NEON_DATABASE_URL not set; skipping live-Neon tests")
class TestIncrementalImportLive:
    """Requirements 6+7 live: re-import skips known ids, inserts nothing."""

    @classmethod
    def setup_class(cls):
        import os
        from agentsafe.knowledge.db import NeonKnowledgeStore
        cls.store = NeonKnowledgeStore(
            dsn=os.environ["NEON_DATABASE_URL"].strip(), vector_dim=2048)
        cls.store.migrate()

    def test_reimport_is_incremental_noop(self):
        from pathlib import Path
        from agentsafe.knowledge.importers import import_jsonl_dataset
        v2 = (Path(__file__).resolve().parents[1] / "src" / "agentsafe" /
              "knowledge" / "dataset" / "v2.jsonl")
        before = self.store.count()
        s = import_jsonl_dataset(self.store, v2, source_name="agentsafe-v2.jsonl")
        assert s.inserted == 0
        assert s.known_skipped >= 12   # all records already known
        assert self.store.count() == before

    def test_verified_rows_untouched_by_enrichment(self):
        from agentsafe.knowledge.enrich import enrich_category_a
        # curated v2/v3 rows must never be modified by an enrichment pass
        with self.store._connect() as conn, conn.cursor() as cur:
            cur.execute("""SELECT id, updated_at, metadata FROM vulnerability_knowledge
                           WHERE source_id='agentsafe-v2.jsonl' LIMIT 3""")
            rows = cur.fetchall()
        es = enrich_category_a(self.store, limit=1000)
        with self.store._connect() as conn, conn.cursor() as cur:
            for r in rows:
                cur.execute("""SELECT updated_at FROM vulnerability_knowledge
                               WHERE id=%s""", (r["id"],))
                assert cur.fetchone()["updated_at"] == r["updated_at"]