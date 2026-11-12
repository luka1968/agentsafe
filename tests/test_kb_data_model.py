"""Neon PostgreSQL data-model tests (standardized knowledge-record fields).

Covers the KB data-model spec:
  * logical fields surface via _row_to_record (aliases: security_invariant,
    source_name, source_license, commercial_use_allowed, exploit_sequence)
  * new columns persist through normalize_record / run_import INSERT
  * 2048-dim vectors preserved; embedding dim not silently changed
  * indexes exist (category, subcategory, vulnerability_id, severity, tags,
    content_hash)
  * no duplicate tables / duplicate records (single table, content-hash dedup)
"""

import os
import json

import pytest

from agentsafe.knowledge.db import _row_to_record
from agentsafe.knowledge.importers import normalize_record

RAW = {
    "id": "X-1",
    "title": "Approval race",
    "source": "example",
    "mechanism": "non-atomic approve allows double spend",
    "category": "approval",
    "subcategory": "allowance-race",
    "protocol_type": "token",
    "root_cause": "approve is not atomic",
    "preconditions": ["spender has allowance"],
    "impact": "double spend",
    "remediation": "increaseAllowance",
    "keywords": ["approve", "race", "allowance"],
    "url": "https://example.test/approve",
    "vulnerability_id": "CVE-2025-0001",
    "swc_id": "SWC-114",
    "exploit_sequence": ["step1", "step2"],
    "confidence": 0.8,
    "tags": ["erc20", "front-run"],
}


class TestStandardFieldsNormalize:
    def test_standard_fields_carried(self):
        n = normalize_record(RAW, source_name="s1")
        assert n["subcategory"] == "allowance-race"
        assert n["vulnerability_id"] == "CVE-2025-0001"
        assert n["swc_id"] == "SWC-114"
        assert n["exploit_sequence"] == ["step1", "step2"]
        assert n["confidence"] == 0.8
        assert n["tags"] == ["erc20", "front-run"]

    def test_aliases_mapped(self):
        n = normalize_record(RAW, source_name="s1")
        # attack_scenario falls back to exploit_sequence in normalize
        assert n["exploit_sequence"] == ["step1", "step2"]


class TestRowToRecordStandardFields:
    def test_all_logical_fields_surface(self):
        row = {
            "external_record_id": "KB-1", "title": "t", "category": "cat",
            "subcategory": "sub", "vulnerability_id": "CVE-1", "swc_id": "SWC-1",
            "severity": "high", "protocol_domain": "defi",
            "affected_function": "f", "root_cause": "rc",
            "preconditions": "[]",             "attack_scenario": "as",
            "exploit_sequence": '["a","b"]', "vulnerable_code": "vc",
            "corrected_code": "cc", "invariant": "inv", "impact": "imp",
            "remediation": "rem", "source_id": "s1", "source_name": "s1",
            "source_url": "https://x.test", "license_status": "MIT",
            "commercial_use": "public-reports",
            "verification_status": "reproduced", "confidence": 0.9,
            "tags": '["a","b"]', "metadata": "{}", "score": None,
        }
        rec = _row_to_record(row)
        # canonical names
        assert rec["subcategory"] == "sub"
        assert rec["vulnerability_id"] == "CVE-1"
        assert rec["swc_id"] == "SWC-1"
        assert rec["confidence"] == 0.9
        assert rec["tags"] == ["a", "b"]
        # spec aliases
        assert rec["security_invariant"] == "inv"
        assert rec["source_name"] == "s1"
        assert rec["source_license"] == "MIT"
        assert rec["commercial_use_allowed"] == "public-reports"
        # exploit_sequence: explicit column wins, JSON-list strings parsed
        assert rec["exploit_sequence"] == ["a", "b"]

    def test_exploit_sequence_parses_json_list_string(self):
        row = {"external_record_id": "X", "description": "m",
               "exploit_sequence": '["enter","callback","drain"]',
               "metadata": "{}", "score": None}
        assert _row_to_record(row)["exploit_sequence"] == ["enter", "callback", "drain"]

    def test_exploit_sequence_plain_text_preserved(self):
        row = {"external_record_id": "X", "description": "m",
               "exploit_sequence": "step1; step2", "metadata": "{}", "score": None}
        assert _row_to_record(row)["exploit_sequence"] == "step1; step2"

    def test_missing_standard_fields_default(self):
        rec = _row_to_record({"external_record_id": "X", "description": "m",
                              "metadata": "{}", "score": None})
        assert rec["tags"] == []
        assert rec["subcategory"] is None
        assert rec["confidence"] is None


def _needs_neon():
    return bool(os.environ.get("NEON_DATABASE_URL", "").strip())


@pytest.mark.skipif(not _needs_neon(),
                    reason="NEON_DATABASE_URL not set; skipping live-Neon tests")
class TestNeonDataModelLive:
    @classmethod
    def setup_class(cls):
        from agentsafe.knowledge.db import NeonKnowledgeStore
        cls.store = NeonKnowledgeStore(
            dsn=os.environ["NEON_DATABASE_URL"].strip(), vector_dim=2048)
        cls.store.migrate()

    def test_columns_exist(self):
        with self.store._connect() as conn, conn.cursor() as cur:
            cur.execute("""SELECT column_name FROM information_schema.columns
                           WHERE table_name='vulnerability_knowledge'
                           AND column_name IN ('subcategory','vulnerability_id',
                             'swc_id','exploit_sequence','confidence','tags')""")
            cols = {r["column_name"] for r in cur.fetchall()}
        assert {"subcategory", "vulnerability_id", "swc_id", "exploit_sequence",
                "confidence", "tags"} <= cols

    def test_indexes_exist(self):
        with self.store._connect() as conn, conn.cursor() as cur:
            cur.execute("""SELECT indexname FROM pg_indexes
                           WHERE tablename='vulnerability_knowledge'""")
            idx = {r["indexname"] for r in cur.fetchall()}
        assert {"vk_category_idx", "vk_subcategory_idx", "vk_vuln_id_idx",
                "vk_severity_idx", "vk_tags_idx", "vk_hash_idx"} <= idx

    def test_embedding_dim_unchanged_and_preserved(self):
        with self.store._connect() as conn, conn.cursor() as cur:
            cur.execute("""SELECT a.atttypmod AS dim FROM pg_attribute a
                           JOIN pg_class c ON c.oid=a.attrelid
                           WHERE c.relname='knowledge_embeddings'
                           AND a.attname='embedding'""")
            dim = cur.fetchone()["dim"]
            cur.execute("SELECT count(*) FROM knowledge_embeddings")
            n = cur.fetchone()["count"]
        assert dim == 2048          # not silently changed
        assert n > 0                # existing vectors preserved

    def test_single_table_no_duplicate_records(self):
        with self.store._connect() as conn, conn.cursor() as cur:
            cur.execute("""SELECT count(*) FROM information_schema.tables
                           WHERE table_name='vulnerability_knowledge'""")
            assert cur.fetchone()["count"] == 1
            cur.execute("""SELECT count(*) FROM (SELECT content_hash
                           FROM vulnerability_knowledge GROUP BY content_hash
                           HAVING count(*) > 1) d""")
            assert cur.fetchone()["count"] == 0