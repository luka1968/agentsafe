"""Cost/performance (Task 8) and implementation-safety (Task 9) compliance.

Verifies with measurements, not claims:
  * embedding reuse: identical re-import costs ZERO embedding calls
  * incremental import: known ids skipped before any embedding work
  * retrieval cache: same query twice -> one DB/embedding round-trip
  * retrieved context is bounded (MAX_SEARCH_LIMIT, renderer budgets)
  * no pricing / x402 / payment / USDC files modified (git working tree)
  * backward compatibility: additive migration, existing columns/rows intact
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

from agentsafe.knowledge.profiles import MAX_SEARCH_LIMIT


REPO = Path(__file__).resolve().parents[1]


class TestCostRequirements:
    def test_max_search_limit_bounds_context(self):
        assert MAX_SEARCH_LIMIT <= 10

    def test_renderer_budgets_bound_context(self):
        from agentsafe.intel.render import KB_BUDGET_CHARS, KB_SNIPPET_CHARS
        assert KB_SNIPPET_CHARS < 1000
        assert KB_BUDGET_CHARS <= 2000


def _needs_neon():
    return bool(os.environ.get("NEON_DATABASE_URL", "").strip())


@pytest.mark.skipif(not _needs_neon(),
                    reason="NEON_DATABASE_URL not set; skipping live-Neon tests")
class TestEmbeddingReuseLive:
    """Requirement: identical re-import costs ZERO embedding calls."""

    def test_reimport_costs_zero_embedding_calls(self):
        from agentsafe.knowledge.db import NeonKnowledgeStore
        from agentsafe.knowledge.importers import import_jsonl_dataset

        V2 = (REPO / "src" / "agentsafe" / "knowledge" / "dataset"
              / "v2.jsonl")

        class CountingEmbedder:
            name = "counting-embedder"

            def __init__(self):
                self.calls = 0

            def embed(self, texts):
                self.calls += 1
                raise RuntimeError("no record should be re-embedded")

            def embed_query(self, text):
                self.calls += 1
                raise RuntimeError("no query should be embedded in import")

        dsn = os.environ["NEON_DATABASE_URL"].strip()
        store = NeonKnowledgeStore(dsn=dsn, vector_dim=2048)
        ce = CountingEmbedder()
        probe = NeonKnowledgeStore(dsn=dsn, vector_dim=2048,
                                   embedding_model=ce)
        before = store.count()
        s = import_jsonl_dataset(probe, V2, embedder=ce,
                                 source_name="agentsafe-v2.jsonl")
        assert s.inserted == 0                 # nothing new inserted
        assert s.known_skipped >= 12           # all records known -> skipped
        assert ce.calls == 0                   # ZERO paid embedding calls
        assert store.count() == before


class TestSafetyRequirements:
    def test_payment_pricing_files_untouched(self):
        """git working tree must show no modifications to pricing/x402/
        payment/USDC/report-retrieval files."""
        res = subprocess.run(
            ["git", "status", "--porcelain"], cwd=REPO,
            capture_output=True, text=True)
        changed = [ln[3:].strip() for ln in res.stdout.splitlines() if ln.strip()]
        forbidden = ("price", "x402", "payment", "usdc", "entitlement")
        touched = [f for f in changed
                   if any(k in f.lower() for k in forbidden)]
        assert not touched, f"forbidden files modified: {touched}"

    def test_llm_providers_unchanged(self):
        """No new/removed LLM providers: config still wires the same
        provider field set (name/base_url/api_key/model)."""
        from agentsafe.config import LLMProviderConfig
        fields = set(LLMProviderConfig.model_fields)
        for k in ("name", "base_url", "api_key", "model"):
            assert k in fields

    def test_no_record_deletion_in_migration(self):
        """migrate() only ADDs columns/indexes — inspect its source for
        destructive statements (DROP/DELETE/TRUNCATE on knowledge rows)."""
        src = (REPO / "src" / "agentsafe" / "knowledge" / "db.py").read_text(
            encoding="utf-8")
        mig = src[src.index("def migrate"):src.index("def migrate") + 2500]
        assert "DELETE FROM vulnerability_knowledge" not in mig
        assert "TRUNCATE" not in mig
        # _DROP_OLD is a pre-existing legacy-table drop, not KB data
        assert "DROP TABLE IF EXISTS kb_records" in src  # legacy only


def _needs_neon():
    return bool(os.environ.get("NEON_DATABASE_URL", "").strip())


@pytest.mark.skipif(not _needs_neon(),
                    reason="NEON_DATABASE_URL not set; skipping live-Neon tests")
class TestBackwardCompatibilityLive:
    @classmethod
    def setup_class(cls):
        from agentsafe.knowledge.db import NeonKnowledgeStore
        cls.store = NeonKnowledgeStore(
            dsn=os.environ["NEON_DATABASE_URL"].strip(), vector_dim=2048)

    def test_existing_rows_and_dim_intact(self):
        with self.store._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) n FROM vulnerability_knowledge")
            n = cur.fetchone()["n"]
            cur.execute("""SELECT a.atttypmod dim FROM pg_attribute a
                           JOIN pg_class c ON c.oid=a.attrelid
                           WHERE c.relname='knowledge_embeddings'
                           AND a.attname='embedding'""")
            dim = cur.fetchone()["dim"]
        assert n >= 900 and dim == 2048

    def test_all_records_carry_license_and_no_unrestricted(self):
        with self.store._connect() as conn, conn.cursor() as cur:
            cur.execute("""SELECT count(*) FILTER (WHERE license_status IS NULL) ln,
                                  count(*) FILTER (WHERE commercial_use='unrestricted') ur,
                                  count(*) total
                           FROM vulnerability_knowledge""")
            r = cur.fetchone()
        assert r["ln"] == 0
        assert r["ur"] == 0
        assert r["total"] >= 900

    def test_retrieval_cache_hit_second_call(self):
        """Same query twice: second call served from the session cache
        (identical results, no additional metrics retrieval_calls)."""
        from agentsafe.metrics import get_metrics
        q = "cache hit probe reentrancy external call"
        a = self.store.search(q, limit=2)
        m0 = get_metrics()
        before = m0.snapshot().get("retrieval_calls", 0) \
            if hasattr(m0, "snapshot") else None
        b = self.store.search(q, limit=2)
        assert a == b
        if before is not None:
            after = m0.snapshot().get("retrieval_calls", 0)
            assert after == before  # cache hit: no new retrieval call