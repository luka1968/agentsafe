"""Category A (real-world vulnerability cases) tests.

Covers:
  1. KB six-group organization registry (A implemented, B-F reserved).
  2. Deterministic classification (`infer_category`): strong-signal mapping,
     honest None on no signal.
  3. Markdown section extraction for both verified report formats
     (Code4rena `## Impact` / `## Recommended Mitigation Steps` /
     `## Proof of Concept`; Sherlock `## Impact` / `## Recommendation` /
     `## Code Snippet`).
  4. Non-destructive enrichment semantics (`_enrich_one`): fills NULLs only,
     never proposes overwriting existing values.
  5. SPECA platform adapter: Category A platforms, per-platform source names,
     Category A organization fields on normalized rows.
  6. Live-Neon (gated): enriched rows carry kb_group/verification/license and
     retrieval surfaces categorized real-world records.
"""

import pytest

from agentsafe.knowledge.enrich import (
    KB_GROUPS,
    VS_HEURISTIC,
    VS_SOURCE,
    _enrich_one,
    extract_markdown_sections,
    infer_category,
)
from agentsafe.knowledge.speca import (
    CATEGORY_A_PLATFORMS,
    normalize_speca_row,
)

C4_DESC = (
    "# Handle\n\nsomeone\n\n# Vulnerability Details\n\nThe pool relies on "
    "an outdated twap oracle price.\n\n## Impact\n\nBorrowing can be "
    "enabled at a manipulated price, leading to bad debt.\n\n"
    "## Proof of Concept\n\n```solidity\nprice = oracle.latest();\n```\n\n"
    "## Recommended Mitigation Steps\n\nCheck updatedAt against a "
    "freshness window before use."
)
SHERLOCK_DESC = (
    "## Summary\n\nPool relies on a twap oracle which can be outdated.\n\n"
    "## Vulnerability Detail\n\nThe metapool is not updated.\n\n"
    "## Impact\n\nMinting/burning enabled at an outdated static price.\n\n"
    "## Code Snippet\n\n```solidity\nuint rate = twap.consult();\n```\n\n"
    "## Tool used\n\nManual Review\n\n## Recommendation\n\nValidate the "
    "round freshness and deviation before use."
)


class TestKBGroups:
    def test_six_groups_registered(self):
        assert set(KB_GROUPS) == {"A", "B", "C", "D", "E", "F"}

    def test_group_a_is_real_world_cases(self):
        assert KB_GROUPS["A"] == "real-world-cases"


class TestInferCategory:
    def test_oracle_signal(self):
        assert infer_category("Outdated TWAP oracle price",
                              "minting enabled at outdated price") == "oracle"

    def test_reentrancy_signal(self):
        assert infer_category("Reentrancy in withdraw",
                              "external call before state update") == "reentrancy"

    def test_accounting_signal(self):
        assert infer_category("Wrong balance accounting",
                              "double count of user shares") == "accounting"

    def test_no_signal_returns_none(self):
        assert infer_category("QA report", "n/a this is a gas note") is None

    def test_title_preferred_order_deterministic(self):
        # reentrancy precedes accounting in vocabulary order
        cat = infer_category("Reentrancy", "balance accounting bug")
        assert cat == "reentrancy"


class TestExtractMarkdownSections:
    def test_code4rena_format(self):
        out = extract_markdown_sections(C4_DESC)
        assert out.impact and "manipulated price" in out.impact
        assert out.remediation and "freshness window" in out.remediation
        assert out.vulnerable_code and "oracle.latest()" in out.vulnerable_code
        assert set(out.derived) == {"impact", "remediation", "vulnerable_code"}

    def test_sherlock_format(self):
        out = extract_markdown_sections(SHERLOCK_DESC)
        assert out.impact and "outdated static price" in out.impact
        assert out.remediation and "round freshness" in out.remediation
        assert out.vulnerable_code and "twap.consult()" in out.vulnerable_code

    def test_no_sections_is_empty(self):
        out = extract_markdown_sections("just a plain note")
        assert out.impact is None and out.remediation is None
        assert out.vulnerable_code is None and out.derived == []

    def test_extraction_is_verbatim_slices(self):
        out = extract_markdown_sections(C4_DESC)
        assert out.impact in C4_DESC  # never paraphrased


class TestEnrichOneNonDestructive:
    def test_fills_only_null_fields(self):
        row = {
            "id": 1, "title": "Outdated TWAP oracle price",
            "description": SHERLOCK_DESC,
            "category": None, "impact": None, "remediation": "EXISTING",
            "vulnerable_code": None, "kb_group": None,
            "verification_status": VS_SOURCE, "metadata": {},
        }
        sets = _enrich_one(row)
        assert sets["category"] == "oracle"
        assert sets["impact"]
        assert sets["vulnerable_code"]
        assert "remediation" not in sets          # existing value untouched
        assert sets["kb_group"] == "A"
        assert sets["verification_status"] == VS_HEURISTIC
        import json
        md = json.loads(sets["metadata"])
        assert "remediation" not in md["enrichment"]["derived_fields"]

    def test_returns_none_when_nothing_to_add(self):
        row = {
            "id": 2, "title": "t", "description": "plain note",
            "category": "oracle", "impact": "i", "remediation": "r",
            "vulnerable_code": "c", "kb_group": "A",
            "verification_status": VS_HEURISTIC, "metadata": {},
        }
        assert _enrich_one(row) is None

    def test_provenance_recorded(self):
        row = {
            "id": 3, "title": "Reentrancy in withdraw",
            "description": C4_DESC, "category": None, "impact": None,
            "remediation": None, "vulnerable_code": None, "kb_group": None,
            "verification_status": None, "metadata": {},
        }
        import json
        sets = _enrich_one(row)
        md = json.loads(sets["metadata"])
        assert md["enrichment"]["derived_fields"]
        assert md["enrichment"]["method"].startswith("deterministic")


class TestSpecaCategoryA:
    def test_platforms_verified(self):
        assert CATEGORY_A_PLATFORMS == ("code4rena", "sherlock", "codehawks")

    def test_normalize_carries_group_a_fields(self):
        raw = {
            "id": "sherlock:x:M-1", "title": "Outdated TWAP oracle",
            "description": "pool relies on outdated price",
            "severity": "Medium", "domain": "defi", "source_url": "",
            "source_platform": "sherlock", "contest": "x", "issue_id": "M-1",
        }
        n = normalize_speca_row(raw, platform="sherlock")
        assert n["kb_group"] == "A"
        assert n["verification_status"] == VS_SOURCE
        assert n["license_status"] and "Sherlock" in n["license_status"]
        assert n["commercial_use"] == "public-reports"

    def test_unknown_platform_rejected(self):
        import pytest as _pt
        from agentsafe.knowledge.speca import import_speca

        class _S:
            def _connect(self):
                raise AssertionError("no db in unit test")

        with _pt.raises(ValueError):
            import_speca(_S(), platform="not-a-platform")


def _needs_neon():
    import os
    return bool(os.environ.get("NEON_DATABASE_URL", "").strip())


@pytest.mark.skipif(not _needs_neon(),
                    reason="NEON_DATABASE_URL not set; skipping live-Neon tests")
class TestCategoryALive:
    @classmethod
    def setup_class(cls):
        import os

        from agentsafe.knowledge.db import NeonKnowledgeStore

        cls.store = NeonKnowledgeStore(dsn=os.environ["NEON_DATABASE_URL"].strip(),
                                       vector_dim=2048)

    def test_group_a_rows_have_organization_columns(self):
        with self.store._connect() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT count(*) FILTER (WHERE kb_group='A') grp,
                       count(*) FILTER (WHERE verification_status IS NOT NULL) vs,
                       count(*) total
                FROM vulnerability_knowledge
                WHERE source_id LIKE 'speca-%'
            """)
            r = cur.fetchone()
        assert r["total"] > 0
        assert r["grp"] == r["total"]
        assert r["vs"] == r["total"]

    def test_categories_were_assigned(self):
        with self.store._connect() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT count(*) n FROM vulnerability_knowledge
                WHERE source_id LIKE 'speca-%' AND category IS NOT NULL
            """)
            n = cur.fetchone()["n"]
        assert n > 100

    def test_retrieval_surfaces_categorized_real_world_records(self):
        hits = self.store.search(
            "oracle price stale twap manipulation", focus="defi_logic", limit=3)
        assert hits
        assert any(h.get("category") == "oracle" for h in hits)
        assert any(h.get("verification_status") for h in hits)