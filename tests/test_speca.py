"""Tests for the SPECA (HuggingFace vulnerability-reports) adapter.

Covers: field normalization/mapping invariants, pagination limits, and
(offline-friendly) no-network import-path contract checks. Live Neon writes
are exercised via the existing DSN-gated knowledge tests; here we keep the
unit surface deterministic without network dependency.
"""

from __future__ import annotations

import pytest

from agentsafe.knowledge.speca import (
    HF_CONFIG,
    HF_DATASET,
    HF_SPLIT,
    normalize_speca_row,
)


# ---------------------------------------------------------------------------
# field mapping — invariant checks on realistic raw rows (structure matches
# the live HF row we verified: code4rena platform, defi domain, etc.)
# ---------------------------------------------------------------------------
def _raw_row(**overrides) -> dict:
    row = {
        "id": "code4rena:2022-01-notional-findings:200",
        "source_platform": "code4rena",
        "contest": "2022-01-notional-findings",
        "issue_id": "#200",
        "severity": "Medium",
        "title": "latestAnswer doesn't check if the value is up to date",
        "description": "# Handle\n\npauliax\n\n# Vulnerability details\n\n## Impact ...",
        "source_url": "https://github.com/code-423n4/2022-01-notional-findings/issues/200",
        "domain": "defi",
        "scraped_at": "2026-05-08T04:37:49Z",
    }
    row.update(overrides)
    return row


class TestNormalizeSpecaRow:
    def test_maps_core_fields(self):
        n = normalize_speca_row(_raw_row())
        assert n["external_record_id"] == "code4rena:2022-01-notional-findings:200"
        assert n["title"].startswith("latestAnswer")
        assert n["description"].startswith("# Handle")
        assert n["severity"] == "Medium"
        assert n["protocol_domain"] == "defi"
        assert n["url"] == ("https://github.com/code-423n4/"
                            "2022-01-notional-findings/issues/200")

    def test_metadata_preserves_provenance(self):
        n = normalize_speca_row(_raw_row())
        assert n["metadata"]["source_platform"] == "code4rena"
        assert n["metadata"]["contest"] == "2022-01-notional-findings"
        assert n["metadata"]["issue_id"] == "#200"
        assert n["metadata"]["scraped_at"] == "2026-05-08T04:37:49Z"

    def test_never_invents_category_or_preconditions(self):
        # SPECA rows are not category-labeled; category must stay None,
        # preconditions must stay empty — honesty over guessing.
        n = normalize_speca_row(_raw_row())
        assert n["category"] is None
        assert n["preconditions"] == []

    def test_missing_optional_fields_become_none(self):
        n = normalize_speca_row(_raw_row(severity="", domain=None,
                                          source_url="   "))
        assert n["severity"] is None
        assert n["protocol_domain"] is None
        assert n["url"] is None

    def test_whitespace_stripped(self):
        n = normalize_speca_row(_raw_row(title="  trimmed title  ",
                                         severity="  High "))
        assert n["title"] == "trimmed title"
        assert n["severity"] == "High"

    def test_external_id_never_empty(self):
        for rid in ("a:1", "code4rena:x:y", "  spaced:id  "):
            n = normalize_speca_row(_raw_row(id=rid))
            assert n["external_record_id"]


class TestSourceContract:
    def test_constant_identity(self):
        # The adapter must point at the verified HF dataset, not a guess.
        assert HF_DATASET == "NyxFoundation/vulnerability-reports"
        assert HF_CONFIG == "default"
        assert HF_SPLIT == "train"

    def test_normalized_row_is_import_ready(self):
        # run_import expects these keys (see importers.normalize_record).
        n = normalize_speca_row(_raw_row())
        for key in ("external_record_id", "title", "description", "severity",
                    "protocol_domain", "url", "category", "preconditions",
                    "metadata"):
            assert key in n


# ---------------------------------------------------------------------------
# pagination precision — no overshoot beyond limit (the bug we fixed: the
# loop previously pulled whole HF pages even past the requested limit)
# ---------------------------------------------------------------------------
class TestPagination:
    def test_precise_limit_with_full_pages(self, monkeypatch):
        import agentsafe.knowledge.speca as speca_mod

        captured: list[int] = []
        page = [normalize_speca_row(_raw_row(id=f"c4:x:{i}")) for i in range(50)]

        def fake_fetch(offset, length, **kw):
            captured.append((offset, length))
            return page[:length]

        monkeypatch.setattr(speca_mod, "fetch_hf_rows", fake_fetch)
        monkeypatch.setattr(speca_mod, "run_import",
                            lambda store, source, records, embedder: records)
        got = speca_mod.import_speca(None, limit=100, embedder=None)
        assert len(got) == 100
        assert len(captured) == 2
        assert captured == [(0, 50), (50, 50)]

    def test_limit_smaller_than_page(self, monkeypatch):
        import agentsafe.knowledge.speca as speca_mod

        page = [normalize_speca_row(_raw_row(id=f"c4:x:{i}")) for i in range(50)]

        def fake_fetch(offset, length, **kw):
            return page[:length]

        monkeypatch.setattr(speca_mod, "fetch_hf_rows", fake_fetch)
        monkeypatch.setattr(speca_mod, "run_import",
                            lambda store, source, records, embedder: records)
        got = speca_mod.import_speca(None, limit=7, embedder=None)
        assert len(got) == 7

    def test_stops_when_fetcher_exhausts(self, monkeypatch):
        import agentsafe.knowledge.speca as speca_mod

        def fake_fetch(offset, length, **kw):
            return []  # no more rows upstream

        monkeypatch.setattr(speca_mod, "fetch_hf_rows", fake_fetch)
        monkeypatch.setattr(speca_mod, "run_import",
                            lambda store, source, records, embedder: records)
        got = speca_mod.import_speca(None, limit=100, embedder=None)
        assert got == []
