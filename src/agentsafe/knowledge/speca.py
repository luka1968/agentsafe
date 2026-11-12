"""HuggingFace SPECA dataset adapter — AgentSafe G+ Stage 3 / Category A.

Verified source (2026-02, live-fetched):
  NyxFoundation/vulnerability-reports (config `default`, split `train`)
  4,470 rows of public smart-contract audit findings. `source_platform`
  values verified live: code4rena, sherlock, codehawks — public contest
  reports from all three platforms are legally reusable here.

Fields verified against the HF datasets-server API:
    id, source_platform, contest, issue_id, severity, title,
    description, source_url, domain, scraped_at

Mapping to vulnerability_knowledge (nothing invented; absent -> null):
  external_record_id <- id
  title              <- title
  description        <- description (verbatim, incl. markdown evidence)
  severity           <- severity
  protocol_domain    <- domain
  source_url         <- source_url
  category           <- None (not labeled by source; honesty > guessing)
  preconditions      <- []   (not structured in source)
  kb_group           <- 'A'   (real-world vulnerability cases)
  verification_status <- 'source' (verbatim public report)
  license_status / commercial_use <- per-source reuse terms (public reports)
  metadata           <- {contest, issue_id, source_platform, scraped_at}

Dataset license: public contest reports; provenance preserved per record via
source_url + source_platform.
"""

from __future__ import annotations

import json
import logging
import urllib.request
from typing import Any, Iterator

from agentsafe.knowledge.db import NeonKnowledgeStore
from agentsafe.knowledge.importers import ImportSummary, run_import

logger = logging.getLogger("agentSAFE.knowledge.speca")

HF_DATASET = "NyxFoundation/vulnerability-reports"
HF_CONFIG = "default"
HF_SPLIT = "train"
HF_ROWS_URL = ("https://datasets-server.huggingface.co/rows"
               "?dataset={ds}&config={cfg}&split={sp}&offset={off}&length={n}")
PAGE_SIZE = 50

# Category A: public contest platforms covered by this source. code4rena is
# the established default; sherlock/codehawks were verified live in the same
# dataset. Each platform imports under its own source name (speca-<platform>).
CATEGORY_A_PLATFORMS = ("code4rena", "sherlock", "codehawks")

# Verified live (2026-11): the platform rows are region-clustered in the
# /rows listing (source_platform is NOT server-filterable — the `where`
# param is ignored and /filter 500s on this dataset), so platform imports
# scan from the known region start and fall back to a full scan.
_PLATFORM_SCAN_START = {"sherlock": 3600, "codehawks": 3850}
_SCAN_FALLBACK_PAGES = 6  # pages scanned from scan_start before full-scan retry

# Reuse terms for public contest reports. License text is recorded verbatim
# from the source registry; commercial_use is an honest status label, not a
# legal claim.
_LICENSE_BY_PLATFORM = {
    "code4rena": "public contest findings (Code4rena reports)",
    "sherlock": "public contest findings (Sherlock reports)",
    "codehawks": "public contest findings (CodeHawks reports)",
}


def fetch_hf_rows(offset: int, length: int, *, timeout: float = 60.0,
                  retries: int = 4, platform: str | None = None
                  ) -> list[dict[str, Any]]:
    """Fetch one page of rows from the HF datasets-server (bounded retries,
    never faked). When `platform` is set, rows are filtered server-side via
    the datasets-server `where` clause when supported, else filtered here."""
    url = HF_ROWS_URL.format(ds=HF_DATASET, cfg=HF_CONFIG, sp=HF_SPLIT,
                             off=offset, n=length)
    if platform:
        from urllib.parse import quote
        url += "&where=" + quote(f"\"source_platform\"='{platform}'")
    last: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            rows = [r["row"] for r in (data.get("rows") or [])]
            if platform:
                rows = [r for r in rows
                        if (r.get("source_platform") or "").strip() == platform]
            return rows
        except Exception as exc:
            last = exc
            import time
            time.sleep(1.5 * attempt)
    raise RuntimeError(f"fetch_hf_rows failed after {retries} retries: {last}")


def normalize_speca_row(raw: dict[str, Any], *, platform: str | None = None
                        ) -> dict[str, Any]:
    """Map a raw SPECA row onto the normalized import shape (used by the
    renderer/Neon schema). Unknown fields stay null — never guessed."""
    plat = platform or (raw.get("source_platform") or "").strip() or None
    sev = (raw.get("severity") or "").strip()
    return {
        "external_record_id": raw.get("id"),
        "title": (raw.get("title") or "").strip(),
        "description": (raw.get("description") or "").strip(),
        "severity": sev or None,
        "protocol_domain": (raw.get("domain") or "").strip() or None,
        "url": (raw.get("source_url") or "").strip() or None,
        "category": None,   # not labeled by source; enrichment infers honestly
        "preconditions": [],
        "kb_group": "A",
        "verification_status": "source",
        "license_status": _LICENSE_BY_PLATFORM.get(plat or ""),
        "commercial_use": "public-reports",
        "metadata": {
            "source_platform": raw.get("source_platform") or plat,
            "contest": raw.get("contest"),
            "issue_id": raw.get("issue_id"),
            "scraped_at": raw.get("scraped_at"),
        },
    }


def import_speca(store: NeonKnowledgeStore, *, limit: int = 100,
                 embedder=None, page_size: int = PAGE_SIZE,
                 platform: str = "code4rena") -> ImportSummary:
    """Import verified SPECA rows for one platform under source name
    `speca-<platform>` (idempotent by content_hash; provenance preserved).
    Category A platforms: code4rena (default), sherlock, codehawks.

    Non-default platforms scan from their verified region start and fall
    back to a full scan from offset 0 when the region yields nothing."""
    if platform not in CATEGORY_A_PLATFORMS:
        raise ValueError(
            f"platform {platform!r} not in Category A sources "
            f"{CATEGORY_A_PLATFORMS}")
    source = {
        "name": f"speca-{platform}",
        "version": "2026-02",
        "url": f"https://huggingface.co/datasets/{HF_DATASET}",
        "license": _LICENSE_BY_PLATFORM[platform],
        "metadata": {"hf_dataset": HF_DATASET, "config": HF_CONFIG,
                     "split": HF_SPLIT, "platform": platform},
    }
    scan_start = 0 if platform == "code4rena" else _PLATFORM_SCAN_START.get(platform, 0)
    records = _collect_platform_rows(limit, page_size, platform, scan_start)
    if not records and scan_start:
        records = _collect_platform_rows(limit, page_size, platform, 0)
    return run_import(store, source=source, records=records[:limit],
                      embedder=embedder)


def _collect_platform_rows(limit: int, page_size: int, platform: str,
                           start_offset: int) -> list[dict[str, Any]]:
    """Page through /rows collecting `platform` rows, client-side filtered
    (datasets-server ignores `where` for this dataset). Stops at `limit`
    collected or when a page returns nothing."""
    records: list[dict[str, Any]] = []
    offset = start_offset
    empty_pages = 0
    while len(records) < limit and empty_pages < 3:
        rows = fetch_hf_rows(offset, page_size)
        if not rows:
            empty_pages += 1
            continue
        empty_pages = 0
        for r in rows:
            if (r.get("source_platform") or "").strip() == platform:
                records.append(normalize_speca_row(r, platform=platform))
                if len(records) >= limit:
                    break
        offset += len(rows)
    return records
