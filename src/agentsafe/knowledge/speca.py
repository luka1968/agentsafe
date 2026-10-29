"""HuggingFace SPECA dataset adapter — AgentSafe G+ Stage 3.

Verified source (2026-02, live-fetched):
  NyxFoundation/vulnerability-reports (config `default`, split `train`)
  4,470 rows of public smart-contract audit findings scraped from
  Code4rena (source_platform=code4rena). Fields verified against the HF
  datasets-server API:

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
  metadata           <- {contest, issue_id, source_platform, scraped_at}

Dataset license: public contest reports (Code4rena findings are public);
provenance preserved per record via source_url + source_platform.
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


def fetch_hf_rows(offset: int, length: int, *, timeout: float = 60.0,
                  retries: int = 4) -> list[dict[str, Any]]:
    """Fetch one page of rows from the HF datasets-server (bounded retries,
    never faked)."""
    url = HF_ROWS_URL.format(ds=HF_DATASET, cfg=HF_CONFIG, sp=HF_SPLIT,
                             off=offset, n=length)
    last: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return [r["row"] for r in (data.get("rows") or [])]
        except Exception as exc:
            last = exc
            import time
            time.sleep(1.5 * attempt)
    raise RuntimeError(f"fetch_hf_rows failed after {retries} retries: {last}")


def normalize_speca_row(raw: dict[str, Any]) -> dict[str, Any]:
    """Map a raw SPECA row onto the normalized import shape (used by the
    renderer/Neon schema). Unknown fields stay null — never guessed."""
    sev = (raw.get("severity") or "").strip()
    return {
        "external_record_id": raw.get("id"),
        "title": (raw.get("title") or "").strip(),
        "description": (raw.get("description") or "").strip(),
        "severity": sev or None,
        "protocol_domain": (raw.get("domain") or "").strip() or None,
        "url": (raw.get("source_url") or "").strip() or None,
        "category": None,   # not labeled by source; do not invent
        "preconditions": [],
        "metadata": {
            "source_platform": raw.get("source_platform"),
            "contest": raw.get("contest"),
            "issue_id": raw.get("issue_id"),
            "scraped_at": raw.get("scraped_at"),
        },
    }


def import_speca(store: NeonKnowledgeStore, *, limit: int = 100,
                 embedder=None, page_size: int = PAGE_SIZE) -> ImportSummary:
    """Import the first `limit` verified SPECA rows under source name
    `speca-code4rena` (idempotent by content_hash; provenance preserved)."""
    source = {
        "name": "speca-code4rena",
        "version": "2026-02",
        "url": f"https://huggingface.co/datasets/{HF_DATASET}",
        "license": "public audit findings (Code4rena contest reports)",
        "metadata": {"hf_dataset": HF_DATASET, "config": HF_CONFIG,
                     "split": HF_SPLIT, "platform": "code4rena"},
    }
    records: list[dict[str, Any]] = []
    offset = 0
    seen = 0
    while seen < limit:
        rows = fetch_hf_rows(offset, min(page_size, limit - seen))
        if not rows:
            break
        for r in rows:
            if seen >= limit:
                break
            records.append(normalize_speca_row(r))
            seen += 1
        offset += len(rows)
    return run_import(store, source=source, records=records[:limit],
                      embedder=embedder)
