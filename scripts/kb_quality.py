#!/usr/bin/env python
"""Phase 2 — knowledge data-quality classification runner (non-destructive).

Annotates every record with a quality class
(VALIDATED / NEEDS_REVIEW / INCOMPLETE / DUPLICATE / INVALID), an issue-flag
list, and an honest claim-verification dimension. The source record is never
modified, rewritten, or deleted — the classification lives in additive columns
(`quality_status`, `quality_flags`, `quality_claim`, `quality_checked_at`) that
can be dropped to revert.

Writes benchmarks/results/kb_quality_report.json and prints a summary.

Usage:
    python scripts/kb_quality.py [--limit N] [--skip-migrate]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

ROOT = Path(__file__).resolve().parents[1]


def _load_env() -> dict:
    env = {}
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--skip-migrate", action="store_true")
    args = ap.parse_args()

    for k, v in _load_env().items():
        os.environ.setdefault(k, v)
    dsn = os.environ.get("NEON_DATABASE_URL", "").strip()
    if not dsn:
        print("NEON_DATABASE_URL not set; nothing to assess", file=sys.stderr)
        return 2

    from agentsafe.knowledge.db import NeonKnowledgeStore
    from agentsafe.knowledge.quality import assess_store

    store = NeonKnowledgeStore(dsn=dsn, vector_dim=2048)
    if not args.skip_migrate:
        store.migrate()
    summary = assess_store(store, limit=args.limit)
    report = summary.to_dict()

    out = ROOT / "benchmarks" / "results" / "kb_quality_report.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    print(json.dumps(report, indent=2)[:4000])
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
