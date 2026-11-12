#!/usr/bin/env python
"""Category A — Real-World Vulnerability Cases: KB upgrade runner.

Applies the Category A organization to the live Neon knowledge base:
  1. migrate() — additive columns (kb_group, verification_status,
     license_status, commercial_use); never drops or rewrites data.
  2. Import Sherlock public contest reports from the verified SPECA source
     (same legally reusable dataset that provided the Code4rena records).
     Idempotent by content_hash.
  3. Non-destructive enrichment of Category A rows: classification, impact,
     remediation, vulnerable code — only NULL fields are filled.

Usage:
    python scripts/kb_category_a.py --sherlock-limit 60 --enrich-limit 500
Never prints secrets. Read-only network source: HF datasets-server.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def _load_env() -> dict:
    env = {}
    p = Path(__file__).resolve().parents[1] / ".env"
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sherlock-limit", type=int, default=60,
                    help="sherlock rows to import (0 = skip import)")
    ap.add_argument("--enrich-limit", type=int, default=500,
                    help="max rows to enrich in the non-destructive pass")
    ap.add_argument("--skip-embed", action="store_true",
                    help="skip embeddings during import (lexical-only rows)")
    args = ap.parse_args()

    env = _load_env()
    for k, v in env.items():
        os.environ.setdefault(k, v)
    dsn = os.environ.get("NEON_DATABASE_URL", "").strip()
    if not dsn:
        print("NEON_DATABASE_URL not set; nothing to do", file=sys.stderr)
        return 2

    from agentsafe.knowledge.db import NeonKnowledgeStore
    from agentsafe.knowledge.embeddings import get_embedder
    from agentsafe.knowledge.enrich import enrich_category_a
    from agentsafe.knowledge.speca import import_speca

    embedder = None if args.skip_embed else get_embedder()
    store = NeonKnowledgeStore(dsn=dsn, vector_dim=2048,
                               embedding_model=embedder)
    store.migrate()
    print(f"store ready: {store.count()} records")

    if args.sherlock_limit > 0:
        s = import_speca(store, limit=args.sherlock_limit,
                         embedder=embedder, platform="sherlock")
        print("sherlock import:", json.dumps(s.to_dict()))
    else:
        print("sherlock import skipped (--sherlock-limit 0)")

    es = enrich_category_a(store, limit=args.enrich_limit)
    print("enrichment:", json.dumps(es.to_dict()))

    print(f"final record count: {store.count()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
