#!/usr/bin/env python
"""Embedding-integrity check + safe back-fill.

  python scripts/kb_integrity.py            # report only
  python scripts/kb_integrity.py --backfill  # also embed records lacking vectors

Never deletes or rewrites a valid vector; back-fill only inserts vectors for
records that have none (or a NULL vector).
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
    ap.add_argument("--backfill", action="store_true")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    for k, v in _load_env().items():
        os.environ.setdefault(k, v)
    dsn = os.environ.get("NEON_DATABASE_URL", "").strip()
    if not dsn:
        print("NEON_DATABASE_URL not set", file=sys.stderr)
        return 2

    from agentsafe.knowledge.db import NeonKnowledgeStore
    from agentsafe.knowledge.embeddings import get_embedder
    from agentsafe.knowledge.integrity import (
        backfill_missing_embeddings,
        embedding_integrity,
    )

    embedder = get_embedder()
    store = NeonKnowledgeStore(dsn=dsn, vector_dim=2048,
                               embedding_model=embedder)
    report = embedding_integrity(store, embedder)
    print(json.dumps(report, indent=2))
    if args.backfill:
        summary = backfill_missing_embeddings(store, embedder, limit=args.limit)
        print("backfill:", json.dumps(summary.to_dict()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
