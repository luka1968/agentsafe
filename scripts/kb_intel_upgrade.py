#!/usr/bin/env python
"""Knowledge-base intelligence upgrade runner (non-destructive).

Applies the data-quality / intelligence pass to the live Neon KB:

  1. Provenance backfill — restore contest / issue_id / source_platform that
     an earlier import double-normalization dropped (derived from the existing
     external id; no URL is fabricated).
  2. LLM structured enrichment — fill root_cause / attack_scenario /
     preconditions / category / subcategory / swc_id / tags for group-A
     records, then propagate the shared intelligence to their chunk children.
     NULL-only, idempotent, verified rows skipped.
  3. Embedding integrity — back up the vectors of changed records, then
     re-embed only the ones whose stored vector no longer matches the current
     embedding body. Unchanged vectors are never discarded.
  4. Source counts — keep knowledge_sources.record_counts accurate.

Every step is additive and idempotent: re-running does nothing already done.

Usage:
    python scripts/kb_intel_upgrade.py --limit 200
    python scripts/kb_intel_upgrade.py --skip-enrich --skip-embed
    python scripts/kb_intel_upgrade.py --dry-run

Never prints secrets.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

DEFAULT_SOURCES = ("speca-code4rena", "speca-sherlock")


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
    ap.add_argument("--source", action="append", default=None,
                    help="source_id to process (repeatable; default group A)")
    ap.add_argument("--limit", type=int, default=200,
                    help="max records to enrich in this run")
    ap.add_argument("--embed-limit", type=int, default=2000,
                    help="max records to scan for stale embeddings")
    ap.add_argument("--skip-provenance", action="store_true")
    ap.add_argument("--skip-enrich", action="store_true")
    ap.add_argument("--skip-embed", action="store_true")
    ap.add_argument("--skip-counts", action="store_true")
    ap.add_argument("--no-propagate", action="store_true",
                    help="do not copy parent intelligence to chunk children")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would be done; no LLM calls, no writes")
    ap.add_argument("--skip-migrate", action="store_true",
                    help="skip the (slow) schema migration on this run")
    ap.add_argument("--provider", action="append", default=None,
                    help="pin LLM provider(s) by name (repeatable); default "
                         "rotates through all configured providers")
    ap.add_argument("--concurrency", type=int, default=4,
                    help="parallel LLM extraction calls (default 4)")
    args = ap.parse_args()

    for k, v in _load_env().items():
        os.environ.setdefault(k, v)
    dsn = os.environ.get("NEON_DATABASE_URL", "").strip()
    if not dsn:
        print("NEON_DATABASE_URL not set; nothing to do", file=sys.stderr)
        return 2
    sources = tuple(args.source or DEFAULT_SOURCES)

    from agentsafe.knowledge.db import NeonKnowledgeStore

    embedder = None
    try:
        from agentsafe.knowledge.embeddings import get_embedder
        embedder = get_embedder()
    except Exception as exc:  # embedding is optional; lexical stays valid
        print(f"embedder unavailable ({exc}); embedding steps skipped",
              file=sys.stderr)

    store = NeonKnowledgeStore(dsn=dsn, vector_dim=2048,
                               embedding_model=embedder)
    if not args.skip_migrate:
        store.migrate()
    print(f"store ready: {store.count()} records; sources={list(sources)}",
          flush=True)

    report: dict = {"sources": list(sources), "dry_run": args.dry_run}

    if not args.skip_provenance and not args.dry_run:
        from agentsafe.knowledge.maintenance import backfill_provenance
        ps = backfill_provenance(store, sources=sources)
        report["provenance"] = ps.to_dict()
        print("provenance:", json.dumps(ps.to_dict()), flush=True)

    if not args.skip_enrich:
        from agentsafe.knowledge.enrich_llm import (
            ProviderLLMClient,
            enrich_group_a_llm,
            providers_from_env,
        )
        providers = providers_from_env()
        if args.provider:
            want = {p.strip() for p in args.provider}
            providers = [p for p in providers if p.get("name") in want]
        if not providers:
            print("no LLM providers configured; enrichment skipped",
                  file=sys.stderr)
        elif args.dry_run:
            with store._connect() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*) c FROM vulnerability_knowledge "
                    "WHERE source_id = ANY(%s) "
                    "AND metadata->>'parent_external_id' IS NULL "
                    "AND NOT (metadata ? 'llm_enrichment')",
                    (list(sources),))
                report["enrich_pending"] = cur.fetchone()["c"]
            print("enrich pending:", report["enrich_pending"])
        else:
            model = providers[0].get("model", "llm")
            # Disable chain-of-thought where honoured: same structured JSON,
            # far lower latency for a large pass.
            client = ProviderLLMClient(providers,
                                       extra_payload={"enable_thinking": False})

            def _progress(done: int, total: int) -> None:
                if done == 1 or done % 5 == 0 or done == total:
                    print(f"  enrich {done}/{total} ...", flush=True)

            es = enrich_group_a_llm(
                store, llm=client, source_ids=sources, limit=args.limit,
                propagate=False, model=model,
                concurrency=max(1, args.concurrency), progress=_progress)
            report["enrich"] = es.to_dict()
            print("enrich:", json.dumps(es.to_dict()), flush=True)
            if not args.no_propagate:
                from agentsafe.knowledge.maintenance import (
                    propagate_parent_intelligence,
                )
                n = propagate_parent_intelligence(store, sources=sources)
                report["propagated_children"] = n
                print("propagated_children:", n, flush=True)

    if not args.skip_embed and not args.dry_run:
        if embedder is None:
            report["embed"] = {"skipped": "no embedder"}
        else:
            from agentsafe.knowledge.maintenance import refresh_embeddings
            rs = refresh_embeddings(store, embedder, sources=sources,
                                    limit=args.embed_limit)
            report["embed"] = rs.to_dict()
            print("embed:", json.dumps(rs.to_dict()))

    if not args.skip_counts and not args.dry_run:
        from agentsafe.knowledge.maintenance import refresh_source_counts
        counts = refresh_source_counts(store)
        report["source_counts"] = counts
        print("source_counts:", json.dumps(counts))

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
