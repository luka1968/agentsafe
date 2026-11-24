#!/usr/bin/env python
"""KB intelligence-coverage evaluation (Task: knowledge-base intelligence).

Measures how much *technically useful* structure the retrieval layer actually
hands an agent, not just how many records exist. Two axes:

  1. Corpus coverage — over the real-world-case sources (group A), the
     fraction of records carrying each intelligence field (category, root
     cause, attack scenario, preconditions, impact, remediation, tags).
  2. Retrieval coverage — over FIXED class-level probe queries (never taken
     from KB record titles, so record-level leakage is impossible), the
     fraction of the TOP-K retrieved records that carry each field, plus
     standard relevance (Precision@K / MRR) against the query's expected
     category set.

The same fixture runs before and after an enrichment pass: a rising retrieval
coverage means the snippets an agent receives increasingly contain a root
cause, an attack scenario, and preconditions instead of "root cause: None".

Usage:
    python benchmarks/kb_intel_eval.py [--limit 5] [--tag before|after]
Writes benchmarks/results/kb_intel_eval.json (merged by --tag).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

# Probe queries: class-level security questions an agent focuses on. Ground
# truth = the KB categories that MUST be considered relevant for the query.
# These strings never come from KB record titles (leakage-controlled).
PROBES: list[tuple[str, str, tuple[str, ...]]] = [
    ("reentrancy external call callback drain state update", "reentrancy",
     ("reentrancy",)),
    ("oracle price stale chainlink twap spot manipulation", "oracle",
     ("oracle",)),
    ("share rounding totalSupply first depositor inflation", "accounting",
     ("rounding", "accounting")),
    ("balance ledger desync withdraw insolvency accounting", "accounting",
     ("accounting",)),
    ("access control missing modifier unprotected withdrawal", "access_control",
     ("access-control",)),
    ("proxy initialization front-run takeover upgradeable", "proxy_upgrade",
     ("initialization", "proxy", "access-control")),
    ("unchecked external call return value silent failure", "cross_function",
     ("unhandled-return", "token-transfer")),
    ("flash loan governance vote manipulation timelock", "cross_function",
     ("governance", "oracle")),
    ("approval race allowance double spend front-run", "cross_function",
     ("approval",)),
    ("cross-contract callback read-only reentrancy state", "reentrancy",
     ("reentrancy", "accounting")),
]

INTEL_FIELDS = ("category", "root_cause", "attack_scenario", "preconditions",
                "impact", "remediation", "tags")

GROUP_A_SOURCES = ("speca-code4rena", "speca-sherlock")


def _nonempty(val) -> bool:
    if val is None:
        return False
    if isinstance(val, str):
        return bool(val.strip())
    if isinstance(val, (list, dict)):
        return len(val) > 0
    return True


def _load_env() -> dict:
    env = {}
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def corpus_coverage(store, sources) -> dict:
    with store._connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT
              count(*) total,
              count(*) FILTER (
                WHERE category IS NOT NULL AND btrim(category) <> '') category,
              count(*) FILTER (
                WHERE root_cause IS NOT NULL AND btrim(root_cause) <> '') root_cause,
              count(*) FILTER (
                WHERE attack_scenario IS NOT NULL
                  AND btrim(attack_scenario) <> '') attack_scenario,
              count(*) FILTER (
                WHERE preconditions IS NOT NULL
                  AND preconditions <> '[]'::jsonb) preconditions,
              count(*) FILTER (
                WHERE impact IS NOT NULL AND btrim(impact) <> '') impact,
              count(*) FILTER (
                WHERE remediation IS NOT NULL AND btrim(remediation) <> '') remediation,
              count(*) FILTER (
                WHERE tags IS NOT NULL AND tags <> '[]'::jsonb) tags,
              count(*) FILTER (
                WHERE metadata ? 'llm_enrichment') llm_enriched
            FROM vulnerability_knowledge
            WHERE source_id = ANY(%s)
            """,
            (list(sources),),
        )
        row = cur.fetchone()
    total = row["total"] or 1
    return {
        "total": row["total"],
        **{f: round(row[f] / total, 4) for f in INTEL_FIELDS},
        "llm_enriched": round(row["llm_enriched"] / total, 4),
    }


def retrieval_coverage(store, limit: int) -> dict:
    per_query = []
    field_hits = {f: 0 for f in INTEL_FIELDS}
    n_records = 0
    prec_sum = mrr_sum = 0.0
    for query, profile, rel_cats in PROBES:
        hits = store.search(query, limit=limit, profile=profile)
        cats = [(h.get("category") or "").strip().lower() for h in hits]
        rel = [1 if c in rel_cats else 0 for c in cats]
        prec = sum(rel) / len(hits) if hits else 0.0
        mrr = 0.0
        for i, r in enumerate(rel, 1):
            if r:
                mrr = 1.0 / i
                break
        prec_sum += prec
        mrr_sum += mrr
        for h in hits:
            n_records += 1
            for f in INTEL_FIELDS:
                if _nonempty(h.get(f)):
                    field_hits[f] += 1
        per_query.append({
            "query": query[:56], "profile": profile,
            "n": len(hits), "hit_categories": cats,
            "precision@k": round(prec, 4), "mrr": round(mrr, 4),
        })
    denom = n_records or 1
    return {
        "probes": len(PROBES), "k": limit, "retrieved": n_records,
        "field_coverage": {f: round(field_hits[f] / denom, 4) for f in INTEL_FIELDS},
        "mean_precision@k": round(prec_sum / len(PROBES), 4),
        "mean_mrr": round(mrr_sum / len(PROBES), 4),
        "per_query": per_query,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=5)
    ap.add_argument("--tag", default="current",
                    help="label for this run (e.g. before/after); results merge")
    args = ap.parse_args()

    for k, v in _load_env().items():
        os.environ.setdefault(k, v)

    dsn = os.environ.get("NEON_DATABASE_URL", "").strip()
    if not dsn:
        print("NEON_DATABASE_URL not set; nothing to evaluate", file=sys.stderr)
        return 2

    from agentsafe.knowledge.db import NeonKnowledgeStore

    try:
        from agentsafe.knowledge.embeddings import get_embedder
        embedder = get_embedder()
    except Exception:
        embedder = None
    store = NeonKnowledgeStore(dsn=dsn, vector_dim=2048,
                               embedding_model=embedder)

    report = {
        "retrieval_mode": "hybrid (vector+lexical RRF)" if embedder
                          else "lexical-only",
        "corpus_coverage_group_a": corpus_coverage(store, GROUP_A_SOURCES),
        "retrieval_coverage": retrieval_coverage(store, args.limit),
    }
    out = ROOT / "benchmarks" / "results" / "kb_intel_eval.json"
    existing = {}
    if out.exists():
        try:
            existing = json.loads(out.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            existing = {}
    existing[args.tag] = report
    out.write_text(json.dumps(existing, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"\nwrote {out} (tag={args.tag})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
