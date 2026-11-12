#!/usr/bin/env python
"""KB-upgrade A/B evaluation (Task: Evaluation).

Fixed benchmark, measured before/after the knowledge-base upgrade.

Design (leakage-controlled):
  * Golden retrieval queries are FIXED class-level queries derived from the
    KB-organization task definitions (accounting/oracle/reentrancy/cross-
    function) — they never come from KB record titles, so record-level
    self-retrieval leakage is impossible.
  * Detection runs the leak-free deterministic probe layer (no LLM) over
    LISABench vulnerable contracts + OpenZeppelin reference-safe contracts;
    ground truth = benchmark labels.
  * "BEFORE" = legacy KB view (the original 281 records: speca-code4rena +
    agentsafe-v1.jsonl) via a source_id filter — nothing is deleted.
  * "AFTER"  = the full upgraded KB (all sources + retrieval profiles).
  * Metrics: retrieval Precision@5 / HitRate@5 / MRR per category;
    detection TP/FP/FN -> precision, recall, F1, FP rate, FN rate;
    per-class detection accuracy (accounting / oracle / cross_function /
    reentrancy); PoC validation success rate (validated findings with
    source-traceable evidence / vulnerable samples).
  * KB<->benchmark overlap is measured and reported for transparency.

Usage:
    python benchmarks/kb_upgrade_eval.py --n-detection 6 [--skip-detection]
Writes benchmarks/results/kb_upgrade_eval.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Legacy KB view = the original pre-upgrade record set (281 records).
LEGACY_SOURCES = ("speca-code4rena", "agentsafe-v1.jsonl")

# Fixed golden retrieval queries: (query, relevant categories).
# Derived from the KB-organization task definitions — NOT from KB records.
GOLDEN_QUERIES: list[tuple[str, tuple[str, ...]]] = [
    ("deposit withdraw share rounding totalSupply first depositor inflation",
     ("rounding", "accounting")),
    ("balance ledger desync withdraw insolvency accounting",
     ("accounting",)),
    ("oracle price stale chainlink manipulation spot twap",
     ("oracle",)),
    ("reentrancy external call callback drain state update",
     ("reentrancy",)),
    ("cross-function state flag interleave check-then-act cap bypass",
     ("reentrancy", "access-control", "accounting")),
    ("proxy initialization front-run takeover upgradeable",
     ("initialization", "proxy", "access-control")),
]

# Profile per golden class (category-specific retrieval, as wired in agents).
PROFILE_FOR_QUERY = [
    "accounting", "accounting", "oracle", "reentrancy",
    "cross_function", "proxy_upgrade",
]

K = 5


def _legacy_view(store):
    """Adapter: forces the legacy source filter on every search call."""
    class _LegacyView:
        def __init__(self, inner):
            self._inner = inner
            self.embedding_model = inner.embedding_model
            self.vector_dim = inner.vector_dim

        def search(self, query, focus="", limit=3, **kw):
            kw.setdefault("sources", LEGACY_SOURCES)
            return self._inner.search(query, focus=focus, limit=limit, **kw)

        def __getattr__(self, name):  # delegate everything else
            return getattr(self._inner, name)
    return _LegacyView(store)


def retrieval_eval(store, *, use_profiles: bool) -> dict:
    """Golden-query retrieval quality: P@5 / HitRate@5 / MRR per query."""
    from agentsafe import metrics as M

    rows = []
    for (query, rel_cats), profile in zip(GOLDEN_QUERIES, PROFILE_FOR_QUERY):
        hits = store.search(query, limit=K,
                            profile=profile if use_profiles else None)
        cats = [(h.get("category") or "").strip().lower() for h in hits]
        rel = [1 if c in rel_cats else 0 for c in cats]
        prec = sum(rel) / K
        hit = 1 if any(rel) else 0
        mrr = 0.0
        for i, r in enumerate(rel, 1):
            if r:
                mrr = 1.0 / i
                break
        rows.append({"query": query[:60], "relevant_categories": list(rel_cats),
                     "hit_categories": cats, "precision_at_5": round(prec, 4),
                     "hit_rate_at_5": hit, "mrr": round(mrr, 4)})
    return {
        "precision_at_5": round(sum(r["precision_at_5"] for r in rows) / len(rows), 4),
        "hit_rate_at_5": round(sum(r["hit_rate_at_5"] for r in rows) / len(rows), 4),
        "mrr": round(sum(r["mrr"] for r in rows) / len(rows), 4),
        "per_query": rows,
    }


def detection_eval(kb_factory, settings, samples) -> dict:
    """Deterministic probe detection over the benchmark, through a KB view."""
    import eval_suite as ES
    import eval_metrics as M

    per_sample = []
    t0 = time.monotonic()
    for s in samples:
        bundle = ES._bundle_from_rec(s)
        if bundle is None:
            continue
        rep, elapsed, _st = asyncio.run(ES.run_audit(
            bundle, rag=True, llm_mode="probe", kb_factory=kb_factory,
            settings=settings))
        per_sample.append(ES._detection_sample(s, rep, True, elapsed))
    rows = [p for p in per_sample if "skipped" not in p]
    agg = {"tp": 0, "fp": 0, "fn": 0}
    per_class: dict[str, dict[str, int]] = {}
    validated = 0
    for r in rows:
        agg["tp"] += len(r["tp"]); agg["fp"] += len(r["fp"]); agg["fn"] += len(r["fn"])
        for c in set(r["gt_categories"]) | set(r["predicted_categories"]):
            d = per_class.setdefault(c, {"tp": 0, "fp": 0, "fn": 0})
            if c in r["tp"]:
                d["tp"] += 1
            elif c in r["fp"]:
                d["fp"] += 1
            elif c in r["fn"]:
                d["fn"] += 1
        # PoC validation success: audit clean + >=1 finding with traceable
        # source evidence (the deterministic validation layer's verdict).
        if not r["audit_error"] and r["n_findings"] > 0 \
                and r["evidence_traceability"].get("traceable", 0) > 0:
            validated += 1
    prf = M.precision_recall_f1(agg["tp"], agg["fp"], agg["fn"])
    per_class_acc = {}
    for c, d in per_class.items():
        pr = M.precision_recall_f1(d["tp"], d["fp"], d["fn"])
        per_class_acc[c] = {"precision": pr["precision"], "recall": pr["recall"],
                            **d}
    return {
        "n_samples": len(rows),
        "tp": agg["tp"], "fp": agg["fp"], "fn": agg["fn"],
        "precision": prf["precision"], "recall": prf["recall"],
        "f1": prf["f1"],
        "false_positive_rate": M.false_positive_rate(agg["tp"], agg["fp"]),
        "false_negative_rate": round(
            agg["fn"] / (agg["fn"] + agg["tp"]), 4) if (agg["fn"] + agg["tp"]) else None,
        "per_class_accuracy": per_class_acc,
        "poc_validation_success_rate": round(validated / len(rows), 4) if rows else None,
        "runtime_seconds": round(time.monotonic() - t0, 1),
        "per_sample": rows,
    }


def kb_benchmark_overlap(store, samples) -> dict:
    """Transparency: KB records sharing a contest id with benchmark samples."""
    kb_ids = {r.get("external_record_id") or "" for r in store.records()}
    overlap = 0
    for s in samples:
        title = (s.get("Title") or "").lower()
        if any(t and (t in title or title in t) for t in
               (i.split(":")[-1] for i in kb_ids if ":" in i)):
            overlap += 1
    return {"kb_records": len(kb_ids), "samples": len(samples),
            "possible_overlap_samples": overlap,
            "note": "golden retrieval queries are class-level and fixed; "
                    "record-level leakage cannot affect them"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-detection", type=int, default=6)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--skip-detection", action="store_true",
                    help="retrieval A/B only (fast; no audit runs)")
    args = ap.parse_args()

    env = {}
    p = Path(__file__).resolve().parents[1] / ".env"
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    for k, v in env.items():
        os.environ.setdefault(k, v)

    from agentsafe.config import Settings
    from agentsafe.knowledge.db import NeonKnowledgeStore

    settings = Settings()
    store = NeonKnowledgeStore(dsn=os.environ["NEON_DATABASE_URL"],
                               vector_dim=2048,
                               embedding_model=_embedder_or_none())
    legacy = _legacy_view(store)

    report: dict = {"k": K, "legacy_sources": list(LEGACY_SOURCES)}
    report["retrieval_before"] = retrieval_eval(legacy, use_profiles=False)
    report["retrieval_after"] = retrieval_eval(store, use_profiles=True)

    if not args.skip_detection:
        import eval_data as data
        samples = data.load_lisabench(args.n_detection, seed=args.seed)
        report["kb_benchmark_overlap"] = kb_benchmark_overlap(store, samples)
        # Detection A/B uses lexical-only retrieval on BOTH sides: the vector
        # provider was returning 5xx at eval time (retry storm would dominate
        # runtime). Identical machinery on both sides keeps the A/B fair;
        # retrieval A/B above measures the embedder path (auto-fallback).
        lexical_store = NeonKnowledgeStore(dsn=os.environ["NEON_DATABASE_URL"],
                                           vector_dim=2048,
                                           embedding_model=None)
        lexical_legacy = _legacy_view(lexical_store)
        report["detection_retrieval_mode"] = "lexical-only (vector provider outage)"
        report["detection_before"] = detection_eval(
            lexical_legacy, settings, samples)
        report["detection_after"] = detection_eval(
            lexical_store, settings, samples)

    out = Path(__file__).resolve().parents[1] / "benchmarks" / "results" \
        / "kb_upgrade_eval.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str),
                   encoding="utf-8")
    slim = {k: ({kk: vv for kk, vv in v.items() if kk != "per_sample"}
                if isinstance(v, dict) else v)
            for k, v in report.items()}
    print(json.dumps(slim, indent=2, ensure_ascii=False, default=str)[:4000])
    print(f"wrote {out}")
    return 0


def _embedder_or_none():
    try:
        from agentsafe.knowledge.embeddings import get_embedder
        return get_embedder()
    except Exception:
        return None


if __name__ == "__main__":
    raise SystemExit(main())
