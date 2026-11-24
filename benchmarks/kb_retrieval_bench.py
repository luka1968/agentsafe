#!/usr/bin/env python
"""Phase 8 — repeatable retrieval benchmark over the live knowledge base.

Ground truth (declared, reproducible, NOT fabricated):
  * a fixed list of CLASS-LEVEL queries (authored from the vulnerability class,
    never from a record title, so there is no retrieval leakage);
  * a retrieved record counts as RELEVANT when its stored `category` is in the
    query's expected category set (a predicate over stored metadata, not over
    retrieval output);
  * RECALL is anchored on the CURATED records (in-repo dataset sources) whose
    category matches — a small, known-denominator set; real-world (group A)
    records are counted for precision but excluded from the recall denominator
    (their count is not a meaningful target);
  * two counterexample (false-positive) cases are scored by whether a
    counterexample record (kb_group E/F) is actually returned.

Compares three retrieval legs head-to-head plus counterexample retrieval:
  vector-only, lexical-only, hybrid (production path: RRF + profile + context).

Metrics: Precision@K, Recall@K, MRR, relevant coverage, irrelevant-retrieval
rate, vector-leg availability (proxy for embedding failures), source-reference
preservation, counterexample-retrieval rate, latency (mean/median).

Writes benchmarks/results/kb_retrieval_bench.json. Read-only.

    python benchmarks/kb_retrieval_bench.py [--k 5]
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
ROOT = Path(__file__).resolve().parents[1]

# Class-level queries. `expected` = KB categories that must be considered
# relevant. Never derived from KB record titles (leakage-controlled).
CASES: list[dict] = [
    {"id": "reentrancy", "kind": "category", "profile": "reentrancy",
     "query": "external call before state update allows reentrant drain",
     "expected": ("reentrancy",)},
    {"id": "cross_function_reentrancy", "kind": "category",
     "profile": "reentrancy",
     "query": "two functions share state and one lacks a reentrancy guard",
     "expected": ("reentrancy",)},
    {"id": "accounting", "kind": "category", "profile": "accounting",
     "query": "share and balance accounting desync after deposit withdraw",
     "expected": ("accounting", "rounding")},
    {"id": "access_control", "kind": "category", "profile": "access_control",
     "query": "missing owner or role check on a privileged function",
     "expected": ("access-control", "initialization")},
    {"id": "arithmetic", "kind": "category", "profile": "arithmetic",
     "query": "unchecked arithmetic overflow changes a value",
     "expected": ("rounding", "accounting")},
    {"id": "oracle_manipulation", "kind": "category", "profile": "oracle",
     "query": "spot price manipulation of an oracle used for valuation",
     "expected": ("oracle",)},
    {"id": "token_integration", "kind": "category", "profile": "accounting",
     "query": "fee-on-transfer token breaks internal balance accounting",
     "expected": ("token-transfer", "accounting")},
    {"id": "signature_validation", "kind": "category", "profile": "access_control",
     "query": "signature replay missing nonce or malleability in verification",
     "expected": ("access-control", "approval", "governance")},
    {"id": "denial_of_service", "kind": "category", "profile": "accounting",
     "query": "unbounded loop or external call reverts withdrawal (dos)",
     "expected": ("accounting", "token-transfer", "reentrancy")},
    {"id": "cross_contract", "kind": "category", "profile": "cross_function",
     "query": "callback into another contract corrupts shared state",
     "expected": ("reentrancy", "accounting", "bridge")},
    {"id": "business_logic", "kind": "category", "profile": "cross_function",
     "query": "governance timelock bypass or business logic accounting flaw",
     "expected": ("governance", "accounting", "access-control")},
    {"id": "solc_version_specific", "kind": "category", "profile": "arithmetic",
     "solc": "0.7",
     "query": "solidity 0.7 unchecked arithmetic overflow without safe math",
     "expected": ("rounding", "accounting")},
    {"id": "evm_rollback_counterexample", "kind": "counterexample",
     "profile": "false_positive",
     "query": "failed transfer reverts all state so no partial deduction persists",
     "code": "token.transfer(to, amt); balances[msg.sender] -= amt;"},
    {"id": "false_positive_examples", "kind": "counterexample",
     "profile": "false_positive",
     "query": "send and low-level call do not auto revert false positive",
     "code": "payable(to).send(amt); (bool ok,) = to.call{value: 1}(\"\");"},
]
FP_SOURCE = "agentsafe-fp-v1.jsonl"


def _load_env() -> dict:
    env = {}
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def _ground_truth(store) -> tuple[set[str], dict[str, set[str]], int]:
    """Return (fp_ids, relevant_by_case, curated_count). Relevant ids are
    external_record_ids of CURATED records whose category matches the case."""
    with store._connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT external_record_id, category, source_id "
                    "FROM vulnerability_knowledge")
        rows = [dict(r) for r in cur.fetchall()]
    curated = [r for r in rows if str(r["source_id"] or "").startswith("agentsafe-")]
    fp_ids = {r["external_record_id"] for r in rows
              if r["source_id"] == FP_SOURCE}
    relevant: dict[str, set[str]] = {}
    for case in CASES:
        if case["kind"] == "counterexample":
            relevant[case["id"]] = set(fp_ids)
        else:
            exp = set(case["expected"])
            relevant[case["id"]] = {
                r["external_record_id"] for r in curated
                if (r["category"] or "").lower() in exp}
    return fp_ids, relevant, len(curated)


def _metrics(hits: list[dict], case: dict, relevant: set[str]) -> dict:
    k = len(hits)
    expected = set(case.get("expected", ()))
    rel_flags = [1 if (h.get("category") or "").lower() in expected else 0
                 for h in hits]
    found = [h for h in hits if h.get("id") in relevant]
    mrr = 0.0
    for i, flag in enumerate(rel_flags, 1):
        if flag:
            mrr = 1.0 / i
            break
    return {
        "retrieved": k,
        "precision@k": round(sum(rel_flags) / k, 4) if k else 0.0,
        "recall@k": (round(len(found) / len(relevant), 4)
                     if relevant else None),  # None = no ground-truth records
        "mrr": round(mrr, 4),
        "hit": bool(sum(rel_flags)),
        "source_refs_preserved": (round(
            sum(1 for h in hits if h.get("url") or h.get("external_record_id"))
            / k, 4) if k else 0.0),
    }


def _run_mode(store, case: dict, k: int, mode: str) -> tuple[list[dict], float]:
    t0 = time.monotonic()
    if mode == "vector":
        hits = store.search_leg_vector(case["query"], limit=k)
    elif mode == "lexical":
        hits = store.search_leg_lexical(case["query"], limit=k)
    else:
        hits = store.search(case["query"], limit=k,
                            profile=case.get("profile"),
                            solc=case.get("solc"))
    return hits, (time.monotonic() - t0) * 1000.0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--k", type=int, default=5)
    args = ap.parse_args()
    k = args.k

    for key, val in _load_env().items():
        os.environ.setdefault(key, val)
    dsn = os.environ.get("NEON_DATABASE_URL", "").strip()
    if not dsn:
        print("NEON_DATABASE_URL not set", file=sys.stderr)
        return 2
    from agentsafe.knowledge.db import NeonKnowledgeStore
    try:
        from agentsafe.knowledge.embeddings import get_embedder
        embedder = get_embedder()
    except Exception:
        embedder = None
    store = NeonKnowledgeStore(dsn=dsn, vector_dim=2048, embedding_model=embedder)
    from agentsafe.knowledge.falsepositives import retrieve_counterexamples

    _fp_ids, relevant, curated_count = _ground_truth(store)

    report: dict = {
        "k": k,
        "mode_embedder": "hybrid" if embedder is not None else "lexical-only",
        "ground_truth": {
            "definition": ("predicate over stored category metadata; recall "
                           "anchored on the curated records; queries are "
                           "class-level and not taken from record titles"),
            "curated_records": curated_count,
            "fp_records": len(_fp_ids),
            "limitation": ("no human relevance judgments exist, so recall is a "
                           "curated-anchored lower bound, not absolute recall"),
        },
        "modes": {},
        "cases": {},
    }

    for mode in ("vector", "lexical", "hybrid"):
        if mode == "vector" and embedder is None:
            report["modes"][mode] = {"unavailable": "no embedder"}
            continue
        per_case = []
        latencies = []
        vec_empty = 0
        for case in CASES:
            if case["kind"] == "counterexample":
                continue
            hits, ms = _run_mode(store, case, k, mode)
            latencies.append(ms)
            if mode == "vector" and not hits:
                vec_empty += 1
            m = _metrics(hits, case, relevant[case["id"]])
            m.update({"case": case["id"], "latency_ms": round(ms, 1)})
            per_case.append(m)
            report["cases"].setdefault(case["id"], {})[mode] = {
                "precision@k": m["precision@k"], "recall@k": m["recall@k"],
                "mrr": m["mrr"]}
        recall_vals = [c["recall@k"] for c in per_case if c["recall@k"] is not None]
        report["modes"][mode] = {
            "cases": len(per_case),
            "mean_precision@k": round(
                statistics.mean(c["precision@k"] for c in per_case), 4),
            "mean_recall@k": (round(statistics.mean(recall_vals), 4)
                              if recall_vals else None),
            "recall_cases_measured": len(recall_vals),
            "mean_mrr": round(statistics.mean(c["mrr"] for c in per_case), 4),
            "coverage": round(
                sum(1 for c in per_case if c["hit"]) / len(per_case), 4),
            "irrelevant_rate": round(
                1 - statistics.mean(c["precision@k"] for c in per_case), 4),
            "source_refs_preserved": round(
                statistics.mean(c["source_refs_preserved"] for c in per_case), 4),
            "latency_ms_mean": round(statistics.mean(latencies), 1),
            "latency_ms_median": round(statistics.median(latencies), 1),
            "vector_leg_empty_cases": vec_empty if mode == "vector" else None,
            "vector_failure_rate": (round(vec_empty / len(per_case), 4)
                                    if mode == "vector" else None),
        }

    # Counterexample (false-positive) retrieval rate.
    ce_hits = ce_total = 0
    ce_detail = {}
    for case in CASES:
        if case["kind"] != "counterexample":
            continue
        ce_total += 1
        t0 = time.monotonic()
        recs = retrieve_counterexamples(
            store, text=case.get("code") or case["query"],
            category=None, limit=max(k, 3))
        ok = any(str(r.get("kb_group") or "") in ("E", "F") for r in recs)
        ce_hits += 1 if ok else 0
        ce_detail[case["id"]] = {"returned": len(recs), "counterexample": ok,
                                 "latency_ms": round((time.monotonic() - t0) * 1000, 1)}
    report["counterexample_retrieval"] = {
        "cases": ce_total, "rate": round(ce_hits / ce_total, 4) if ce_total else None,
        "detail": ce_detail,
    }

    # Honest statements about unmeasurable metrics.
    report["unmeasurable"] = {
        "absolute_recall": ("no exhaustive labeled corpus; recall is reported "
                            "against the curated anchor set only"),
        "embedding_failure_rate": ("reported as vector-leg-empty rate; a hard "
                                   "embedding failure is indistinguishable from "
                                   "a genuinely empty vector result"),
    }

    out = ROOT / "benchmarks" / "results" / "kb_retrieval_bench.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    print(json.dumps({k2: v for k2, v in report.items() if k2 != "cases"},
                     indent=2))
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
