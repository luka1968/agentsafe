"""Stage 10 — metric functions (deterministic, unit-testable).

Every metric is computed from actually-executed runs; there is no synthesized
number anywhere in this module.
"""

from __future__ import annotations

from collections import Counter
from typing import Iterable, Sequence


def precision_recall_f1(tp: int, fp: int, fn: int) -> dict[str, float | None]:
    prec = tp / (tp + fp) if (tp + fp) else None
    rec = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * prec * rec / (prec + rec)) if (prec and rec and prec + rec) else None
    return {"precision": prec, "recall": rec, "f1": f1}


def macro_f1(rows: Iterable[dict]) -> dict:
    """Macro-averaged P/R/F1 over per-class TP/FP/FN counts."""
    agg: dict[str, Counter] = {k: Counter() for k in ("tp", "fp", "fn")}
    classes: set[str] = set()
    for r in rows:
        classes.update({r["class"]})
        for k in ("tp", "fp", "fn"):
            agg[k][r["class"]] += r[k]
    vals = [precision_recall_f1(agg["tp"][c], agg["fp"][c], agg["fn"][c])
            for c in sorted(classes)]
    n = len(vals)
    out: dict = {"n_classes": n}
    for k in ("precision", "recall", "f1"):
        non_null = [v[k] for v in vals if v[k] is not None]
        out[k] = round(sum(non_null) / len(non_null), 4) if non_null else None
    return out


def false_positive_rate(tp: int, fp: int) -> float | None:
    """FP / (FP + TN) requires TN; here we report FP share of predicted
    positives when TN is unavailable (documented in the artifact)."""
    if tp + fp == 0:
        return None
    return round(fp / (tp + fp), 4)


def severity_accuracy(pairs: Sequence[tuple[str | None, str | None]]) -> dict:
    """Exact-match severity agreement over (gt, predicted) pairs.

    None gt (no severity label in source) is excluded, not counted as a miss.
    """
    cmp = [(g, p) for g, p in pairs if g is not None and p is not None]
    exact = sum(1 for g, p in cmp if g == p)
    return {
        "n_labeled": len(cmp),
        "n_exact": exact,
        "accuracy": round(exact / len(cmp), 4) if cmp else None,
    }


def evidence_traceability(gt_texts: Sequence[str],
                          evidence_texts: Sequence[str]) -> dict:
    """How often at least one ground-truth code line appears verbatim in the
    emitted evidence (source-location accuracy proxy — LISABench has no
    structured line numbers; documented as a limitation)."""
    ev_set = set(" ".join(evidence_texts).split())
    hits = 0
    for gt in gt_texts:
        lines = [ln.strip() for ln in gt.splitlines() if ln.strip()
                 and not ln.strip().startswith("//")]
        if not lines:
            continue
        key_tokens = lines[0].replace(";", "").split()
        if any(tok in ev_set for tok in key_tokens if len(tok) > 4):
            hits += 1
    return {"n": len(gt_texts), "traceable": hits}


def recall_at_k(ranked_ids: Sequence[str], gt: str, ks: Sequence[int] = (1, 3, 5)) -> dict:
    """Recall@k + MRR over a ranked id list (already normalized)."""
    out: dict = {}
    for k in ks:
        out[f"recall@{k}"] = int(gt in ranked_ids[:k])
    for i, hid in enumerate(ranked_ids, start=1):
        if hid == gt:
            out["mrr"] = round(1.0 / i, 4)
            break
    else:
        out["mrr"] = 0.0
    return out


def runtime_summary(seconds: Sequence[float]) -> dict:
    if not seconds:
        return {"n": 0, "mean_seconds": None, "median_seconds": None}
    s = sorted(seconds)
    mid = len(s) // 2
    med = s[mid] if len(s) % 2 else (s[mid - 1] + s[mid]) / 2
    return {"n": len(s),
            "mean_seconds": round(sum(s) / len(s), 3),
            "median_seconds": round(med, 3),
            "min_seconds": round(s[0], 3),
            "max_seconds": round(s[-1], 3)}


def tool_success_rate(runs: Sequence[dict]) -> dict:
    """runs: [{tool, executed, error}] — executed-without-error over total."""
    total = len(runs)
    ok = sum(1 for r in runs if r.get("executed") and not r.get("error"))
    return {"n_runs": total,
            "success_rate": round(ok / total, 4) if total else None,
            "n_success": ok}
