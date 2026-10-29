"""AgentSafe G+ Stage 7 — retrieval quality benchmark.

Protocol (deterministic, reproducible):
  * Pool: live SPECA rows in the Neon KB (source `speca-code4rena`).
  * Sample: `seed`-fixed sample of `n` rows whose title is discriminative
    (>= 8 chars, not generic like "QA Report").
  * Query: the record's own title (self-retrieval, ground truth = its id).
  * Matching: ids normalized (strip `#chunkN` suffix) so chunk variants of
    the same finding count as the same document.
  * Metrics: Recall@k (k=1,3,5), MRR, mean reciprocal rank + per-run output.

  Run modes:
    python benchmarks/retrieval_bench.py            # RRF hybrid (default)
    python benchmarks/retrieval_bench.py --leg vector-only  # ablation

  Writes benchmarks/results/retrieval_<mode>_<n>.json + prints summary.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

# ---------------------------------------------------------------- bootstrap
def _load_env() -> dict:
    env = {}
    p = Path(__file__).resolve().parents[1] / ".env"
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def norm_id(doc_id: str) -> str:
    """Collapse chunk variants (id#chunk2 -> id) — same finding."""
    return re.sub(r"#chunk\d*$", "", doc_id).strip()


def discriminative(title: str) -> bool:
    t = (title or "").strip()
    if len(t) < 8:
        return False
    low = t.lower()
    return "qa report" not in low and "qa summary" not in low \
        and not low.startswith("low/") and not low.startswith("n/a")


# ------------------------------------------------------------------ metrics
def evaluate(hits_ids: list[str], gt: str) -> dict:
    nid = norm_id(gt)
    ranked = [norm_id(h) for h in hits_ids]
    if nid in ranked:
        rank = ranked.index(nid) + 1
        return {"hit": True, "rank": rank,
                "recall1": int(rank == 1), "recall3": int(rank <= 3),
                "recall5": int(rank <= 5), "mrr": 1.0 / rank}
    return {"hit": False, "rank": None, "recall1": 0, "recall3": 0,
            "recall5": 0, "mrr": 0.0}


def summarize(results: list[dict]) -> dict:
    n = len(results)
    return {
        "n": n,
        "recall@1": round(sum(r["recall1"] for r in results) / n, 4),
        "recall@3": round(sum(r["recall3"] for r in results) / n, 4),
        "recall@5": round(sum(r["recall5"] for r in results) / n, 4),
        "mrr": round(sum(r["mrr"] for r in results) / n, 4),
        "hits": sum(1 for r in results if r["hit"]),
        "misses": sum(1 for r in results if not r["hit"]),
    }


# --------------------------------------------------------------------- main
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20, help="sample size")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--leg", choices=("rrf", "vector", "lexical"), default="rrf")
    ap.add_argument("--no-embed", action="store_true",
                    help="skip query embedding (lexical-only run; fast, no NVIDIA calls)")
    args = ap.parse_args()

    env = _load_env()
    for k, v in env.items():
        os.environ.setdefault(k, v)

    from agentsafe.knowledge.db import NeonKnowledgeStore
    from agentsafe.knowledge.embeddings import get_embedder

    emb = get_embedder()
    st = NeonKnowledgeStore(dsn=env["NEON_DATABASE_URL"], vector_dim=2048,
                            embedding_model=(None if args.no_embed else emb))

    # pool: all SPECA records w/ title+embedding
    pool = []
    with st._connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT vk.external_record_id, vk.title
                FROM vulnerability_knowledge vk
                JOIN knowledge_embeddings ke ON ke.knowledge_id = vk.id
                WHERE vk.source_id = 'speca-code4rena'
                  AND vk.title IS NOT NULL
            """)
            for r in cur.fetchall():
                rid = r["external_record_id"] if isinstance(r, dict) else r[0]
                title = r["title"] if isinstance(r, dict) else r[1]
                if discriminative(title):
                    pool.append((rid, title))
    rng = random.Random(args.seed)
    sample = rng.sample(pool, min(args.n, len(pool)))

    results = []
    for rid, title in sample:
        if args.leg == "vector":
            hits = st.search_leg_vector(title, limit=5)
        elif args.leg == "lexical":
            hits = st.search_leg_lexical(title, limit=5)
        else:
            hits = st.search(title, limit=5)
        ids = [h.get("id") or h.get("external_record_id") or "" for h in hits]
        results.append({"gt": rid, "q": title, "top": ids,
                        **evaluate(ids, rid)})

    summary = summarize(results)
    print(f"mode={args.leg} n={summary['n']} seed={args.seed}")
    for k, v in summary.items():
        print(f"  {k}: {v}")

    out_dir = Path(__file__).resolve().parents[1] / "benchmarks" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"retrieval_{args.leg}_{args.n}.json"
    out.write_text(json.dumps({"mode": args.leg, "seed": args.seed,
                               "summary": summary, "results": results},
                              ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
