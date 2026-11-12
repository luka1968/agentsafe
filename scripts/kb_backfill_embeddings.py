#!/usr/bin/env python
"""Backfill embeddings for KB rows that lack vectors (e.g. rows imported
with --skip-embed).

Reads rows with no knowledge_embeddings entry directly from Neon (no HF
dependency), builds the same body text the import pipeline uses, embeds in
NVIDIA NIM batches via the existing NVIDIAEmbedder, and inserts vectors with
a per-row existence check (no unique constraint exists on
knowledge_embeddings, so the guard prevents duplicates).

Idempotent: re-running embeds nothing (all rows already have vectors).

Usage:
    python scripts/kb_backfill_embeddings.py            # all sources
    python scripts/kb_backfill_embeddings.py --source speca-sherlock
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


def _embed_text(row: dict) -> str:
    """Same body construction as importers.run_import."""
    return " ".join(filter(None, [
        row.get("title"), row.get("description"), row.get("root_cause"),
        " ".join(row.get("preconditions") or []),
        row.get("impact"), row.get("remediation"),
    ]))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default=None,
                    help="restrict backfill to one source_id (default: all)")
    ap.add_argument("--batch-size", type=int, default=32,
                    help="rows per NIM embedding request (max 32)")
    args = ap.parse_args()

    env = _load_env()
    for k, v in env.items():
        os.environ.setdefault(k, v)
    dsn = os.environ.get("NEON_DATABASE_URL", "").strip()
    if not dsn:
        print("NEON_DATABASE_URL not set; nothing to do", file=sys.stderr)
        return 2

    from agentsafe.knowledge.db import NeonKnowledgeStore, content_hash_of
    from agentsafe.knowledge.embeddings import get_embedder

    embedder = get_embedder()
    if embedder is None:
        print("NVIDIA_API_KEY not configured; cannot backfill vectors",
              file=sys.stderr)
        return 2

    store = NeonKnowledgeStore(dsn=dsn, vector_dim=2048,
                               embedding_model=embedder)
    batch_size = max(1, min(args.batch_size, 32))

    where = "AND vk.source_id = %s" if args.source else ""
    params = (args.source,) if args.source else ()
    with store._connect() as conn, conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT vk.id, vk.title, vk.description, vk.root_cause,
                   vk.preconditions, vk.impact, vk.remediation,
                   vk.source_id
            FROM vulnerability_knowledge vk
            LEFT JOIN knowledge_embeddings ke ON ke.knowledge_id = vk.id
            WHERE ke.id IS NULL {where}
            ORDER BY vk.id
            """,
            params,
        )
        rows = cur.fetchall()
    print(f"rows lacking vectors: {len(rows)}"
          + (f" (source={args.source})" if args.source else ""))

    done = failed = 0
    errors: list[str] = []
    for i in range(0, len(rows), batch_size):
        batch = rows[i:i + batch_size]
        texts = [_embed_text(r) for r in batch]
        try:
            vecs = embedder.embed(texts)  # NIM passage input (import parity)
        except Exception as exc:
            failed += len(batch)
            errors.append(f"batch {i // batch_size}: embed: {str(exc)[:120]}")
            continue
        try:
            with store._connect() as conn, conn.cursor() as cur:
                for row, text, vec in zip(batch, texts, vecs):
                    cur.execute(
                        "SELECT 1 FROM knowledge_embeddings WHERE knowledge_id=%s",
                        (row["id"],))
                    if cur.fetchone():
                        continue  # raced/already present
                    cur.execute(
                        """
                        INSERT INTO knowledge_embeddings
                            (knowledge_id, embedding, embedding_model,
                             dimensions, content_hash)
                        VALUES (%s, %s, %s, %s, %s)
                        """,
                        (row["id"], [float(x) for x in vec[:store.vector_dim]],
                         embedder.name, len(vec), content_hash_of(text)),
                    )
                    done += 1
        except Exception as exc:
            failed += len(batch)
            errors.append(f"batch {i // batch_size}: db: {str(exc)[:120]}")
            continue
        print(f"  batch {i // batch_size + 1}: +{len(batch)} vectors",
              flush=True)

    print(json.dumps({"embedded": done, "failed": failed,
                      "errors": errors[:10]}))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
