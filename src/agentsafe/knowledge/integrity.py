"""Embedding integrity: verify the model/dimension contract and back-fill gaps.

Reads the STORED embedding metadata and compares it to the configured embedder,
so a mismatch (model drift, wrong EMBED_DIM, stale vectors) is detected rather
than silently degrading retrieval. Back-filling only INSERTS/UPDATEs vectors
for records that have none — it never deletes or rewrites a valid vector.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

from agentsafe.knowledge.db import content_hash_of
from agentsafe.knowledge.embeddings import DEFAULT_DIM, DEFAULT_MODEL
from agentsafe.knowledge.importers import embedding_body

logger = logging.getLogger("agentSAFE.knowledge.integrity")


def embedding_integrity(store: Any, embedder: Any = None) -> dict[str, Any]:
    """Report stored-model/dimension facts and any contract mismatch.

    Detects: multiple stored models, null/missing vectors, duplicate
    knowledge_id rows, stored dim != configured dim, configured model != stored
    model, and whether the vector index (HNSW) exists."""
    with store._connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT embedding_model, dimensions, count(*) c "
            "FROM knowledge_embeddings GROUP BY 1,2 ORDER BY 3 DESC")
        stored = [{"model": r["embedding_model"], "dim": r["dimensions"],
                   "count": r["c"]} for r in cur.fetchall()]
        cur.execute("SELECT count(*) c FROM knowledge_embeddings")
        total = int(cur.fetchone()["c"])
        cur.execute("SELECT count(*) c FROM knowledge_embeddings "
                    "WHERE embedding IS NULL")
        null_vecs = int(cur.fetchone()["c"])
        cur.execute(
            "SELECT count(*) c FROM vulnerability_knowledge vk "
            "LEFT JOIN knowledge_embeddings ke ON ke.knowledge_id = vk.id "
            "WHERE ke.id IS NULL OR ke.embedding IS NULL")
        missing = int(cur.fetchone()["c"])
        cur.execute(
            "SELECT count(*) c FROM (SELECT knowledge_id FROM "
            "knowledge_embeddings GROUP BY knowledge_id HAVING count(*)>1) d")
        dup_ids = int(cur.fetchone()["c"])
        cur.execute("SELECT to_regclass('public.ke_hnsw_idx') t")
        hnsw = cur.fetchone()["t"] is not None

    cfg_model = getattr(embedder, "model", None) or \
        os.environ.get("NVIDIA_EMBED_MODEL", DEFAULT_MODEL)
    cfg_dim = getattr(embedder, "dim", None) or \
        int(os.environ.get("EMBED_DIM", DEFAULT_DIM))
    store_dim = int(getattr(store, "vector_dim", cfg_dim))

    mismatches: list[str] = []
    if len(stored) > 1:
        mismatches.append(
            f"multiple embedding models present: "
            f"{sorted({s['model'] for s in stored})}")
    if stored and any(s["dim"] and int(s["dim"]) != store_dim for s in stored):
        mismatches.append(
            f"stored dim {[s['dim'] for s in stored]} != configured "
            f"KB_VECTOR_DIM {store_dim}")
    if embedder is None:
        mismatches.append("no embedder configured: vector retrieval cannot run")
    elif getattr(embedder, "dim", None) != store_dim:
        mismatches.append(
            f"embedder dim {embedder.dim} != store dim {store_dim}")

    return {
        "records_total": None,  # filled by caller if needed
        "embeddings_total": total,
        "null_vectors": null_vecs,
        "records_without_embedding": missing,
        "duplicate_knowledge_ids": dup_ids,
        "stored": stored,
        "configured": {"model": cfg_model, "dim": cfg_dim,
                       "store_dim": store_dim},
        "hnsw_index_present": hnsw,
        "mismatches": mismatches,
        "ok": not mismatches and missing == 0 and null_vecs == 0,
    }


@dataclass
class BackfillSummary:
    missing: int = 0
    embedded: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"missing": self.missing, "embedded": self.embedded,
                "failed": self.failed, "errors": self.errors[:20]}


def backfill_missing_embeddings(store: Any, embedder: Any, *,
                                limit: int | None = None,
                                batch_size: int = 32) -> BackfillSummary:
    """Embed ONLY records that lack a vector (row missing, or NULL embedding).
    Never touches a valid stored vector."""
    summary = BackfillSummary()
    if embedder is None:
        summary.errors.append("no embedder configured")
        return summary
    sql = """
        SELECT vk.id, vk.title, vk.description, vk.root_cause,
               vk.preconditions, vk.impact, vk.remediation
        FROM vulnerability_knowledge vk
        LEFT JOIN knowledge_embeddings ke ON ke.knowledge_id = vk.id
        WHERE ke.id IS NULL OR ke.embedding IS NULL
        ORDER BY vk.id
    """
    params: list[Any] = []
    if limit:
        sql += " LIMIT %s"
        params.append(int(limit))
    with store._connect() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        rows = [dict(r) for r in cur.fetchall()]
    summary.missing = len(rows)
    dim = int(getattr(store, "vector_dim", 2048))
    model = getattr(embedder, "name", "embedder")
    for i in range(0, len(rows), batch_size):
        batch = rows[i:i + batch_size]
        texts = [embedding_body(r) for r in batch]
        try:
            vecs = embedder.embed(texts)
        except Exception as exc:  # noqa: BLE001 - report, never fake
            summary.failed += len(batch)
            summary.errors.append(f"batch {i // batch_size}: embed {exc}")
            continue
        try:
            with store._connect() as conn, conn.cursor() as cur:
                for row, vec in zip(batch, vecs, strict=False):
                    if not vec:
                        summary.failed += 1
                        continue
                    payload = [float(x) for x in vec[:dim]]
                    cur.execute(
                        "UPDATE knowledge_embeddings SET embedding=%s, "
                        "embedding_model=%s, dimensions=%s, content_hash=%s, "
                        "created_at=now() WHERE knowledge_id=%s AND embedding IS NULL",
                        (payload, model, len(vec), content_hash_of(
                            embedding_body(row)), row["id"]))
                    if cur.rowcount == 0:
                        cur.execute(
                            "INSERT INTO knowledge_embeddings (knowledge_id, "
                            "embedding, embedding_model, dimensions, content_hash) "
                            "VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                            (row["id"], payload, model, len(vec),
                             content_hash_of(embedding_body(row))))
                    summary.embedded += 1
        except Exception as exc:  # noqa: BLE001
            summary.failed += len(batch)
            summary.errors.append(f"batch {i // batch_size}: db {exc}")
    return summary
