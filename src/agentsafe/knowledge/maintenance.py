"""Knowledge-base maintenance: provenance repair, embedding integrity, counts.

These are the non-content upkeep operations an enrichment pass leaves behind:

  * backfill_provenance     — restore per-record provenance keys (contest,
                              issue_id, source_platform) that were dropped by
                              an earlier import double-normalization. The keys
                              are derived deterministically from the record's
                              existing external id (``<platform>:<contest>:
                              <issue>``); nothing is invented and no URL is
                              fabricated.
  * refresh_source_counts   — keep knowledge_sources.record_counts in sync with
                              the actual row counts (bookkeeping only).
  * backup_embeddings       — copy the current vectors of affected records into
                              an additive ``knowledge_embeddings_backup`` table
                              BEFORE they are replaced, so a refresh is
                              reversible.
  * refresh_embeddings      — re-embed records whose stored vector hash no
                              longer matches ``content_hash_of(
                              embedding_body(row))`` (i.e. enrichment changed
                              the text that is embedded). Only genuinely stale
                              vectors are touched; unchanged vectors are never
                              discarded.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from agentsafe.knowledge.db import content_hash_of
from agentsafe.knowledge.importers import embedding_body

logger = logging.getLogger("agentSAFE.knowledge.maintenance")

_KNOWN_PLATFORMS = ("code4rena", "sherlock", "codehawks")


# ---------------------------------------------------------------------------
# provenance
# ---------------------------------------------------------------------------
def parse_external_id(external_record_id: str | None) -> dict[str, str] | None:
    """Split ``<platform>:<contest>:<issue>[#chunkN]`` deterministically.

    Returns None when the id is not in the recognised contest-report shape
    (e.g. a curated dataset row), so we never guess provenance."""
    if not external_record_id:
        return None
    base = str(external_record_id).split("#chunk", 1)[0]
    parts = base.split(":")
    if len(parts) < 3:
        return None
    platform = parts[0].strip().lower()
    if platform not in _KNOWN_PLATFORMS:
        return None
    issue = parts[-1].strip()
    contest = ":".join(parts[1:-1]).strip()
    if not contest or not issue:
        return None
    return {"source_platform": platform, "contest": contest, "issue_id": issue}


@dataclass
class ProvenanceSummary:
    scanned: int = 0
    updated: int = 0
    already_complete: int = 0
    unrecognised: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanned": self.scanned, "updated": self.updated,
            "already_complete": self.already_complete,
            "unrecognised": self.unrecognised, "errors": self.errors[:20],
        }


def backfill_provenance(store: Any, *, sources: Iterable[str],
                        limit: int | None = None) -> ProvenanceSummary:
    """Fill missing contest/issue_id/source_platform metadata from the external
    id. Only absent keys are written; existing values are never overwritten."""
    summary = ProvenanceSummary()
    sources = list(sources)
    sql = ("SELECT id, external_record_id, metadata "
           "FROM vulnerability_knowledge WHERE source_id = ANY(%s) ORDER BY id")
    params: list[Any] = [sources]
    if limit:
        sql += " LIMIT %s"
        params.append(int(limit))
    with store._connect() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        rows = list(cur.fetchall())
    # Compute updates locally, then write in batches over FRESH connections.
    # A single long-lived connection drops on Neon's pooler; per-row connects
    # are far too slow. executemany pipelines each batch in one round trip.
    pending: list[tuple[str, int]] = []
    for row in rows:
        summary.scanned += 1
        parsed = parse_external_id(row.get("external_record_id"))
        if not parsed:
            summary.unrecognised += 1
            continue
        md = dict(row.get("metadata") or {}) \
            if isinstance(row.get("metadata"), dict) else {}
        changed = False
        for k, v in parsed.items():
            if not md.get(k):
                md[k] = v
                changed = True
        if not changed:
            summary.already_complete += 1
            continue
        pending.append((json.dumps(md), row["id"]))
    for i in range(0, len(pending), 200):
        batch = pending[i:i + 200]
        try:
            with store._connect() as conn, conn.cursor() as cur:
                cur.executemany(
                    "UPDATE vulnerability_knowledge SET metadata = %s, "
                    "updated_at = now() WHERE id = %s", batch)
            summary.updated += len(batch)
        except Exception as exc:  # noqa: BLE001 - rerun finishes (idempotent)
            summary.errors.append(f"batch {i // 200}: {exc}")
    return summary


# Set-based parent -> child intelligence propagation. Idempotent and robust:
# fills only empty child fields, so it can run after every enrichment pass and
# catch chunk children whose per-parent copy was interrupted.
_PROPAGATE_SQL = """
    UPDATE vulnerability_knowledge c
    SET root_cause = COALESCE(c.root_cause, p.root_cause),
        attack_scenario = COALESCE(c.attack_scenario, p.attack_scenario),
        exploit_sequence = COALESCE(c.exploit_sequence, p.exploit_sequence),
        subcategory = COALESCE(c.subcategory, p.subcategory),
        category = COALESCE(c.category, p.category),
        swc_id = COALESCE(c.swc_id, p.swc_id),
        confidence = COALESCE(c.confidence, p.confidence),
        preconditions = CASE WHEN c.preconditions IS NULL
                              OR c.preconditions = '[]'::jsonb
                             THEN p.preconditions ELSE c.preconditions END,
        tags = CASE WHEN c.tags IS NULL OR c.tags = '[]'::jsonb
                    THEN p.tags ELSE c.tags END,
        verification_status = COALESCE(c.verification_status,
                                       p.verification_status),
        metadata = CASE WHEN p.metadata ? 'llm_enrichment'
                         AND NOT (c.metadata ? 'llm_enrichment')
                        THEN c.metadata || jsonb_build_object(
                             'llm_enrichment',
                             p.metadata -> 'llm_enrichment')
                        ELSE c.metadata END,
        updated_at = now()
    FROM vulnerability_knowledge p
    WHERE c.source_id = p.source_id
      AND c.source_id = ANY(%s)
      AND c.metadata ->> 'parent_external_id' = p.external_record_id
      AND p.metadata ->> 'parent_external_id' IS NULL
      AND p.metadata ? 'llm_enrichment'
      AND (c.root_cause IS NULL OR c.attack_scenario IS NULL
           OR c.preconditions IS NULL OR c.preconditions = '[]'::jsonb)
"""


def propagate_parent_intelligence(store: Any, *, sources: Iterable[str]) -> int:
    """Copy enriched-parent structured fields onto still-empty chunk children.
    Returns the number of child rows updated."""
    with store._connect() as conn, conn.cursor() as cur:
        cur.execute(_PROPAGATE_SQL, (list(sources),))
        return int(cur.rowcount or 0)


# ---------------------------------------------------------------------------
# source counts
# ---------------------------------------------------------------------------
def refresh_source_counts(store: Any) -> dict[str, int]:
    """Set knowledge_sources.record_counts to the real per-source row count."""
    with store._connect() as conn, conn.cursor() as cur:
        cur.execute("UPDATE knowledge_sources SET record_counts = 0")
        cur.execute(
            "UPDATE knowledge_sources ks SET record_counts = sub.c, "
            "updated_at = now() "
            "FROM (SELECT source_id, count(*) c FROM vulnerability_knowledge "
            "      GROUP BY source_id) sub "
            "WHERE ks.name = sub.source_id"
        )
        cur.execute(
            "SELECT name, record_counts FROM knowledge_sources ORDER BY name")
        return {r["name"]: int(r["record_counts"] or 0) for r in cur.fetchall()}


# ---------------------------------------------------------------------------
# embeddings
# ---------------------------------------------------------------------------
def _ensure_backup_table(store: Any) -> None:
    dim = int(getattr(store, "vector_dim", 2048))
    with store._connect() as conn, conn.cursor() as cur:
        cur.execute(
            f"""
            CREATE TABLE IF NOT EXISTS knowledge_embeddings_backup (
                backup_id      bigserial PRIMARY KEY,
                knowledge_id   bigint,
                embedding      vector({dim}),
                embedding_model text,
                dimensions     int,
                content_hash   text,
                created_at     timestamptz,
                backed_up_at   timestamptz DEFAULT now()
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS keb_knowledge_idx "
            "ON knowledge_embeddings_backup (knowledge_id)")


def backup_embeddings(store: Any, knowledge_ids: Iterable[int]) -> int:
    """Snapshot the current vector rows for ``knowledge_ids`` (deduped by
    knowledge_id + content_hash) so a later replacement is reversible."""
    ids = [int(i) for i in knowledge_ids]
    if not ids:
        return 0
    _ensure_backup_table(store)
    with store._connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO knowledge_embeddings_backup
                (knowledge_id, embedding, embedding_model, dimensions,
                 content_hash, created_at)
            SELECT ke.knowledge_id, ke.embedding, ke.embedding_model,
                   ke.dimensions, ke.content_hash, ke.created_at
            FROM knowledge_embeddings ke
            WHERE ke.knowledge_id = ANY(%s)
              AND NOT EXISTS (
                  SELECT 1 FROM knowledge_embeddings_backup b
                  WHERE b.knowledge_id = ke.knowledge_id
                    AND b.content_hash IS NOT DISTINCT FROM ke.content_hash)
            """,
            (ids,),
        )
        return int(cur.rowcount or 0)


@dataclass
class ReembedSummary:
    scanned: int = 0
    stale: int = 0
    reembedded: int = 0
    backup_rows: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanned": self.scanned, "stale": self.stale,
            "reembedded": self.reembedded, "backup_rows": self.backup_rows,
            "failed": self.failed, "errors": self.errors[:20],
        }


def _stale_rows(store: Any, sources: list[str], limit: int | None
                ) -> list[dict[str, Any]]:
    sql = """
        SELECT vk.id, vk.title, vk.description, vk.root_cause,
               vk.preconditions, vk.impact, vk.remediation,
               ke.content_hash AS emb_hash
        FROM vulnerability_knowledge vk
        LEFT JOIN knowledge_embeddings ke ON ke.knowledge_id = vk.id
        WHERE vk.source_id = ANY(%s)
        ORDER BY vk.id
    """
    params: list[Any] = [sources]
    if limit:
        sql += " LIMIT %s"
        params.append(int(limit))
    with store._connect() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        return list(cur.fetchall())


def refresh_embeddings(store: Any, embedder: Any, *,
                       sources: Iterable[str],
                       limit: int | None = None,
                       batch_size: int = 32) -> ReembedSummary:
    """Re-embed only rows whose stored vector no longer matches their current
    embedding body. Existing (valid) vectors are never touched; replaced
    vectors are backed up first."""
    summary = ReembedSummary()
    if embedder is None:
        summary.errors.append("no embedder configured")
        return summary
    rows = _stale_rows(store, list(sources), limit)
    summary.scanned = len(rows)
    stale: list[tuple[dict[str, Any], str]] = []
    for r in rows:
        body = embedding_body(r)
        h = content_hash_of(body)
        if r.get("emb_hash") != h:
            stale.append((r, body))
    summary.stale = len(stale)
    if not stale:
        return summary

    summary.backup_rows = backup_embeddings(store, [r["id"] for r, _ in stale])

    dim = int(getattr(store, "vector_dim", 2048))
    for i in range(0, len(stale), batch_size):
        batch = stale[i:i + batch_size]
        texts = [body for _, body in batch]
        try:
            vecs = embedder.embed(texts)
        except Exception as exc:  # noqa: BLE001 - isolate the bad input(s)
            # A single oversized/invalid record makes the whole provider batch
            # fail (e.g. HTTP 422). Fall back to one-by-one so one bad row does
            # not block the rest of the batch.
            vecs = []
            for text in texts:
                try:
                    got = embedder.embed([text])
                    vecs.append(got[0] if got else None)
                except Exception as one:  # noqa: BLE001
                    vecs.append(None)
                    summary.errors.append(
                        f"batch {i // batch_size}: row embed {one}")
            if all(v is None for v in vecs):
                summary.failed += len(batch)
                summary.errors.append(f"batch {i // batch_size}: embed {exc}")
                continue
        try:
            with store._connect() as conn, conn.cursor() as cur:
                for (row, body), vec in zip(batch, vecs, strict=False):
                    if not vec:
                        summary.failed += 1
                        continue
                    cur.execute(
                        """
                        UPDATE knowledge_embeddings
                        SET embedding = %s, embedding_model = %s,
                            dimensions = %s, content_hash = %s, created_at = now()
                        WHERE knowledge_id = %s
                        """,
                        ([float(x) for x in vec[:dim]],
                         getattr(embedder, "name", "local"), len(vec),
                         content_hash_of(body), row["id"]),
                    )
                    if cur.rowcount == 0:
                        cur.execute(
                            """
                            INSERT INTO knowledge_embeddings
                                (knowledge_id, embedding, embedding_model,
                                 dimensions, content_hash)
                            VALUES (%s, %s, %s, %s, %s)
                            """,
                            (row["id"], [float(x) for x in vec[:dim]],
                             getattr(embedder, "name", "local"), len(vec),
                             content_hash_of(body)),
                        )
                    summary.reembedded += 1
        except Exception as exc:  # noqa: BLE001
            summary.failed += len(batch)
            summary.errors.append(f"batch {i // batch_size}: db {exc}")
    return summary
