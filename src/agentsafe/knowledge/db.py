"""Neon PostgreSQL knowledge-base persistence — AgentSafe G+.

Normalized, versioned, migration-safe schema (per G+ Stage 1 spec):

    knowledge_sources        source registry (name PK, version, URL, license,
                             import_status, record_counts, metadata, timestamps)
    vulnerability_knowledge  normalized vulnerability/incident records with full
                             provenance + content_hash (dedup) + affected code
    knowledge_embeddings     vector embeddings keyed to a knowledge record +
                             model metadata + content hash
    knowledge_import_jobs     resumable import jobs (status, progress,
                             checkpoint, retries, failure_info)

The old Stage-1 flat `kb_records` table is dropped in migrate() (dev-only table;
the new schema supersedes it). `NeonKnowledgeStore` is the READ interface that
agents/renderer depend on; it reshapes the normalized rows onto the renderer's
expected keys (id, category, protocol_type, mechanism, root_cause, preconditions,
impact, remediation, source, url).

Resilience: `get_knowledge_store` never lets a Neon outage block an audit — it
falls back to the shipped JSONL dataset.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Callable, Iterable

from agentsafe.knowledge.kb import KnowledgeBase

logger = logging.getLogger("agentSAFE.knowledge.db")

_DROP_OLD = "DROP TABLE IF EXISTS kb_records"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS knowledge_sources (
    name            text PRIMARY KEY,
    version         text,
    url             text,
    license         text,
    import_status   text DEFAULT 'pending',   -- pending|importing|done|failed
    record_counts   int  DEFAULT 0,
    metadata        jsonb DEFAULT '{}'::jsonb,
    created_at      timestamptz DEFAULT now(),
    updated_at      timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS vulnerability_knowledge (
    id                 bigserial PRIMARY KEY,
    source_id          text REFERENCES knowledge_sources(name) ON DELETE CASCADE,
    external_record_id text,
    title              text,
    description        text,
    category           text,
    severity           text,
    protocol_domain    text,
    affected_contract  text,
    affected_function  text,
    vulnerable_code    text,
    corrected_code     text,
    root_cause         text,
    preconditions      jsonb DEFAULT '[]'::jsonb,
    attack_scenario    text,
    impact             text,
    remediation        text,
    source_url         text,
    content_hash       text NOT NULL UNIQUE,
    metadata           jsonb DEFAULT '{}'::jsonb,
    created_at         timestamptz DEFAULT now(),
    updated_at         timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS vk_source_idx  ON vulnerability_knowledge (source_id);
CREATE INDEX IF NOT EXISTS vk_category_idx ON vulnerability_knowledge (category);
CREATE INDEX IF NOT EXISTS vk_hash_idx    ON vulnerability_knowledge (content_hash);

CREATE TABLE IF NOT EXISTS knowledge_embeddings (
    id              bigserial PRIMARY KEY,
    knowledge_id    bigint REFERENCES vulnerability_knowledge(id) ON DELETE CASCADE,
    embedding       vector({DIM}),
    embedding_model text,
    dimensions      int,
    content_hash    text,
    created_at      timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ke_hnsw_idx ON knowledge_embeddings
    USING hnsw (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS ke_knowledge_idx ON knowledge_embeddings (knowledge_id);

CREATE TABLE IF NOT EXISTS knowledge_import_jobs (
    id          bigserial PRIMARY KEY,
    source_id   text REFERENCES knowledge_sources(name) ON DELETE CASCADE,
    status      text DEFAULT 'pending',   -- pending|running|done|failed
    progress    int DEFAULT 0,
    checkpoint  jsonb DEFAULT '{}'::jsonb,  -- resumable cursor
    retries     int DEFAULT 0,
    failure_info jsonb DEFAULT '{}'::jsonb,
    created_at  timestamptz DEFAULT now(),
    updated_at  timestamptz DEFAULT now()
);
"""


def content_hash_of(text: str) -> str:
    """Stable SHA-256 content hash used for dedup across sources."""
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _row_to_record(row: Any) -> dict[str, Any]:
    """Reshape a normalized vulnerability_knowledge row (joined with its source)
    onto the renderer's expected keys. Extra fields are dropped."""
    if isinstance(row, dict):
        r = dict(row)
    elif hasattr(row, "_asdict"):
        r = dict(row._asdict())
    else:
        r = {str(i): v for i, v in enumerate(row)}
    for k in ("preconditions", "metadata"):
        if isinstance(r.get(k), str):
            try:
                r[k] = json.loads(r[k])
            except (ValueError, TypeError):
                r[k] = [] if k == "preconditions" else {}
    out = {
        "id": r.get("external_record_id") or str(r.get("id") or ""),
        "category": r.get("category"),
        "protocol_type": r.get("protocol_domain"),
        "mechanism": r.get("description") or r.get("title"),
        "root_cause": r.get("root_cause"),
        "preconditions": r.get("preconditions") or [],
        "impact": r.get("impact"),
        "remediation": r.get("remediation"),
        "source": r.get("source_name"),
        "url": r.get("source_url") or r.get("source_url_explicit"),
    }
    out["_neon_score"] = r.pop("score", None)
    return out


def _connect(dsn: str):
    import psycopg

    from psycopg.rows import dict_row

    return psycopg.connect(dsn, connect_timeout=15, row_factory=dict_row)


# ---------------------------------------------------------------------------
# NeonKnowledgeStore — read interface (search / records / count)
# ---------------------------------------------------------------------------
class NeonKnowledgeStore:
    def __init__(self, dsn: str, vector_dim: int = 384,
                 embedding_model: Callable[[str], list[float]] | None = None):
        self.dsn = dsn
        self.vector_dim = vector_dim
        self.embedding_model = embedding_model

    def _connect(self):
        return _connect(self.dsn)

    def migrate(self) -> None:
        with self._connect() as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("create extension if not exists vector")
                cur.execute(_DROP_OLD)
                cur.execute(_SCHEMA.replace("{DIM}", str(self.vector_dim)))

    _VK_SELECT = """
        SELECT vk.*, src.name AS source_name, src.url AS source_url_explicit
        FROM vulnerability_knowledge vk
        JOIN knowledge_sources src ON src.name = vk.source_id
    """

    _TS_COLS = (
        "coalesce(vk.description,'') || ' ' || coalesce(vk.root_cause,'') || ' ' || "
        "coalesce(vk.remediation,'') || ' ' || "
        "coalesce(vk.metadata::text,'') || ' ' || "
        "coalesce(vk.category,'') || ' ' || coalesce(vk.protocol_domain,'')"
    )

    def search(self, query: str, focus: str = "", limit: int = 3) -> list[dict[str, Any]]:
        if not query or not query.strip():
            return []
        with self._connect() as conn:
            with conn.cursor() as cur:
                if self.embedding_model is not None:
                    vec = self.embedding_model(query)
                    if vec:
                        qv = [float(x) for x in vec[: self.vector_dim]]
                        cur.execute(
                            f"""
                            SELECT vk.*, src.name AS source_name,
                                   src.url AS source_url_explicit,
                                   (1 - (ke.embedding <=> %s::vector)) AS score
                            FROM knowledge_embeddings ke
                            JOIN vulnerability_knowledge vk ON vk.id = ke.knowledge_id
                            JOIN knowledge_sources src ON src.name = vk.source_id
                            WHERE ke.embedding IS NOT NULL
                            ORDER BY score DESC
                            LIMIT %s
                            """,
                            (qv, limit),
                        )
                        rows = cur.fetchall()
                        if rows:
                            return [_row_to_record(r) for r in rows]
                cur.execute(
                    f"""
                    SELECT vk.*, src.name AS source_name,
                           src.url AS source_url_explicit,
                           ts_rank(to_tsvector('english', {self._TS_COLS}),
                                   websearch_to_tsquery('english', %s)) AS score
                    FROM vulnerability_knowledge vk
                    JOIN knowledge_sources src ON src.name = vk.source_id
                    WHERE websearch_to_tsquery('english', %s) IS NOT NULL
                    ORDER BY score DESC
                    LIMIT %s
                    """,
                    (query, query, limit),
                )
                return [_row_to_record(r) for r in cur.fetchall()]

    def records(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(self._VK_SELECT + " ORDER BY vk.id")
                return [_row_to_record(r) for r in cur.fetchall()]

    def count(self) -> int:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM vulnerability_knowledge")
                row = cur.fetchone()
                return int(row.get("count", 0)) if isinstance(row, dict) else int(row[0])

    # -- job helpers (used by the import pipeline) ---------------------------
    def record_counts(self) -> int:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM knowledge_sources")
                row = cur.fetchone()
                return int(row.get("count", 0)) if isinstance(row, dict) else int(row[0])

    def source_status(self, name: str) -> str | None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT import_status FROM knowledge_sources WHERE name=%s", (name,))
                row = cur.fetchone()
                return row.get("import_status") if row else None


def get_knowledge_store(settings: Any,
                        dataset_path: str | Path | None = None) -> Any:
    """Best available store for the runtime; never blocks an audit on a Neon
    outage (falls back to the shipped JSONL KnowledgeBase)."""
    try:
        mode = getattr(settings, "resolved_kb_storage", "jsonl")
        dsn = getattr(settings, "NEON_DATABASE_URL", "").strip()
    except Exception:
        mode, dsn = "jsonl", ""
    if mode == "neon" and dsn:
        store = NeonKnowledgeStore(
            dsn=dsn, vector_dim=getattr(settings, "KB_VECTOR_DIM", 384))
        try:
            store.migrate()
            if store.count() == 0:
                from agentsafe.knowledge.importers import import_jsonl_dataset
                path = dataset_path or (Path(__file__).parent / "dataset"
                                        / f"v1.jsonl")
                import_jsonl_dataset(store, path)
            if store.count() > 0:
                logger.info("knowledge store: neon (%d records)", store.count())
                return store
            logger.warning("neon kb empty after seed; falling back to jsonl")
        except Exception as exc:
            logger.warning("neon kb unavailable (%s); falling back to jsonl", exc)
    return KnowledgeBase.load_default()


