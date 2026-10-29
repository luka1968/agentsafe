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
        # extra provenance/severity surfaces (renderer keeps its keys;
        # these enrich retrieval output without breaking consumers)
        "severity": r.get("severity"),
        "title": r.get("title"),
        "external_record_id": r.get("external_record_id"),
        "source_url": r.get("source_url") or r.get("source_url_explicit"),
        "metadata": r.get("metadata") or {},
    }
    out["_neon_score"] = r.pop("score", None)
    return out


def _connect(dsn: str, *, retries: int = 3):
    import time as _t

    import psycopg

    from psycopg.rows import dict_row

    last: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            return psycopg.connect(dsn, connect_timeout=15,
                                   row_factory=dict_row)
        except Exception as exc:
            last = exc
            if attempt < retries:
                _t.sleep(1.5 * attempt)
    raise last  # type: ignore[misc]


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
                # Dimension change: drop stale embeddings so the HNSW index is
                # rebuilt with the configured dim (records stay; vectors reseed).
                cur.execute(
                    "SELECT a.atttypmod AS dim FROM pg_attribute a "
                    "JOIN pg_class c ON c.oid=a.attrelid "
                    "WHERE c.relname='knowledge_embeddings' AND a.attname='embedding'")
                row = cur.fetchone()
                if row:
                    old_dim = row.get("dim") if isinstance(row, dict) else row[0]
                    if old_dim and int(old_dim) != int(self.vector_dim):
                        logger.info("embedding dim %s -> %s; dropping stale vectors",
                                    old_dim, self.vector_dim)
                        cur.execute("DROP TABLE knowledge_embeddings CASCADE")
                cur.execute(_SCHEMA.replace("{DIM}", str(self.vector_dim)))
                # HNSW has a hard 2000-dim cap in pgvector. For higher dims
                # (e.g. nemotron 2048) skip the index — exact sequential-scan
                # cosine is used, which is MORE accurate (no ANN approximation).
                if int(self.vector_dim) <= 2000:
                    cur.execute(
                        "CREATE INDEX IF NOT EXISTS ke_hnsw_idx "
                        "ON knowledge_embeddings USING hnsw "
                        "(embedding vector_cosine_ops)")

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

    def _leg_vector(self, query: str, limit: int) -> list[dict[str, Any]]:
        """Vector-only retrieval leg (pgvector cosine). Raises/None-safe:
        returns [] when no embedder or embedding fails."""
        if self.embedding_model is None:
            return []
        try:
            if hasattr(self.embedding_model, "embed_query"):
                vec = self.embedding_model.embed_query(query)
            else:
                vec = self.embedding_model(query)  # type: ignore[operator]
            if not vec:
                return []
            qv = [float(x) for x in vec[: self.vector_dim]]
            with self._connect() as conn:
                with conn.cursor() as cur:
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
                    return list(cur.fetchall())
        except Exception as exc:
            logger.warning("vector leg failed (%s)", exc)
            from agentsafe.metrics import get_metrics

            get_metrics().incr("retrieval_vector_fallback")
            return []

    def _leg_lexical(self, query: str, limit: int) -> list[dict[str, Any]]:
        """Lexical-only retrieval leg (PostgreSQL ts_rank; documented NOT
        BM25)."""
        with self._connect() as conn:
            with conn.cursor() as cur:
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
                return list(cur.fetchall())

    def search_leg_vector(self, query: str, limit: int = 3) -> list[dict[str, Any]]:
        """Benchmark/ablation surface: vector-only retrieval."""
        return [_row_to_record(r) for r in self._leg_vector(query, limit)]

    def search_leg_lexical(self, query: str, limit: int = 3) -> list[dict[str, Any]]:
        """Benchmark/ablation surface: lexical-only retrieval."""
        return [_row_to_record(r) for r in self._leg_lexical(query, limit)]

    def search(self, query: str, focus: str = "", limit: int = 3) -> list[dict[str, Any]]:
        """Hybrid retrieval: pgvector cosine + PostgreSQL full-text, fused with
        Reciprocal Rank Fusion (RRF): score(d) = sum 1/(K + rank_i(d)), K=60
        (standard RRF constant). Rank-fusion is documented, not BM25: full-text
        uses ts_rank, which is NOT BM25 — no such claim is made.
        Falls back to lexical-only when no embedder is configured."""
        if not query or not query.strip():
            return []
        import time as _t

        from agentsafe.metrics import get_metrics

        _m = get_metrics()
        _t0 = _t.monotonic()
        K = 60
        vec_hits: list[tuple[Any, float]] = []  # (record, rank0-based)
        lex_hits: list[tuple[Any, float]] = []
        if self.embedding_model is not None:
            vec_hits = [(r, i) for i, r in enumerate(self._leg_vector(query, limit * 3))]
        lex_hits = [(r, i) for i, r in enumerate(self._leg_lexical(query, limit * 3))]
        if not vec_hits and not lex_hits:
            return []
        if self.embedding_model is not None and not vec_hits:
            from agentsafe.metrics import get_metrics

            get_metrics().incr("retrieval_vector_fallback")
        # RRF fusion keyed on content_hash (stable dedup across legs)
        def key(r: dict[str, Any]) -> str:
            return str(r.get("content_hash") or r.get("id") or id(r))
        rrf: dict[str, float] = {}
        best: dict[str, dict[str, Any]] = {}
        legs: dict[str, list[int]] = {}
        for hits in (vec_hits, lex_hits):
            for row, rank in hits:
                k = key(row)
                rrf[k] = rrf.get(k, 0.0) + 1.0 / (K + rank + 1)
                legs.setdefault(k, []).append(rank)
                if k not in best:
                    best[k] = row
        fused = sorted(best.values(), key=lambda r: rrf[key(r)], reverse=True)
        out = []
        for r in fused[:limit]:
            rec = _row_to_record(r)
            rec["_retrieval"] = {
                "rrf_score": round(rrf[key(r)], 6),
                "vector_rank": min(legs[key(r)]) if key(r) in legs else None,
                "matched_legs": sum(1 for h in (vec_hits, lex_hits)
                                    if any(key(x[0]) == key(r) for x in h)),
            }
            out.append(rec)
        _m.incr("retrieval_calls")
        _m.record("retrieval_latency_ms", (_t.monotonic() - _t0) * 1000.0)
        return out

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
            from agentsafe.metrics import get_metrics

            get_metrics().incr("retrieval_neon_fallback")
        except Exception as exc:
            logger.warning("neon kb unavailable (%s); falling back to jsonl", exc)
            from agentsafe.metrics import get_metrics

            get_metrics().incr("retrieval_neon_fallback")
    return KnowledgeBase.load_default()


