"""Neon PostgreSQL persistence for the security knowledge base.

AgentSafe G+ — the storage/retrieval layer. Neon is NOT a source of better
detection; it persists the same high-quality, provenance-carrying records the
in-repo JSONL ships, adds real full-text lexical retrieval (PostgreSQL
ts_rank) and a pgvector slot for semantic retrieval (Stage 2 embeddings).

Resilience contract:
- `get_knowledge_store(settings)` returns a Neon-backed store when the DSN is
  configured and reachable; otherwise it returns the shipped JSONL
  `KnowledgeBase` (in-memory lexical). An audit is NEVER blocked by the
  retrieval layer — a Neon outage degrades to the dataset file, never to a
  failed audit.
- psycopg is imported lazily so the package still imports when the driver is
  absent (e.g. a minimal local venv). Embeddings are populated lazily (Stage 2)
  and NULL vectors simply disable the vector leg of hybrid search.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentsafe.knowledge.kb import KnowledgeBase

logger = logging.getLogger("agentSAFE.knowledge.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS kb_records (
    id            text PRIMARY KEY,
    version       int  NOT NULL,
    source        text,
    url           text,
    license       text,
    protocol_type text,
    category      text,
    mechanism     text,
    root_cause    text,
    preconditions   jsonb,
    exploit_sequence jsonb,
    impact        text,
    remediation   text,
    code_evidence text,
    keywords      jsonb,
    embedding     vector({DIM}),
    created_at    timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS kb_records_category ON kb_records (category);
CREATE INDEX IF NOT EXISTS kb_records_hnsw ON kb_records
    USING hnsw (embedding vector_cosine_ops);
"""

_TS_COLUMNS = (
    "coalesce(mechanism,'') || ' ' || coalesce(root_cause,'') || ' ' || "
    "coalesce(remediation,'') || ' ' || "
    "coalesce(keywords::text,'') || ' ' || coalesce(category,'') || ' ' || "
    "coalesce(protocol_type,'')"
)
_TSVEC = f"to_tsvector('english', {_TS_COLUMNS})"


def _row_to_record(row: Any) -> dict[str, Any]:
    # psycopg3 with dict_row yields dict; tolerate a tuple by zipping to
    # synthetic keys (best-effort) so a bad row_factory never crashes.
    if isinstance(row, dict):
        r = dict(row)
    elif hasattr(row, "_asdict"):
        r = dict(row._asdict())
    else:
        r = {str(i): v for i, v in enumerate(row)}
    for k in ("preconditions", "exploit_sequence", "keywords"):
        if isinstance(r.get(k), str):
            try:
                r[k] = json.loads(r[k])
            except (ValueError, TypeError):
                r[k] = []
    score = r.pop("score", None)
    r.pop("embedding", None)  # never ship the raw vector to an LLM
    r["_neon_score"] = score
    return r


@dataclass
class NeonKnowledgeStore:
    """Read/write Neon-backed KB store with hybrid (lexical + vector) search.

    If `embedding_model` is provided, search is hybrid (ts_rank weighted with
    cosine similarity over `embedding`). Without a model, retrieval is pure
    PostgreSQL full-text lexical ranking.
    """

    dsn: str
    vector_dim: int = 384
    embedding_model: Any = None  # callable(text)->list[float] (Stage 2 lazy)

    def _connect(self):
        import psycopg

        from psycopg.rows import dict_row

        return psycopg.connect(self.dsn, connect_timeout=15, row_factory=dict_row)

    def migrate(self) -> None:
        with self._connect() as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(
                    "create extension if not exists vector"
                    if "postgresql" in self.dsn else
                    "create extension if not exists vector")
                cur.execute(_SCHEMA.replace("{DIM}", str(self.vector_dim)))

    # -- ingestion -----------------------------------------------------------
    def seed_from_jsonl(self, path: str | Path) -> int:
        """Idempotent upsert of a dataset file. Returns number of records
        written (inserted or updated)."""
        records = KnowledgeBase.load(path).records
        if not records:
            return 0
        vectors: dict[str, list[float]] = {}
        if self.embedding_model is not None:
            for r in records:
                emb = self._embed(r)
                if emb:
                    vectors[r["id"]] = emb
        n = 0
        with self._connect() as conn:
            with conn.cursor() as cur:
                for r in records:
                    vec = vectors.get(r["id"])
                    cur.execute(
                        """
                        INSERT INTO kb_records (
                            id, version, source, url, license, protocol_type,
                            category, mechanism, root_cause, preconditions,
                            exploit_sequence, impact, remediation,
                            code_evidence, keywords, embedding
                        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (id) DO UPDATE SET
                            version = EXCLUDED.version,
                            mechanism = EXCLUDED.mechanism,
                            root_cause = EXCLUDED.root_cause,
                            preconditions = EXCLUDED.preconditions,
                            exploit_sequence = EXCLUDED.exploit_sequence,
                            impact = EXCLUDED.impact,
                            remediation = EXCLUDED.remediation,
                            keywords = EXCLUDED.keywords,
                            embedding = EXCLUDED.embedding,
                            url = EXCLUDED.url,
                            category = EXCLUDED.category
                        """,
                        (
                            r["id"], r.get("version", 1), r.get("source"),
                            r.get("url"), r.get("license"),
                            r.get("protocol_type"), r.get("category"),
                            r.get("mechanism"), r.get("root_cause"),
                            json.dumps(r.get("preconditions", [])),
                            json.dumps(r.get("exploit_sequence", [])),
                            r.get("impact"), r.get("remediation"),
                            r.get("code_evidence"), json.dumps(r.get("keywords", [])),
                            vec,
                        ),
                    )
                    n += 1
        logger.info("neon kb seeded/upserted %d records", n)
        return n

    def _embed(self, record: dict[str, Any]) -> list[float] | None:
        try:
            text = " ".join([
                record.get("mechanism", ""), record.get("root_cause", ""),
                " ".join(record.get("preconditions", [])),
                " ".join(record.get("keywords", [])),
                record.get("category", ""), record.get("protocol_type", ""),
            ])
            emb = self.embedding_model(text)
            if emb and len(emb) >= 8:
                return [float(x) for x in emb[: self.vector_dim]]
        except Exception as exc:  # pragma: no cover - model is optional
            logger.warning("embedding failed for %s: %s", record.get("id"), exc)
        return None

    # -- retrieval -------------------------------------------------------------
    def search(self, query: str, focus: str = "", limit: int = 3) -> list[dict[str, Any]]:
        """Hybrid search: PostgreSQL full-text ts_rank as the lexical leg, plus
        vector cosine when `embedding_model` was provided at seed time. Records
        with no embedding still participate via the lexical leg."""
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
                            SELECT *, (1 - (embedding <=> %s::vector))
                                     * ts_rank({_TSVEC}, websearch_to_tsquery('english', %s))
                                     AS score
                            FROM kb_records
                            WHERE embedding IS NOT NULL
                              AND websearch_to_tsquery('english', %s) IS NOT NULL
                            ORDER BY score DESC
                            LIMIT %s
                            """,
                            (qv, query, query, limit),
                        )
                        rows = cur.fetchall()
                        if rows:
                            return [_row_to_record(r) for r in rows]
                # Lexical-only fallback (no model, or vector query empty).
                cur.execute(
                    f"""
                    SELECT *, ts_rank({_TSVEC}, websearch_to_tsquery('english', %s))
                              AS score
                    FROM kb_records
                    WHERE websearch_to_tsquery('english', %s) IS NOT NULL
                    ORDER BY score DESC
                    LIMIT %s
                    """,
                    (query, query, limit),
                )
                return [_row_to_record(r) for r in cur.fetchall()]

    @property
    def records(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM kb_records ORDER BY id")
                return [_row_to_record(r) for r in cur.fetchall()]

    def count(self) -> int:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM kb_records")
                row = cur.fetchone()
                if isinstance(row, dict):
                    return int(row.get("count", 0))
                return int(row[0]) if row else 0


def get_knowledge_store(
    settings: Any, dataset_path: str | Path | None = None
) -> Any:
    """Return the best available knowledge store for the configured runtime.

    Order: configured 'neon' + reachable + seeded -> NeonKnowledgeStore;
    otherwise -> the shipped JSONL KnowledgeBase. A Neon outage degrades to
    the dataset file (same records), never to a failed audit.
    """
    try:
        mode = getattr(settings, "resolved_kb_storage", "jsonl")
        dsn = getattr(settings, "NEON_DATABASE_URL", "").strip()
    except Exception:
        mode, dsn = "jsonl", ""

    if mode == "neon" and dsn:
        store = NeonKnowledgeStore(dsn=dsn, vector_dim=getattr(
            settings, "KB_VECTOR_DIM", 384))
        try:
            store.migrate()
            if store.count() == 0:
                path = dataset_path or (
                    Path(__file__).parent / "dataset" / f"v1.jsonl")
                store.seed_from_jsonl(path)
            if store.count() > 0:
                logger.info("knowledge store: neon (%d records)", store.count())
                return store
            logger.warning("neon kb empty after seed; falling back to jsonl")
        except Exception as exc:
            logger.warning(
                "neon kb unavailable (%s); falling back to jsonl dataset", exc)

    return KnowledgeBase.load_default()