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

import copy
import hashlib
import json
import logging
import threading
from collections import OrderedDict
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
    -- Category A (real-world case) organization columns. Added additively:
    -- kb_group assigns the record to one of the six KB main categories
    -- (A = real-world vulnerability cases); verification_status marks how
    -- the stored fields were produced (curated | source | heuristic);
    -- license_status / commercial_use carry per-record reuse terms.
    kb_group           text,
    verification_status text,
    license_status     text,
    commercial_use     text,
    -- Category B (attack-path knowledge) columns. Added additively for
    -- multi-call / cross-contract vulnerability discovery:
    --   attack_entry       where the attacker starts (first callable)
    --   call_sequence      ordered function call sequence (jsonb array)
    --   internal_calls     internal (same-contract) calls on the path
    --   external_calls     external (cross-contract) calls on the path
    --   state_vars         state variables the path reads/writes
    --   state_deps         state read/write dependency relations
    --   attacker_permissions roles/privileges the attacker must hold
    --   tx_conditions      transaction/ordering prerequisites
    --   cross_function_deps dependencies across functions
    --   cross_contract_deps dependencies across contracts
    --   poc_reference      PoC link when available
    attack_entry       text,
    call_sequence      jsonb DEFAULT '[]'::jsonb,
    internal_calls     jsonb DEFAULT '[]'::jsonb,
    external_calls     jsonb DEFAULT '[]'::jsonb,
    state_vars         jsonb DEFAULT '[]'::jsonb,
    state_deps         jsonb DEFAULT '[]'::jsonb,
    attacker_permissions jsonb DEFAULT '[]'::jsonb,
    tx_conditions      jsonb DEFAULT '[]'::jsonb,
    cross_function_deps jsonb DEFAULT '[]'::jsonb,
    cross_contract_deps jsonb DEFAULT '[]'::jsonb,
    poc_reference      text,
    -- Category C (accounting-vulnerability) columns. Added additively for
    -- balance/share/debt/rounding formula-level knowledge:
    --   invariant             the accounting invariant that must hold
    --   incorrect_behavior    how the vulnerable formula deviates from it
    --   verification_evidence evidence the deviation is real (test, PoC, diff)
    invariant          text,
    incorrect_behavior text,
    verification_evidence text,
    -- Category D (oracle-vulnerability) columns. Added additively:
    --   oracle_type          chainlink|twap|spot|band|uniswap-v3|... (honest label)
    --   price_source         which feed/pair the price comes from
    --   freshness_requirements the staleness/deviation window that must hold
    --   price_validation     validation the vulnerable code fails to apply
    oracle_type        text,
    price_source       text,
    freshness_requirements text,
    price_validation   text,
    -- Category E (secure-code / false-positive) columns. Added additively:
    --   security_pattern     named pattern (CEI, ReentrancyGuard, ...)
    --   safe_code            the secure implementation example
    --   required_assumptions assumptions for the pattern to hold
    --   why_safe             reason the pattern is safe
    --   known_limitations    what the pattern does NOT cover
    --   related_vuln_classes vulnerability classes this pattern relates to
    --   fp_patterns          code shapes that LOOK vulnerable but are not
    --   evidence_required    what must be shown before reporting a finding
    security_pattern  text,
    safe_code         text,
    required_assumptions text,
    why_safe          text,
    known_limitations text,
    related_vuln_classes text,
    fp_patterns       text,
    evidence_required text,
    -- Category F (vulnerability-verification / testing) columns. Added
    -- additively to teach agents how to PROVE or REFUTE a finding:
    --   verification_method   how to verify (foundry-poc|invariant|fuzz|trace)
    --   poc_code              the executable PoC / test harness
    --   expected_result       what a correct PoC must show
    --   confirmation_signals  evidence the vulnerability is real
    --   refutation_signals    evidence it is NOT exploitable (false positive)
    --   test_tooling          forge/hardhat/echidna/... used
    verification_method text,
    poc_code           text,
    expected_result    text,
    confirmation_signals text,
    refutation_signals text,
    test_tooling       text,
    -- Category F (Foundry PoC / exploit-validation) columns. Added
    -- additively for concrete, reproducible exploit records:
    --   attacker_contract           the attacker contract used in the PoC
    --   test_setup                  harness/deploy steps for the test
    --   required_initial_state      state the contract must start in
    --   expected_vulnerable_behavior what the PoC must demonstrate pre-fix
    --   expected_safe_behavior      expected post-remediation behavior
    --   test_result                 recorded outcome (reproduced/refuted)
    --   solc_version / foundry_version toolchain pins
    -- PoC repository/URL is stored in poc_reference; the vulnerable contract
    -- is affected_contract; the attack tx sequence is call_sequence; and
    -- verification_status marks curated|source|heuristic|reproduced.
    attacker_contract text,
    test_setup        text,
    required_initial_state text,
    expected_vulnerable_behavior text,
    expected_safe_behavior text,
    test_result        text,
    solc_version       text,
    foundry_version    text,
    -- Standardized knowledge-record fields (KB data-model spec). Added
    -- additively; existing columns are kept and reused where they already
    -- satisfy a logical field (see the mapping in _row_to_record):
    --   subcategory           finer-grained class within `category`
    --   vulnerability_id      external vulnerability identifier (CVE/C4 id)
    --   swc_id                Smart Contract Weakness Classification id
    --   exploit_sequence      explicit exploit walk-through (alias: attack_scenario)
    --   confidence            0..1 LLM/deterministic confidence score
    --   tags                  flexible keyword tags (jsonb array)
    subcategory        text,
    vulnerability_id   text,
    swc_id             text,
    exploit_sequence   text,
    confidence         double precision,
    tags               jsonb DEFAULT '[]'::jsonb,
    created_at         timestamptz DEFAULT now(),
    updated_at         timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS vk_source_idx  ON vulnerability_knowledge (source_id);
CREATE INDEX IF NOT EXISTS vk_category_idx ON vulnerability_knowledge (category);
CREATE INDEX IF NOT EXISTS vk_hash_idx    ON vulnerability_knowledge (content_hash);
CREATE INDEX IF NOT EXISTS vk_subcategory_idx ON vulnerability_knowledge (subcategory);
CREATE INDEX IF NOT EXISTS vk_vuln_id_idx      ON vulnerability_knowledge (vulnerability_id);
CREATE INDEX IF NOT EXISTS vk_severity_idx     ON vulnerability_knowledge (severity);
CREATE INDEX IF NOT EXISTS vk_tags_idx         ON vulnerability_knowledge USING gin (tags);

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
    # Category B jsonb columns: parse to lists when the driver returned a str.
    for k in ("call_sequence", "internal_calls", "external_calls", "state_vars",
              "state_deps", "attacker_permissions", "tx_conditions",
              "cross_function_deps", "cross_contract_deps", "tags"):
        if isinstance(r.get(k), str):
            try:
                r[k] = json.loads(r[k])
            except (ValueError, TypeError):
                r[k] = []
    # exploit_sequence may be stored as a JSON list string (v1/v2 legacy);
    # normalize to a list so consumers get the array, not its repr.
    if isinstance(r.get("exploit_sequence"), str) and r.get("exploit_sequence").startswith("["):
        try:
            parsed = json.loads(r["exploit_sequence"])
            if isinstance(parsed, list):
                r["exploit_sequence"] = parsed
        except (ValueError, TypeError):
            pass
    out = {
        "id": r.get("external_record_id") or str(r.get("id") or ""),
        "category": r.get("category"),
        "protocol_type": r.get("protocol_domain"),
        "mechanism": r.get("description") or r.get("title"),
        "root_cause": r.get("root_cause"),
        "preconditions": r.get("preconditions") or [],
        "impact": r.get("impact"),
        "remediation": r.get("remediation"),
        "attack_scenario": r.get("attack_scenario") or r.get("exploit_sequence"),
        "vulnerable_code": r.get("vulnerable_code"),
        "corrected_code": r.get("corrected_code"),
        "source": r.get("source_name"),
        "url": r.get("source_url") or r.get("source_url_explicit"),
        # extra provenance/severity surfaces (renderer keeps its keys;
        # these enrich retrieval output without breaking consumers)
        "severity": r.get("severity"),
        "title": r.get("title"),
        "external_record_id": r.get("external_record_id"),
        "source_url": r.get("source_url") or r.get("source_url_explicit"),
        "metadata": r.get("metadata") or {},
        # Category A organization surfaces
        "kb_group": r.get("kb_group"),        "verification_status": r.get("verification_status"),
        "license_status": r.get("license_status"),
        "commercial_use": r.get("commercial_use"),
        # Category B (attack-path) surfaces
        "attack_entry": r.get("attack_entry"),
        "call_sequence": r.get("call_sequence") or [],
        "internal_calls": r.get("internal_calls") or [],
        "external_calls": r.get("external_calls") or [],
        "state_vars": r.get("state_vars") or [],
        "state_deps": r.get("state_deps") or [],
        "attacker_permissions": r.get("attacker_permissions") or [],
        "tx_conditions": r.get("tx_conditions") or [],
        "cross_function_deps": r.get("cross_function_deps") or [],
        "cross_contract_deps": r.get("cross_contract_deps") or [],
        "poc_reference": r.get("poc_reference"),
        # Category C (accounting) surfaces
        "invariant": r.get("invariant"),
        "incorrect_behavior": r.get("incorrect_behavior"),
        "verification_evidence": r.get("verification_evidence"),
        # Category D (oracle) surfaces
        "oracle_type": r.get("oracle_type"),
        "price_source": r.get("price_source"),
        "freshness_requirements": r.get("freshness_requirements"),
        "price_validation": r.get("price_validation"),
        # Category E (secure-code / false-positive) surfaces
        "security_pattern": r.get("security_pattern"),
        "safe_code": r.get("safe_code"),
        "required_assumptions": r.get("required_assumptions"),
        "why_safe": r.get("why_safe"),
        "known_limitations": r.get("known_limitations"),
        "related_vuln_classes": r.get("related_vuln_classes"),
        "fp_patterns": r.get("fp_patterns"),
        "evidence_required": r.get("evidence_required"),
        # Category F (verification/testing) surfaces
        "verification_method": r.get("verification_method"),
        "poc_code": r.get("poc_code"),
        "expected_result": r.get("expected_result"),
        "confirmation_signals": r.get("confirmation_signals"),
        "refutation_signals": r.get("refutation_signals"),
        "test_tooling": r.get("test_tooling"),
        # Category F (Foundry PoC / exploit-validation) surfaces
        "attacker_contract": r.get("attacker_contract"),
        "test_setup": r.get("test_setup"),
        "required_initial_state": r.get("required_initial_state"),
        "expected_vulnerable_behavior": r.get("expected_vulnerable_behavior"),
        "expected_safe_behavior": r.get("expected_safe_behavior"),
        "test_result": r.get("test_result"),
        "solc_version": r.get("solc_version"),
        "foundry_version": r.get("foundry_version"),
        # Standardized KB data-model surfaces (spec field names + aliases so
        # consumers can read either the canonical name or the mapped column).
        "subcategory": r.get("subcategory"),
        "vulnerability_id": r.get("vulnerability_id"),
        "swc_id": r.get("swc_id"),
        "exploit_sequence": r.get("exploit_sequence") or r.get("attack_scenario"),
        "confidence": r.get("confidence"),
        "tags": r.get("tags") or [],
        "security_invariant": r.get("invariant"),
        "source_name": r.get("source_name") or r.get("source_id"),
        "source_license": r.get("license_status"),
        "commercial_use_allowed": r.get("commercial_use"),
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
                 embedding_model: Callable[[str], list[float]] | None = None,
                 cache_capacity: int = 256):
        self.dsn = dsn
        self.vector_dim = vector_dim
        self.embedding_model = embedding_model
        # Session-scoped retrieval cache (LRU, thread-safe). Eliminates
        # repeated expensive vector+Neon queries when the same probe string
        # is issued many times within one audit (specialists often search the
        # KB for the same keyword). Caching is pure performance: it never
        # changes results, counts, or payment semantics. A capacity cap keeps
        # memory bounded.
        self._cache_capacity = max(1, int(cache_capacity))
        self._cache: OrderedDict[str, list[dict[str, Any]]] = OrderedDict()
        self._cache_lock = threading.Lock()

    def _cache_get(self, key: str) -> list[dict[str, Any]] | None:
        with self._cache_lock:
            hit = self._cache.get(key)
            if hit is None:
                return None
            self._cache.move_to_end(key)
            from agentsafe.metrics import get_metrics

            get_metrics().incr("retrieval_cache_hits")
            return copy.deepcopy(hit)

    def _cache_put(self, key: str, rows: list[dict[str, Any]]) -> None:
        with self._cache_lock:
            self._cache[key] = copy.deepcopy(rows)
            self._cache.move_to_end(key)
            while len(self._cache) > self._cache_capacity:
                self._cache.popitem(last=False)
            from agentsafe.metrics import get_metrics

            get_metrics().incr("retrieval_cache_misses")

    def _connect(self):
        return _connect(self.dsn)

    def migrate(self) -> None:
        with self._connect() as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("create extension if not exists vector")
                cur.execute(_DROP_OLD)
                # Additive Category A/B columns for pre-existing deployments
                # (CREATE TABLE IF NOT EXISTS does not alter existing tables).
                for col in ("kb_group", "verification_status", "license_status",
                            "commercial_use", "attack_entry", "poc_reference",
                            "invariant", "incorrect_behavior",
                            "verification_evidence", "oracle_type", "price_source",
                            "freshness_requirements", "price_validation",
                            "security_pattern", "safe_code",
                            "required_assumptions", "why_safe",
                            "known_limitations", "related_vuln_classes",
                            "fp_patterns", "evidence_required",
                            "verification_method", "poc_code",
                            "expected_result", "confirmation_signals",
                            "refutation_signals", "test_tooling",
                            "attacker_contract", "test_setup",
                            "required_initial_state",
                            "expected_vulnerable_behavior",
                            "expected_safe_behavior", "test_result",
                            "solc_version", "foundry_version",
                            "subcategory", "vulnerability_id", "swc_id",
                            "exploit_sequence"):
                    cur.execute(
                        "ALTER TABLE vulnerability_knowledge "
                        f"ADD COLUMN IF NOT EXISTS {col} text")
                cur.execute(
                    "ALTER TABLE vulnerability_knowledge "
                    "ADD COLUMN IF NOT EXISTS confidence double precision")
                for col in ("call_sequence", "internal_calls", "external_calls",
                            "state_vars", "state_deps", "attacker_permissions",
                            "tx_conditions", "cross_function_deps",
                            "cross_contract_deps", "tags"):
                    cur.execute(
                        "ALTER TABLE vulnerability_knowledge "
                        f"ADD COLUMN IF NOT EXISTS {col} jsonb "
                        "DEFAULT '[]'::jsonb")
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
                # Standardized data-model indexes (idempotent; also covers the
                # fresh-CREATE path since CREATE TABLE IF NOT EXISTS above only
                # makes indexes for brand-new tables).
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS vk_subcategory_idx "
                    "ON vulnerability_knowledge (subcategory)")
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS vk_vuln_id_idx "
                    "ON vulnerability_knowledge (vulnerability_id)")
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS vk_severity_idx "
                    "ON vulnerability_knowledge (severity)")
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS vk_tags_idx "
                    "ON vulnerability_knowledge USING gin (tags)")
                # DB-level dedup on the source identifier pair (requirement 6):
                # same (source_id, external_record_id) can exist only once.
                # If legacy data contains dupes, index creation fails and is
                # logged; code-level dedup in run_import still enforces the rule.
                try:
                    cur.execute(
                        "CREATE UNIQUE INDEX IF NOT EXISTS vk_source_eid_idx "
                        "ON vulnerability_knowledge (source_id, external_record_id)")
                except Exception as exc:  # noqa: BLE001 - legacy dupes possible
                    logger.warning(
                        "unique (source_id, external_record_id) index skipped: %s",
                        str(exc)[:160])
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
        "coalesce(vk.description,'') || ' ' || coalesce(vk.title,'') || ' ' || "
        "coalesce(vk.root_cause,'') || ' ' || coalesce(vk.remediation,'') || ' ' || "
        "coalesce(vk.attack_scenario,'') || ' ' || coalesce(vk.vulnerable_code,'') || ' ' || "
        "coalesce(vk.metadata::text,'') || ' ' || "
        "coalesce(vk.category,'') || ' ' || coalesce(vk.protocol_domain,'')"
    )

    @staticmethod
    def _filter_clause(kb_groups=None, categories=None, tags=None,
                       sources=None) -> tuple[str, list[Any]]:
        """SQL WHERE fragment for hard metadata filters (both legs).
        kb_groups -> kb_group IN (...); categories -> category IN (...);
        tags -> tags ?| ARRAY[...] (jsonb: any-of match);
        sources -> source_id IN (...) (used for before/after A/B views)."""
        sql = ""
        params: list[Any] = []
        if kb_groups:
            sql += " AND vk.kb_group = ANY(%s)"
            params.append([str(g) for g in kb_groups])
        if categories:
            sql += " AND vk.category = ANY(%s)"
            params.append([str(c) for c in categories])
        if tags:
            sql += " AND vk.tags ?| %s"
            params.append([str(t) for t in tags])
        if sources:
            sql += " AND vk.source_id = ANY(%s)"
            params.append([str(s) for s in sources])
        return sql, params

    def _leg_vector(self, query: str, limit: int, *,
                    kb_groups=None, categories=None, tags=None,
                    sources=None) -> list[dict[str, Any]]:
        """Vector-only retrieval leg (pgvector cosine). Raises/None-safe:
        returns [] when no embedder or embedding fails (lexical fallback)."""
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
            fsql, fparams = self._filter_clause(kb_groups, categories, tags,
                                                sources=sources)
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
                        WHERE ke.embedding IS NOT NULL{fsql}
                        ORDER BY score DESC
                        LIMIT %s
                        """,
                        (qv, *fparams, limit),
                    )
                    return list(cur.fetchall())
        except Exception as exc:
            logger.warning("vector leg failed (%s)", exc)
            from agentsafe.metrics import get_metrics

            get_metrics().incr("retrieval_vector_fallback")
            return []

    def _leg_lexical(self, query: str, limit: int, *,
                     kb_groups=None, categories=None, tags=None,
                     sources=None) -> list[dict[str, Any]]:
        """Lexical-only retrieval leg (PostgreSQL ts_rank; documented NOT
        BM25)."""
        fsql, fparams = self._filter_clause(kb_groups, categories, tags,
                                            sources=sources)
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
                    WHERE websearch_to_tsquery('english', %s) IS NOT NULL{fsql}
                    ORDER BY score DESC
                    LIMIT %s
                    """,
                    (query, query, *fparams, limit),
                )
                return list(cur.fetchall())

    def search_leg_vector(self, query: str, limit: int = 3) -> list[dict[str, Any]]:
        """Benchmark/ablation surface: vector-only retrieval."""
        return [_row_to_record(r) for r in self._leg_vector(query, limit)]

    def search_leg_lexical(self, query: str, limit: int = 3) -> list[dict[str, Any]]:
        """Benchmark/ablation surface: lexical-only retrieval."""
        return [_row_to_record(r) for r in self._leg_lexical(query, limit)]

    def search(self, query: str, focus: str = "", limit: int = 3, *,
               profile: str | None = None, kb_groups=None, categories=None,
               tags=None, sources=None) -> list[dict[str, Any]]:
        """Hybrid retrieval: pgvector cosine + PostgreSQL full-text, fused with
        Reciprocal Rank Fusion (RRF): score(d) = sum 1/(K + rank_i(d)), K=60
        (standard RRF constant). Rank-fusion is documented, not BM25: full-text
        uses ts_rank, which is NOT BM25 — no such claim is made.
        Falls back to lexical-only when no embedder is configured or the
        vector leg fails.

        Category-specific retrieval: `profile` (see knowledge/profiles.py)
        BOOSTS records whose kb_group/category match the agent's knowledge
        class after fusion — prioritizing without excluding, so a Reentrancy
        agent still sees secure-pattern records and cross-signal. Explicit
        `kb_groups` / `categories` / `tags` args hard-filter both legs.

        Results are small by construction: limit is hard-capped at
        MAX_SEARCH_LIMIT so an LLM never receives hundreds of records.
        Results are cached per (query, focus, limit, profile, filters) for the
        lifetime of this store instance (a single audit session). Caching
        never changes results (same probe -> same rows) or payment/count
        semantics; it only avoids repeating expensive vector embedding +
        Neon round-trips.
        """
        if not query or not query.strip():
            return []
        from agentsafe.knowledge.profiles import (
            MAX_SEARCH_LIMIT,
            resolve_profile,
        )

        limit = max(1, min(int(limit), MAX_SEARCH_LIMIT))
        prof = resolve_profile(profile)
        import time as _t

        from agentsafe.metrics import get_metrics

        _m = get_metrics()
        _t0 = _t.monotonic()
        _ckey = (f"{query.strip()}\x1f{focus}\x1f{limit}\x1f{profile or ''}"
                 f"\x1f{sorted(kb_groups or [])}\x1f{sorted(categories or [])}"
                 f"\x1f{sorted(tags or [])}\x1f{sorted(sources or [])}")
        cached = self._cache_get(_ckey)
        if cached is not None:
            return cached
        K = 60
        vec_hits: list[tuple[Any, float]] = []  # (record, rank0-based)
        lex_hits: list[tuple[Any, float]] = []
        if self.embedding_model is not None:
            vec_hits = [(r, i) for i, r in enumerate(self._leg_vector(
                query, limit * 3, kb_groups=kb_groups, categories=categories,
                tags=tags, sources=sources))]
        lex_hits = [(r, i) for i, r in enumerate(self._leg_lexical(
            query, limit * 3, kb_groups=kb_groups, categories=categories,
            tags=tags, sources=sources))]
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
        # Category-specific prioritization: boost matched records after
        # fusion (never exclude — cross-signal stays visible).
        boosted: dict[str, float] = {}
        if prof:
            for k, row in best.items():
                b = prof["boost"] if (
                    row.get("kb_group") in prof["kb_groups"]
                    or row.get("category") in prof["categories"]) else 1.0
                boosted[k] = rrf[k] * b
        else:
            boosted = rrf
        fused = sorted(best.values(), key=lambda r: boosted[key(r)], reverse=True)
        out = []
        for r in fused[:limit]:
            rec = _row_to_record(r)
            rec["_retrieval"] = {
                "rrf_score": round(rrf[key(r)], 6),
                "boosted_score": round(boosted[key(r)], 6),
                "profile": profile,
                "vector_rank": min(legs[key(r)]) if key(r) in legs else None,
                "matched_legs": sum(1 for h in (vec_hits, lex_hits)
                                    if any(key(x[0]) == key(r) for x in h)),
            }
            out.append(rec)
        _m.incr("retrieval_calls")
        _m.record("retrieval_latency_ms", (_t.monotonic() - _t0) * 1000.0)
        self._cache_put(_ckey, out)
        return out

    def search_for_agent(self, query: str, profile: str | None,
                         limit: int = 3, **filters: Any) -> list[dict[str, Any]]:
        """Category-specific retrieval entry point for agents: resolves the
        agent's profile (kb_groups/categories boost) and applies any explicit
        hard filters. Equivalent to search(..., profile=profile, **filters)."""
        return self.search(query, profile=profile, limit=limit, **filters)

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
        vector_dim = int(getattr(settings, "KB_VECTOR_DIM", 384))
        # Attach the configured embedder so production retrieval uses the
        # stored vectors (Nemotron 2048-dim) instead of degrading to
        # lexical-only. A None embedder or an embedding failure leaves the
        # store lexical-only — never a hard failure (see NeonKnowledgeStore.search).
        embedder: Callable[[str], list[float]] | None = None
        try:
            from agentsafe.knowledge.embeddings import get_embedder

            embedder = get_embedder()
            if embedder is not None and embedder.dim != vector_dim:
                logger.warning(
                    "embedder dim %s != KB_VECTOR_DIM %s; vector leg truncates to %s",
                    embedder.dim, vector_dim, vector_dim,
                )
        except Exception as exc:  # embedder is an optimization, never a blocker
            logger.warning("embedder unavailable (%s); lexical-only retrieval", exc)
            embedder = None
        store = NeonKnowledgeStore(
            dsn=dsn, vector_dim=vector_dim, embedding_model=embedder)
        try:
            store.migrate()
            if store.count() == 0:
                from agentsafe.knowledge.importers import import_jsonl_dataset
                path = dataset_path or (Path(__file__).parent / "dataset"
                                        / f"v1.jsonl")
                import_jsonl_dataset(store, path, embedder=embedder)
            if store.count() > 0:
                # Seed the curated v2 dataset (additive; never rewrites or
                # deletes existing records). Idempotent: only imported when the
                # source is absent, so a re-run is a no-op.
                try:
                    if store.source_status("agentsafe-v2.jsonl") not in ("done", "running"):
                        from agentsafe.knowledge.importers import import_jsonl_dataset
                        v2_path = dataset_path or (Path(__file__).parent / "dataset"
                                                   / "v2.jsonl")
                        if Path(v2_path).exists():
                            import_jsonl_dataset(
                                store, v2_path, embedder=embedder,
                                source_name="agentsafe-v2.jsonl")
                except Exception as exc:  # v2 seed is additive, never a blocker
                    logger.warning("v2 knowledge seed skipped (%s)", exc)
                # Seed the curated v3 (Category B: attack-path) dataset.
                # Idempotent: only imported when the source is absent.
                try:
                    if store.source_status("agentsafe-v3.jsonl") not in ("done", "running"):
                        from agentsafe.knowledge.importers import import_jsonl_dataset
                        v3_path = dataset_path or (Path(__file__).parent / "dataset"
                                                   / "v3.jsonl")
                        if Path(v3_path).exists():
                            import_jsonl_dataset(
                                store, v3_path, embedder=embedder,
                                source_name="agentsafe-v3.jsonl")
                except Exception as exc:  # v3 seed is additive, never a blocker
                    logger.warning("v3 knowledge seed skipped (%s)", exc)
                # Seed the curated v4 (Category C: accounting-vulnerability)
                # dataset. Idempotent: only imported when the source is absent.
                try:
                    if store.source_status("agentsafe-v4.jsonl") not in ("done", "running"):
                        from agentsafe.knowledge.importers import import_jsonl_dataset
                        v4_path = dataset_path or (Path(__file__).parent / "dataset"
                                                   / "v4.jsonl")
                        if Path(v4_path).exists():
                            import_jsonl_dataset(
                                store, v4_path, embedder=embedder,
                                source_name="agentsafe-v4.jsonl")
                except Exception as exc:  # v4 seed is additive, never a blocker
                    logger.warning("v4 knowledge seed skipped (%s)", exc)
                # Seed curated v5 (Category D: oracle), v6 (Category E:
                # secure-code / FP), v7 (Category F: verification methods),
                # and v8 (Category F: Foundry PoC / exploit validation)
                # datasets. Idempotent.
                for _src, _file in (("agentsafe-v5.jsonl", "v5.jsonl"),
                                    ("agentsafe-v6.jsonl", "v6.jsonl"),
                                    ("agentsafe-v7.jsonl", "v7.jsonl"),
                                    ("agentsafe-v8.jsonl", "v8.jsonl")):
                    try:
                        if store.source_status(_src) not in ("done", "running"):
                            from agentsafe.knowledge.importers import import_jsonl_dataset
                            p = dataset_path or (Path(__file__).parent / "dataset" / _file)
                            if Path(p).exists():
                                import_jsonl_dataset(
                                    store, p, embedder=embedder, source_name=_src)
                    except Exception as exc:  # additive seeds, never blockers
                        logger.warning("%s seed skipped (%s)", _src, exc)
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


