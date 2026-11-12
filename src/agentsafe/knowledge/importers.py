"""Dataset import pipeline — AgentSafe G+ Stage 2.

Reusable adapters normalize verified public security data into the Neon
knowledge schema. Framework guarantees:

- Preserve original records + provenance; missing data stays null (never
  invented).
- Dedup by stable SHA-256 content hash (INSERT ... ON CONFLICT DO NOTHING).
- Split long documents into retrieval chunks that keep a parent-record
  relationship (parent_external_id in metadata + the parent row id).
- Generate embeddings in batches (optional embedder; NULL vectors degrade to
  lexical-only retrieval).
- Track inserted/skipped/failed/duplicate + a resumable checkpoint so an
  interrupted import resumes instead of re-importing.
- Import jobs are recorded in knowledge_import_jobs; bounded batch sizes keep
  work out of ordinary Vercel request paths.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

from agentsafe.knowledge.db import NeonKnowledgeStore, content_hash_of

logger = logging.getLogger("agentSAFE.knowledge.importers")

CHUNK_MAX_CHARS = 900  # ~2.5k tokens; small enough for focused retrieval

_AGGREGATE_FIELDS = (
    "root_cause", "preconditions", "attack_scenario", "impact", "remediation",
    "affected_contract", "affected_function", "vulnerable_code", "corrected_code",
    "title", "description", "mechanism", "protocol_type", "category", "severity",
    "source_url", "url", "id", "external_record_id", "metadata", "code_evidence",
)


@dataclass
class ImportSummary:
    source: str
    total: int = 0
    inserted: int = 0
    skipped: int = 0
    failed: int = 0
    duplicates: int = 0
    embeddings: int = 0
    embeddings_reused: int = 0
    known_skipped: int = 0  # records skipped by (source_id, external_record_id)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source, "total": self.total, "inserted": self.inserted,
            "skipped": self.skipped, "failed": self.failed,
            "duplicates": self.duplicates, "embeddings": self.embeddings,
            "embeddings_reused": self.embeddings_reused,
            "known_skipped": self.known_skipped,
            "errors": self.errors[:20],
        }


def normalize_record(raw: dict[str, Any], *, source_name: str) -> dict[str, Any]:
    """Map a raw source record onto the normalized import shape. Unknown
    fields are dropped (null), never invented. Provenance is preserved."""
    return {
        "external_record_id": raw.get("id") or raw.get("external_record_id"),
        "title": raw.get("title"),
        "description": raw.get("mechanism") or raw.get("description"),
        "category": raw.get("category"),
        "severity": raw.get("severity"),
        "protocol_type": raw.get("protocol_type") or raw.get("protocol_domain"),
        "affected_contract": raw.get("affected_contract"),
        "affected_function": raw.get("affected_function"),
        "vulnerable_code": raw.get("vulnerable_code") or raw.get("code_evidence"),
        "corrected_code": raw.get("corrected_code"),
        "root_cause": raw.get("root_cause"),
        "preconditions": raw.get("preconditions") or [],
        "attack_scenario": raw.get("attack_scenario") or raw.get("exploit_sequence"),
        "impact": raw.get("impact"),
        "remediation": raw.get("remediation"),
        "url": raw.get("url"),
        # Category A organization fields (absent -> null; never guessed)
        "kb_group": raw.get("kb_group"),
        "verification_status": raw.get("verification_status"),
        "license_status": raw.get("license_status") or raw.get("license"),
        "commercial_use": raw.get("commercial_use"),
        # Category B (attack-path knowledge) fields
        "attack_entry": raw.get("attack_entry"),
        "call_sequence": raw.get("call_sequence") or [],
        "internal_calls": raw.get("internal_calls") or [],
        "external_calls": raw.get("external_calls") or [],
        "state_vars": raw.get("state_vars") or [],
        "state_deps": raw.get("state_deps") or [],
        "attacker_permissions": raw.get("attacker_permissions") or [],
        "tx_conditions": raw.get("tx_conditions") or [],
        "cross_function_deps": raw.get("cross_function_deps") or [],
        "cross_contract_deps": raw.get("cross_contract_deps") or [],
        "poc_reference": raw.get("poc_reference"),
        # Category C (accounting-vulnerability) fields
        "invariant": raw.get("invariant"),
        "incorrect_behavior": raw.get("incorrect_behavior"),
        "verification_evidence": raw.get("verification_evidence"),
        # Category D (oracle-vulnerability) fields
        "oracle_type": raw.get("oracle_type"),
        "price_source": raw.get("price_source"),
        "freshness_requirements": raw.get("freshness_requirements"),
        "price_validation": raw.get("price_validation"),
        # Category E (secure-code / false-positive) fields
        "security_pattern": raw.get("security_pattern"),
        "safe_code": raw.get("safe_code"),
        "required_assumptions": raw.get("required_assumptions"),
        "why_safe": raw.get("why_safe"),
        "known_limitations": raw.get("known_limitations"),
        "related_vuln_classes": raw.get("related_vuln_classes"),
        "fp_patterns": raw.get("fp_patterns"),
        "evidence_required": raw.get("evidence_required"),
        # Category F (vulnerability-verification / testing) fields
        "verification_method": raw.get("verification_method"),
        "poc_code": raw.get("poc_code"),
        "expected_result": raw.get("expected_result"),
        "confirmation_signals": raw.get("confirmation_signals"),
        "refutation_signals": raw.get("refutation_signals"),
        "test_tooling": raw.get("test_tooling"),
        # Category F (Foundry PoC / exploit-validation) fields
        "attacker_contract": raw.get("attacker_contract"),
        "test_setup": raw.get("test_setup"),
        "required_initial_state": raw.get("required_initial_state"),
        "expected_vulnerable_behavior": raw.get("expected_vulnerable_behavior"),
        "expected_safe_behavior": raw.get("expected_safe_behavior"),
        "test_result": raw.get("test_result"),
        "solc_version": raw.get("solc_version"),
        "foundry_version": raw.get("foundry_version"),
        # Standardized KB data-model fields
        "subcategory": raw.get("subcategory"),
        "vulnerability_id": raw.get("vulnerability_id"),
        "swc_id": raw.get("swc_id"),
        "exploit_sequence": raw.get("exploit_sequence")
                              or raw.get("attack_scenario"),
        "confidence": raw.get("confidence"),
        "tags": raw.get("tags") or [],
        "metadata": {
            "source_name": source_name,
            "original": raw.get("id") or raw.get("external_record_id"),
            "parent_external_id": None,
        },
    }


def _chunk_text(text: str, max_chars: int = CHUNK_MAX_CHARS) -> list[str]:
    """Split long text into chunks on paragraph/line boundaries, falling back
    to hard character splits for a single paragraph that exceeds the budget so
    huge unstructured blocks are always retrievable. A short record stays one
    chunk (the parent row itself) — small records are never needlessly split."""
    if len(text) <= max_chars:
        return [text]
    chunks: list[str] = []
    buf: list[str] = []
    size = 0
    for para in text.split("\n\n"):
        if not para.strip():
            continue
        if len(para) > max_chars:
            # A single paragraph over budget: hard-split it.
            if buf:
                chunks.append("\n\n".join(buf))
                buf, size = [], 0
            for i in range(0, len(para), max_chars):
                chunks.append(para[i:i + max_chars])
            continue
        if size + len(para) > max_chars and buf:
            chunks.append("\n\n".join(buf))
            buf, size = [], 0
        buf.append(para)
        size += len(para) + 2
    if buf:
        chunks.append("\n\n".join(buf))
    return chunks


def _split_long_records(recs: list[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    """Yield normalized records, splitting very long descriptive fields into
    child chunks tagged with parent_external_id so parent relationships are
    preserved for retrieval/re-assembly."""
    for rec in recs:
        long_text = " ".join(filter(None, [
            rec.get("description"), rec.get("root_cause"), rec.get("remediation"),
        ]))
        parts = _chunk_text(long_text)
        if len(parts) <= 1:
            yield rec
            continue
        yield rec  # parent row carries the summary
        for i, part in enumerate(parts[1:], 1):
            child = dict(rec)
            child["description"] = part
            child["root_cause"] = None
            child["remediation"] = None
            child["metadata"] = dict(rec.get("metadata") or {})
            child["metadata"]["parent_external_id"] = rec.get("external_record_id")
            child["external_record_id"] = (
                f"{rec.get('external_record_id') or rec.get('id')}#chunk{i}")
            yield child


def _embed_in_batches(embedder: Callable[[str], list[float]] | None,
                      texts: list[str], batch_size: int) -> list[list[float] | None]:
    if embedder is None:
        return [None] * len(texts)
    out: list[list[float] | None] = []
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i + batch_size]
        try:
            # Support both callable(batch)->vectors and .embed(batch) objects.
            if hasattr(embedder, "embed"):
                vecs = embedder.embed(batch)
            else:
                vecs = embedder(batch)  # type: ignore[operator]
            if isinstance(vecs, list) and vecs and isinstance(vecs[0], list):
                out.extend(vecs)
                continue
            out.extend([None] * len(batch))
        except Exception as exc:
            logger.warning("embedding batch failed: %s", exc)
            out.extend([None] * len(batch))
    return out


def _existing_content_hashes(store: Any, hashes: list[str]) -> set[str]:
    """Stage 11: content hashes already stored WITH a vector (embedding
    reuse lookup). Best-effort: on store failure we return empty so the
    caller re-embeds everything (correctness over speed)."""
    if not hashes:
        return set()
    try:
        with store._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT DISTINCT content_hash FROM knowledge_embeddings "
                    "WHERE content_hash = ANY(%s)",
                    (hashes,),
                )
                return {
                    row[0] if not isinstance(row, dict) else row["content_hash"]
                    for row in cur.fetchall()
                }
    except Exception as exc:  # noqa: BLE001 - reuse is best-effort
        logger.warning("embedding reuse lookup failed (%s); re-embedding all", exc)
        return set()


def _plan_embeddings(store: Any, texts: list[str],
                     embedder: Callable[[str], list[float]] | None,
                     batch_size: int) -> tuple[list[list[float] | None], int]:
    """Plan embeddings with reuse: unchanged content (same content_hash) that
    already has a vector in the store is never re-embedded. Returns
    (embeddings aligned with texts, reused_count). When embedder is None all
    vectors are None (lexical-only)."""
    hashes = [content_hash_of(t) for t in texts]
    existing = _existing_content_hashes(store, hashes) if embedder is not None else set()
    need_idx = [i for i in range(len(texts)) if hashes[i] not in existing]
    reused = len(texts) - len(need_idx)
    if embedder is not None and need_idx:
        need_vecs = _embed_in_batches(embedder, [texts[i] for i in need_idx], batch_size)
        vec_by_i = dict(zip(need_idx, need_vecs))
        embeddings = [vec_by_i.get(i) for i in range(len(texts))]
    else:
        embeddings = [None] * len(texts)
    return embeddings, reused


def _known_external_ids(store: Any, source_name: str) -> set[str]:
    """External record ids already stored for one source (incremental-import
    lookup). Best-effort: on failure return empty so the caller imports all
    (content_hash dedup still protects correctness)."""
    try:
        with store._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT external_record_id FROM vulnerability_knowledge "
                    "WHERE source_id = %s",
                    (source_name,),
                )
                return {
                    (r["external_record_id"] if isinstance(r, dict) else r[0])
                    for r in cur.fetchall()
                }
    except Exception as exc:  # noqa: BLE001 - incremental skip is best-effort
        logger.warning("known-id lookup failed (%s); importing all", exc)
        return set()


def run_import(
    store: NeonKnowledgeStore,
    *,
    source: dict[str, Any],
    records: list[dict[str, Any]],
    embedder: Callable[[str], list[float]] | None = None,
    batch_size: int = 20,
    skip_known: bool = True,
) -> ImportSummary:
    """Run a resumable import. `records` is the fully-fetched source; callers
    with huge sources should use `run_import_resumable` for cursor checkpointing.
    Returns a structured summary; never raises on per-record failures.

    Dedup is two-layered (requirement 6): content_hash (INSERT ON CONFLICT)
    AND the source identifier pair (source_id, external_record_id). With
    skip_known=True (incremental), records whose (source_id,
    external_record_id) is already stored are filtered out BEFORE embedding
    work, so re-imports cost no embedding calls. Existing records are never
    overwritten by a re-import (requirement 9): same-id different-content
    rows are skipped and counted as duplicates."""
    summary = ImportSummary(source=source["name"])
    normalized = [normalize_record(r, source_name=source["name"]) for r in records]

    known: set[str] = set()
    if skip_known:
        known = _known_external_ids(store, source["name"])
        if known:
            fresh = [r for r in normalized
                     if r.get("external_record_id") not in known]
            summary.known_skipped = len(normalized) - len(fresh)
            if summary.known_skipped:
                logger.info("incremental import %s: %d known ids skipped",
                            source["name"], summary.known_skipped)
            normalized = fresh

    expanded = list(_split_long_records(normalized))
    summary.total = len(expanded)

    # Parent rows (not chunk children) carry the aggregate; chunk children only
    # carry their description slice, so the parent retains full provenance.
    parent_pool: dict[str, dict[str, Any]] = {}
    texts: list[str] = []
    for rec in expanded:
        parent_id = rec.get("metadata", {}).get("parent_external_id")
        if parent_id and parent_id in parent_pool:
            rec["root_cause"], rec["remediation"] = None, None
            rec["preconditions"] = []
        else:
            parent_pool[rec["external_record_id"]] = rec
        body = " ".join(filter(None, [
            rec.get("title"), rec.get("description"),
            rec.get("root_cause"), " ".join(rec.get("preconditions") or []),
            rec.get("impact"), rec.get("remediation"),
        ]))
        texts.append(body)

    embeddings, reused = _plan_embeddings(store, texts, embedder, batch_size)
    summary.embeddings_reused = reused
    # Compute embeddings BEFORE opening the DB transaction: Neon poolers kill
    # idle-in-transaction sessions, and remote embedding calls are slow.
    # (Stage 11: unchanged content is never re-embedded — see _plan_embeddings.)

    with store._connect() as conn:
        with conn.cursor() as cur:
            conn.autocommit = False
            cur.execute(
                """
                INSERT INTO knowledge_sources (name, version, url, license,
                    import_status, metadata)
                VALUES (%(name)s, %(version)s, %(url)s, %(license)s, 'running',
                        %(metadata)s)
                ON CONFLICT (name) DO UPDATE SET
                    import_status='running', updated_at=now()
                """,
                {
                    "name": source["name"], "version": source.get("version", "1"),
                    "url": source.get("url", ""), "license": source.get("license", ""),
                    "metadata": json.dumps(source.get("metadata", {})),
                },
            )
            cur.execute(
                "INSERT INTO knowledge_import_jobs (source_id, status, progress) "
                "VALUES (%s, 'running', 0)",
                (source["name"],),
            )
            for idx, (rec, body, emb) in enumerate(
                    zip(expanded, texts, embeddings)):
                ch = content_hash_of(body)
                try:
                    # Second dedup layer: same (source_id, external_record_id)
                    # already stored -> skip (never overwrite an existing
                    # record, even when upstream content changed).
                    if known and rec.get("external_record_id"):
                        cur.execute(
                            "SELECT 1 FROM vulnerability_knowledge "
                            "WHERE source_id=%s AND external_record_id=%s",
                            (source["name"], rec.get("external_record_id")))
                        if cur.fetchone():
                            summary.duplicates += 1
                            summary.skipped += 1
                            continue
                    cur.execute(
                        """
                        INSERT INTO vulnerability_knowledge (
                            source_id, external_record_id, title, description,
                            category, severity, protocol_domain, affected_contract,
                            affected_function, vulnerable_code, corrected_code,
                            root_cause, preconditions, attack_scenario, impact,
                            remediation, source_url, content_hash, metadata,
                            kb_group, verification_status, license_status,
                            commercial_use, attack_entry, call_sequence,
                            internal_calls, external_calls, state_vars,
                            state_deps, attacker_permissions, tx_conditions,
                            cross_function_deps, cross_contract_deps,
                            poc_reference, invariant, incorrect_behavior,
                            verification_evidence, oracle_type, price_source,
                            freshness_requirements, price_validation,
                            security_pattern, safe_code, required_assumptions,
                            why_safe, known_limitations, related_vuln_classes,
                            fp_patterns, evidence_required, verification_method,
                            poc_code, expected_result, confirmation_signals,
                            refutation_signals, test_tooling, attacker_contract,
                            test_setup, required_initial_state,
                            expected_vulnerable_behavior, expected_safe_behavior,
                            test_result, solc_version, foundry_version,
                            subcategory, vulnerability_id, swc_id,
                            exploit_sequence, confidence, tags
                        ) VALUES (%(s)s, %(eid)s, %(title)s, %(desc)s, %(cat)s,
                            %(sev)s, %(dom)s, %(ac)s, %(af)s, %(vc)s, %(cc)s,
                            %(rc)s, %(pc)s, %(as)s, %(imp)s, %(rem)s, %(url)s,
                            %(ch)s, %(md)s, %(grp)s, %(vs)s, %(ls)s, %(cu)s,
                            %(ae)s, %(cs)s, %(ic)s, %(ec)s, %(sv)s, %(sd)s,
                            %(ap)s, %(tc)s, %(cfd)s, %(ccd)s, %(poc)s,
                            %(inv)s, %(ib)s, %(ve)s, %(ot)s, %(ps)s, %(fr)s,
                            %(pv)s, %(sp)s, %(sc)s, %(ra)s, %(ws)s, %(kl)s,
                            %(rvc)s, %(fpp)s, %(er)s, %(vm)s, %(pocc)s, %(exr)s,
                            %(csg)s, %(rfs)s, %(tt)s, %(ac2)s, %(ts)s, %(ris)s,
                            %(evb)s, %(esb)s, %(tr)s, %(solc)s, %(fv)s,
                            %(subcat)s, %(vid)s, %(swc)s, %(es)s, %(conf)s,
                            %(tags)s)
                        ON CONFLICT (content_hash) DO NOTHING
                        """,
                        {
                            "s": source["name"], "eid": rec.get("external_record_id"),
                            "title": rec.get("title"), "desc": rec.get("description"),
                            "cat": rec.get("category"), "sev": rec.get("severity"),
                            "dom": rec.get("protocol_type"),
                            "ac": rec.get("affected_contract"),
                            "af": rec.get("affected_function"),
                            "vc": rec.get("vulnerable_code"), "cc": rec.get("corrected_code"),
                            "rc": rec.get("root_cause"),
                            "pc": json.dumps(rec.get("preconditions", [])),
                            "as": rec.get("attack_scenario"), "imp": rec.get("impact"),
                            "rem": rec.get("remediation"), "url": rec.get("url"),
                            "ch": ch, "md": json.dumps(rec.get("metadata", {})),
                            "grp": rec.get("kb_group"),
                            "vs": rec.get("verification_status"),
                            "ls": rec.get("license_status"),
                            "cu": rec.get("commercial_use"),
                            "ae": rec.get("attack_entry"),
                            "cs": json.dumps(rec.get("call_sequence", [])),
                            "ic": json.dumps(rec.get("internal_calls", [])),
                            "ec": json.dumps(rec.get("external_calls", [])),
                            "sv": json.dumps(rec.get("state_vars", [])),
                            "sd": json.dumps(rec.get("state_deps", [])),
                            "ap": json.dumps(rec.get("attacker_permissions", [])),
                            "tc": json.dumps(rec.get("tx_conditions", [])),
                            "cfd": json.dumps(rec.get("cross_function_deps", [])),
                            "ccd": json.dumps(rec.get("cross_contract_deps", [])),
                            "poc": rec.get("poc_reference"),
                            "inv": rec.get("invariant"),
                            "ib": rec.get("incorrect_behavior"),
                            "ve": rec.get("verification_evidence"),
                            "ot": rec.get("oracle_type"),
                            "ps": rec.get("price_source"),
                            "fr": rec.get("freshness_requirements"),
                            "pv": rec.get("price_validation"),
                            "sp": rec.get("security_pattern"),
                            "sc": rec.get("safe_code"),
                            "ra": rec.get("required_assumptions"),
                            "ws": rec.get("why_safe"),
                            "kl": rec.get("known_limitations"),
                            "rvc": rec.get("related_vuln_classes"),
                            "fpp": rec.get("fp_patterns"),
                            "er": rec.get("evidence_required"),
                            "vm": rec.get("verification_method"),
                            "pocc": rec.get("poc_code"),
                            "exr": rec.get("expected_result"),
                            "csg": rec.get("confirmation_signals"),
                            "rfs": rec.get("refutation_signals"),
                            "tt": rec.get("test_tooling"),
                            "ac2": rec.get("attacker_contract"),
                            "ts": rec.get("test_setup"),
                            "ris": rec.get("required_initial_state"),
                            "evb": rec.get("expected_vulnerable_behavior"),
                            "esb": rec.get("expected_safe_behavior"),
                            "tr": rec.get("test_result"),
                            "solc": rec.get("solc_version"),
                            "fv": rec.get("foundry_version"),
                            "subcat": rec.get("subcategory"),
                            "vid": rec.get("vulnerability_id"),
                            "swc": rec.get("swc_id"),
                            "es": rec.get("exploit_sequence"),
                            "conf": rec.get("confidence"),
                            "tags": json.dumps(rec.get("tags", [])),
                        },
                    )
                    if cur.rowcount == 0:
                        summary.duplicates += 1
                        summary.skipped += 1
                    else:
                        summary.inserted += 1
                except Exception as exc:
                    summary.failed += 1
                    summary.errors.append(str(exc)[:160])
                    continue
                if emb is not None:
                    # Reuse: skip re-embedding when this content_hash already
                    # has a vector from a prior import (unchanged content).
                    cur.execute(
                        "SELECT 1 FROM knowledge_embeddings WHERE content_hash=%s",
                        (ch,))
                    if cur.fetchone():
                        summary.embeddings_reused += 1
                        continue
                    cur.execute(
                        "SELECT id FROM vulnerability_knowledge WHERE content_hash=%s",
                        (ch,))
                    row = cur.fetchone()
                    if row:
                        vid = row["id"] if isinstance(row, dict) else row[0]
                        cur.execute(
                            """
                            INSERT INTO knowledge_embeddings
                                (knowledge_id, embedding, embedding_model,
                                 dimensions, content_hash)
                            VALUES (%s, %s, %s, %s, %s)
                            ON CONFLICT DO NOTHING
                            """,
                            (vid, [float(x) for x in emb[: store.vector_dim]],
                             getattr(embedder, "name", "local"), len(emb), ch),
                        )
                        summary.embeddings += 1
                if (idx + 1) % batch_size == 0:
                    cur.execute(
                        "UPDATE knowledge_import_jobs SET progress=%s, "
                        "checkpoint=%s, updated_at=now() WHERE source_id=%s",
                        (idx + 1, json.dumps({"idx": idx + 1}), source["name"]),
                    )
            status = "done" if summary.failed == 0 else "failed"
            cur.execute(
                "UPDATE knowledge_import_jobs SET status=%s, progress=%s, "
                "updated_at=now() WHERE source_id=%s",
                (status, summary.total, source["name"]),
            )
            cur.execute(
                "UPDATE knowledge_sources SET import_status=%s, record_counts=%s, "
                "updated_at=now() WHERE name=%s",
                (status, summary.inserted, source["name"]),
            )
    from agentsafe.metrics import get_metrics

    get_metrics().incr("import_records", summary.inserted)
    get_metrics().incr("import_duplicates", summary.duplicates)
    if summary.failed:
        get_metrics().incr("import_failed", summary.failed)
    else:
        get_metrics().incr("import_success")
    get_metrics().incr("import_embedding_calls", summary.embeddings)
    return summary


# ---------------------------------------------------------------------------
# Adapters
# ---------------------------------------------------------------------------
def import_jsonl_dataset(store: NeonKnowledgeStore,
                         path: str | Path,
                         embedder: Callable[[str], list[float]] | None = None,
                         source_name: str = "agentsafe-v1.jsonl",
                         ) -> ImportSummary:
    """Adapter for a shipped, in-repo JSONL dataset (own words, full
    provenance). Defaults to the v1 dataset name for backward compatibility;
    pass `source_name` (e.g. "agentsafe-v2.jsonl") to seed another curated
    dataset through the same pipeline."""
    import json as _json

    from pathlib import Path as P

    p = P(path)
    records: list[dict[str, Any]] = []
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            records.append(_json.loads(line))
    source = {
        "name": source_name,
        "version": "2" if source_name == "agentsafe-v2.jsonl" else "1",
        "url": "file://" + str(p),
        "license": "proprietary (agentSAFE); external provenance per record",
        "metadata": {"chunk_max_chars": CHUNK_MAX_CHARS,
                     "record_count": len(records)},
    }
    return run_import(store, source=source, records=records, embedder=embedder)


# -- resumable cursor-style import (for very large sources) -----------------
def run_import_resumable(
    store: NeonKnowledgeStore,
    *,
    source: dict[str, Any],
    fetch_batch: Callable[[int, int], tuple[list[dict[str, Any]], int | None]],
    embedder: Callable[[str], list[float]] | None = None,
    batch_size: int = 20,
    skip_known: bool = True,
) -> ImportSummary:
    """Fetch-and-import in pages via `fetch_batch(offset, limit) -> (rows, next)`.
    Persists a checkpoint after each page so an interrupted job resumes. This
    keeps large imports out of synchronous Vercel request paths (caller runs it
    in a worker)."""
    summary = ImportSummary(source=source["name"])
    offset = 0
    while True:
        rows, next_cursor = fetch_batch(offset, batch_size)
        if not rows:
            break
        page = run_import(store, source=source, records=rows, embedder=embedder,
                          batch_size=batch_size, skip_known=skip_known)
        summary.inserted += page.inserted
        summary.skipped += page.skipped
        summary.failed += page.failed
        summary.duplicates += page.duplicates
        summary.embeddings += page.embeddings
        summary.known_skipped += page.known_skipped
        if next_cursor is None:
            break
    return summary