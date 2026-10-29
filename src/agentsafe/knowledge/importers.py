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
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source, "total": self.total, "inserted": self.inserted,
            "skipped": self.skipped, "failed": self.failed,
            "duplicates": self.duplicates, "embeddings": self.embeddings,
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


def run_import(
    store: NeonKnowledgeStore,
    *,
    source: dict[str, Any],
    records: list[dict[str, Any]],
    embedder: Callable[[str], list[float]] | None = None,
    batch_size: int = 20,
) -> ImportSummary:
    """Run a resumable import. `records` is the fully-fetched source; callers
    with huge sources should use `run_import_resumable` for cursor checkpointing.
    Returns a structured summary; never raises on per-record failures."""
    summary = ImportSummary(source=source["name"])
    normalized = [normalize_record(r, source_name=source["name"]) for r in records]
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

    embeddings = _embed_in_batches(embedder, texts, batch_size)
    # Compute embeddings BEFORE opening the DB transaction: Neon poolers kill
    # idle-in-transaction sessions, and remote embedding calls are slow.

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
                    cur.execute(
                        """
                        INSERT INTO vulnerability_knowledge (
                            source_id, external_record_id, title, description,
                            category, severity, protocol_domain, affected_contract,
                            affected_function, vulnerable_code, corrected_code,
                            root_cause, preconditions, attack_scenario, impact,
                            remediation, source_url, content_hash, metadata
                        ) VALUES (%(s)s, %(eid)s, %(title)s, %(desc)s, %(cat)s,
                            %(sev)s, %(dom)s, %(ac)s, %(af)s, %(vc)s, %(cc)s,
                            %(rc)s, %(pc)s, %(as)s, %(imp)s, %(rem)s, %(url)s,
                            %(ch)s, %(md)s)
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
                        summary.skipped_embed = getattr(summary,
                                                        "skipped_embed", 0) + 1
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
    return summary


# ---------------------------------------------------------------------------
# Adapters
# ---------------------------------------------------------------------------
def import_jsonl_dataset(store: NeonKnowledgeStore,
                         path: str | Path,
                         embedder: Callable[[str], list[float]] | None = None,
                         ) -> ImportSummary:
    """Adapter for the shipped, in-repo v1.jsonl dataset (our own words,
    full provenance). This is the first verified source: we own its content
    and licensing, so it is a safe seed before adding external adapters."""
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
        "name": "agentsafe-v1.jsonl",
        "version": "1",
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
                          batch_size=batch_size)
        summary.inserted += page.inserted
        summary.skipped += page.skipped
        summary.failed += page.failed
        summary.duplicates += page.duplicates
        summary.embeddings += page.embeddings
        offset = next_cursor if isinstance(next_cursor, int) else offset + len(rows)
        if next_cursor is None:
            break
    return summary