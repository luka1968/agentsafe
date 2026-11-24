"""Phase 2 — knowledge data-quality classification (NON-DESTRUCTIVE).

Every stored record is inspected and annotated with a quality class and a list
of issue flags. The source record itself is NEVER modified, rewritten, or
deleted: the assessment lives in additive columns
(``quality_status`` / ``quality_flags`` / ``quality_claim`` /
``quality_checked_at``) that can be dropped to revert. Original fields
(``description``, ``title``, ``url``, ``external_record_id``, ``metadata`` …)
stay byte-for-byte as imported, so any record remains fully recoverable.

Classes (data completeness + internal consistency; NOT a verdict on whether the
underlying vulnerability is real):

  VALIDATED     complete core fields, consistent classification/provenance
  NEEDS_REVIEW  complete enough to keep, but has a soft defect (missing exploit
                walk-through, unknown/missing severity, malformed PoC, a
                classification that the text does not support, …)
  INCOMPLETE    a REQUIRED core field is missing (description, category,
                preconditions, source reference)
  DUPLICATE     a near-duplicate of another, distinct record (chunk
                parent/child pairs are NOT duplicates)
  INVALID       unusable: no title/description AND no source reference

A SEPARATE dimension ``quality_claim`` records claim verification honestly and
is never fabricated:
  reproduced         a runnable PoC/test reproduced it (verification_status)
  curated            human-authored knowledge record
  unverified-source  imported from a public report; NOT independently verified

The module never invents technical detail. Where a field cannot be verified it
is reported as missing/unknown, never guessed.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from agentsafe.knowledge.enrich import _KEYWORD_CATEGORY

logger = logging.getLogger("agentSAFE.knowledge.quality")

VALIDATED = "VALIDATED"
NEEDS_REVIEW = "NEEDS_REVIEW"
INCOMPLETE = "INCOMPLETE"
DUPLICATE = "DUPLICATE"
INVALID = "INVALID"
STATUSES = (VALIDATED, NEEDS_REVIEW, INCOMPLETE, DUPLICATE, INVALID)

VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational", "info"}
MIN_DESC_CHARS = 80
NEAR_DUP_JACCARD = 0.90

_CATEGORY_KEYWORDS: dict[str, tuple[str, ...]] = {
    cat: tuple(kws) for cat, kws in _KEYWORD_CATEGORY}
CANONICAL_CATEGORIES = set(_CATEGORY_KEYWORDS)
_SWC_RE = re.compile(r"^SWC-\d+$")

# Substrings that indicate an actual code/PoC excerpt (Solidity, pseudo, or a
# runnable trace). A "vulnerable_code" field with none of these is a non-code
# snippet (e.g. an arithmetic derivation), which we flag rather than discard.
_CODE_HINTS = (
    "function", "contract", "interface", "library", "pragma", "mapping",
    "require", "assert", "modifier", "event", "return", "emit", "revert",
    "=>", "{", "}", ";", ".call", ".transfer", ".send", "delegatecall",
    "balance", "uint", "int", "address", "bytes",
)

# Hard defects -> INCOMPLETE. Soft defects -> NEEDS_REVIEW.
_HARD_FLAGS = {
    "no_description", "short_description", "missing_category",
    "missing_preconditions", "no_source_reference",
}
# Informational flags are recorded for transparency but do NOT downgrade a
# record: the source is still recoverable, so it is not a review blocker.
_INFO_FLAGS = {"missing_source_url"}


def _text(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        return " ".join(str(x) for x in v)
    if isinstance(v, dict):
        return " ".join(f"{k} {v2}" for k, v2 in v.items())
    return str(v)


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def _tokens(s: str, cap: int = 600) -> set[str]:
    return {t for t in _norm(s[:cap]).split() if len(t) > 2}


def base_record_id(external_record_id: Any) -> str:
    """Strip a `#chunkN` suffix so a finding and its chunks share a base id."""
    return re.split(r"#chunk\d+$", str(external_record_id or ""))[0]


def category_supported(text: str, category: str) -> bool | None:
    """True/False if the category has vocabulary and the text supports it;
    None when the category is not in the canonical vocabulary."""
    kws = _CATEGORY_KEYWORDS.get(category or "")
    if not kws:
        return None
    low = (text or "").lower()
    return any(k in low for k in kws)


def looks_like_code(code: str) -> bool:
    if not code or not code.strip():
        return True
    low = code.lower()
    return any(h in low for h in _CODE_HINTS)


def severity_is_valid(severity: Any) -> bool:
    return severity is None or str(severity).strip().lower() in VALID_SEVERITIES


def claim_status(verification_status: Any) -> str:
    vs = (str(verification_status or "")).strip().lower()
    if vs == "reproduced":
        return "reproduced"
    if vs == "curated":
        return "curated"
    return "unverified-source"


@dataclass
class Assessment:
    status: str
    flags: list[str] = field(default_factory=list)
    claim: str = "unverified-source"

    def to_row(self) -> dict[str, Any]:
        return {"status": self.status, "flags": self.flags, "claim": self.claim}


def assess_record(row: dict[str, Any]) -> Assessment:
    """Classify ONE record from its stored fields (no cross-record comparison;
    duplicate detection is applied by the store pass)."""
    title = _text(row.get("title")).strip()
    desc = _text(row.get("description")).strip()
    category = (row.get("category") or "").strip()
    severity = row.get("severity")
    preconditions = row.get("preconditions") or []
    attack = _text(row.get("attack_scenario") or row.get("exploit_sequence")).strip()
    vulnerable_code = _text(row.get("vulnerable_code"))
    corrected_code = _text(row.get("corrected_code"))
    solc = _text(row.get("solc_version")).strip()
    source_url = _text(row.get("source_url")).strip()
    ext_id = _text(row.get("external_record_id")).strip()
    metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    tags = row.get("tags") or []

    flags: list[str] = []

    # -- provenance --------------------------------------------------------
    has_ref = bool(source_url) or bool(ext_id) or bool(metadata.get("contest")) \
        or bool(metadata.get("original"))
    if not has_ref:
        flags.append("no_source_reference")
    if not source_url:
        # Provenance may still be resolvable from the external id; flagged so
        # the gap is visible rather than hidden.
        flags.append("missing_source_url")

    # -- description -------------------------------------------------------
    if not desc:
        flags.append("no_description")
    elif len(desc) < MIN_DESC_CHARS:
        flags.append("short_description")

    # -- classification ----------------------------------------------------
    if not category:
        flags.append("missing_category")
    else:
        blob = f"{title} {desc} {_text(row.get('root_cause'))}"
        supported = category_supported(blob, category)
        if supported is None:
            flags.append("category_not_in_vocabulary")
        elif not supported:
            # The record's own category has no keyword support; if another
            # canonical class is evidenced, the label is suspect.
            other = next((c for c in CANONICAL_CATEGORIES
                          if c != category and category_supported(blob, c)), None)
            if other:
                flags.append("possible_misclassification")

    # -- exploitability conditions ----------------------------------------
    if not preconditions:
        flags.append("missing_preconditions")
    if not attack:
        flags.append("missing_attack_scenario")

    # -- severity ----------------------------------------------------------
    if severity is None or str(severity).strip() == "":
        flags.append("missing_severity")
    elif not severity_is_valid(severity):
        flags.append("unknown_severity")

    # -- PoC sanity --------------------------------------------------------
    if vulnerable_code and not looks_like_code(vulnerable_code):
        flags.append("non_solidity_code_snippet")
    for label, code in (("vulnerable_code", vulnerable_code),
                        ("corrected_code", corrected_code)):
        if code and "```" in code and code.count("```") % 2 != 0:
            flags.append(f"unbalanced_code_fence:{label}")

    # -- toolchain / version ----------------------------------------------
    if solc:
        if not re.match(r"^\d+\.\d+\.\d+$", solc):
            flags.append("malformed_solc_version")
        else:
            pragma = re.search(r"pragma\s+solidity\s+([^;]+);", vulnerable_code)
            if pragma and solc not in pragma.group(1):
                flags.append("solc_version_mismatch")

    # -- terminology -------------------------------------------------------
    if category and category != category.lower():
        flags.append("inconsistent_terminology")
    for t in tags:
        if isinstance(t, str) and t != t.lower():
            flags.append("inconsistent_terminology")
            break

    # -- verification honesty ---------------------------------------------
    if not (str(row.get("verification_status") or "").strip()):
        flags.append("unknown_verification")
    swc = _text(row.get("swc_id")).strip()
    if swc and not _SWC_RE.match(swc):
        flags.append("malformed_swc_id")

    flags = sorted(set(flags))

    if "no_source_reference" in flags and not title and not desc:
        status = INVALID
    elif any(f in _HARD_FLAGS for f in flags):
        status = INCOMPLETE
    elif any(f not in _INFO_FLAGS for f in flags):
        status = NEEDS_REVIEW
    else:
        status = VALIDATED
    return Assessment(status=status, flags=flags,
                      claim=claim_status(row.get("verification_status")))


# ---------------------------------------------------------------------------
# store pass
# ---------------------------------------------------------------------------
_FETCH = """
    SELECT id, source_id, external_record_id, title, description, category,
           severity, root_cause, attack_scenario, exploit_sequence,
           preconditions, vulnerable_code, corrected_code, solc_version,
           swc_id, tags, source_url, metadata, verification_status
    FROM vulnerability_knowledge
    ORDER BY id
"""


@dataclass
class QualitySummary:
    scanned: int = 0
    by_status: dict[str, int] = field(default_factory=dict)
    by_claim: dict[str, int] = field(default_factory=dict)
    flag_counts: dict[str, int] = field(default_factory=dict)
    duplicates: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanned": self.scanned,
            "by_status": dict(sorted(self.by_status.items())),
            "by_claim": dict(sorted(self.by_claim.items())),
            "flag_counts": dict(sorted(self.flag_counts.items(),
                                       key=lambda kv: -kv[1])),
            "duplicate_count": len(self.duplicates),
            "duplicates": self.duplicates[:50],
            "errors": self.errors[:20],
        }


def find_near_duplicates(rows: list[dict[str, Any]],
                         threshold: float = NEAR_DUP_JACCARD
                         ) -> dict[int, int]:
    """Map record id -> id of the earlier record it duplicates. Records that
    share a base external id (a finding and its chunk children) are never
    duplicates of one another."""
    buckets: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        key = _norm(_text(r.get("title")))[:80]
        buckets.setdefault(key, []).append(r)
    dups: dict[int, int] = {}
    for key, group in buckets.items():
        if not key or len(group) < 2:
            continue
        for i in range(1, len(group)):
            a = group[i]
            a_tokens = _tokens(f"{a.get('title')} {a.get('description')}")
            for j in range(i):
                b = group[j]
                if base_record_id(a.get("external_record_id")) == \
                        base_record_id(b.get("external_record_id")):
                    continue
                b_tokens = _tokens(f"{b.get('title')} {b.get('description')}")
                if not a_tokens or not b_tokens:
                    continue
                inter = len(a_tokens & b_tokens)
                union = len(a_tokens | b_tokens)
                if union and inter / union >= threshold:
                    dups[a["id"]] = b["id"]
                    break
    return dups


def assess_store(store: Any, *, limit: int | None = None) -> QualitySummary:
    """Assess every record and write the classification into the additive
    quality columns. The source fields are never modified."""
    sql = _FETCH + (" LIMIT %s" if limit else "")
    with store._connect() as conn, conn.cursor() as cur:
        cur.execute(sql, (int(limit),) if limit else ())
        rows = [dict(r) for r in cur.fetchall()]

    summary = QualitySummary(scanned=len(rows))
    dups = find_near_duplicates(rows)
    updates: list[tuple[str, str, str, int]] = []
    for row in rows:
        try:
            assessment = assess_record(row)
        except Exception as exc:  # one bad row never stops the pass
            summary.errors.append(f"row {row.get('id')}: {exc}")
            continue
        status, flags = assessment.status, list(assessment.flags)
        dup_of = dups.get(row["id"])
        if dup_of is not None:
            status = DUPLICATE
            flags = sorted(set(flags + [f"near_duplicate_of:{dup_of}"]))
            summary.duplicates.append({"id": row["id"], "duplicate_of": dup_of,
                                       "title": _text(row.get("title"))[:80]})
        summary.by_status[status] = summary.by_status.get(status, 0) + 1
        summary.by_claim[assessment.claim] = \
            summary.by_claim.get(assessment.claim, 0) + 1
        for f in flags:
            summary.flag_counts[f] = summary.flag_counts.get(f, 0) + 1
        updates.append((status, json.dumps(flags), assessment.claim, row["id"]))

    for i in range(0, len(updates), 200):
        batch = updates[i:i + 200]
        try:
            with store._connect() as conn, conn.cursor() as cur:
                cur.executemany(
                    "UPDATE vulnerability_knowledge SET quality_status = %s, "
                    "quality_flags = %s::jsonb, quality_claim = %s, "
                    "quality_checked_at = now() WHERE id = %s",
                    batch)
        except Exception as exc:  # noqa: BLE001 - rerun finishes (idempotent)
            summary.errors.append(f"batch {i // 200}: {exc}")
    from agentsafe.metrics import get_metrics

    get_metrics().incr("quality_assessed", summary.scanned)
    return summary
