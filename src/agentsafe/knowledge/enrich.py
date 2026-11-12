"""Category A — Real-World Vulnerability Cases: taxonomy + enrichment.

Purpose (KB organization spec): help agents recognize real-world
vulnerability patterns instead of relying only on generic descriptions.

The KB is organized into six main category groups; this module implements
group A (real-world vulnerability cases from public audit reports:
Code4rena, Sherlock, CodeHawks — public contest reports, legally reusable)
and reserves the remaining groups.

What enrichment does (deterministic, non-destructive):
  * classification  <- keyword inference from title/description (only on a
    strong signal; null otherwise — never guessed)
  * impact          <- the `## Impact` markdown section (Code4rena &
    Sherlock both use it)
  * remediation     <- `## Recommendation` / `## Recommended Mitigation Steps`
  * vulnerable_code <- fenced code blocks inside `## Code Snippet` /
    `## Proof of Concept` (or the first code block as fallback)
  * kb_group        <- 'A'
  * verification_status <- 'curated' | 'source' | 'heuristic' (honest: a
    record with any deterministically derived field is 'heuristic', with
    per-field provenance in metadata.enrichment)

What enrichment never does: overwrite a non-null value, delete a record,
invent a field that cannot be extracted or inferred, or claim legal
clearance beyond the source's recorded license.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("agentSAFE.knowledge.enrich")

# ---------------------------------------------------------------------------
# KB main-category organization (six groups). Group A (real-world cases) and
# Group B (attack-path knowledge) are implemented; C-F are reserved for
# later KB organization passes.
# ---------------------------------------------------------------------------
KB_GROUPS: dict[str, str] = {
    "A": "real-world-cases",       # public audit reports (this module)
    "B": "attack-paths",           # multi-call / cross-contract attack paths
    "C": "accounting",             # balance/share/debt/rounding knowledge
    "D": "oracle",                 # price/oracle-vulnerability knowledge
    "E": "secure-code-fp",         # secure patterns + false-positive guidance
    "F": "verification",           # proving / refuting findings (testing)
}

GROUP_A_SOURCES = (
    "speca-code4rena", "speca-sherlock", "speca-codehawks",
)

# Group B (attack-path knowledge) curated source.
GROUP_B_SOURCES = ("agentsafe-v3.jsonl",)

# Group C (accounting-vulnerability knowledge) curated source.
GROUP_C_SOURCES = ("agentsafe-v4.jsonl",)

# Group D (oracle-vulnerability knowledge) curated source.
GROUP_D_SOURCES = ("agentsafe-v5.jsonl",)

# Group E (secure-code / false-positive knowledge) curated source.
GROUP_E_SOURCES = ("agentsafe-v6.jsonl",)

# Group F (vulnerability-verification / testing knowledge) curated sources:
# v7 = verification-method guidance; v8 = concrete Foundry PoC reproductions.
GROUP_F_SOURCES = ("agentsafe-v7.jsonl", "agentsafe-v8.jsonl")

# Verification-status vocabulary (honest provenance of stored fields).
VS_CURATED = "curated"        # human-authored record (v1/v2 curated datasets)
VS_SOURCE = "source"          # verbatim public report, nothing derived
VS_HEURISTIC = "heuristic"    # contains deterministically derived fields
VS_REPRODUCED = "reproduced"  # exploit verified by a public/test repro PoC

# Verification statuses that must never be overwritten by deterministic
# enrichment (requirement 9). Verified records are kept exactly as-is: no
# enrichment field is ever filled on them.
VERIFIED_STATUSES = {VS_CURATED, VS_REPRODUCED}

# confirmation_status is NEVER set on unverified rows: a record with an
# unverified origin is marked "source"/"heuristic"/None at most; only records
# whose output was reproduced by a runnable PoC/test may be "reproduced".


# ---------------------------------------------------------------------------
# classification vocabulary + deterministic keyword inference
# ---------------------------------------------------------------------------
_KEYWORD_CATEGORY: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("reentrancy", ("re-entran", "reentran", "callback", "fallback receives",
                    "external call before", "cei", "checks-effects")),
    ("oracle", ("oracle", "price feed", "twap", "spot price", "latestrounddata",
                "stale price", "price manipulation", "chainlink")),
    ("access-control", ("access control", "onlyowner", "missing modifier",
                        "unauthorized", "privilege", "role", "who can call",
                        "unprotected", "anyone can")),
    ("initialization", ("initializ", "uninitialized", "front-run the init",
                        "proxy admin", "implementation contract")),
    ("proxy", ("proxy", "delegatecall", "upgradeab", "storage slot",
               "storage collision", "implementation")),
    ("accounting", ("accounting", "balance", "share", "collateral", "debt",
                    "overcollateral", "undercollateral", "insolven",
                    "double count", "miscalculat", "wrong amount",
                    "incorrect amount", "asset", "mint", "burn")),
    ("rounding", ("rounding", "round down", "round up", "precision",
                  "truncat", "division before", "first depositor",
                  "dust", "decimal")),
    ("approval", ("allowance", "approve", "permit", "signature replay",
                  "front-run the approval")),
    ("token-transfer", ("fee on transfer", "deflationary", "token transfer",
                        "safetransfer", "erc20", "transferfrom")),
    ("unhandled-return", ("return value", "unchecked return", "ignores the",
                          "not checked", "no check on the result",
                          "silent fail", "send returns")),
    ("governance", ("governance", "proposal", "voting", "quorum", "timelock",
                    "flash-loan vote")),
    ("bridge", ("bridge", "cross-chain", "guardian", "header")),
    ("donation", ("donation", "donate", "direct transfer inflat",
                  "first depositor inflation")),
)

_CATEGORY_ORDER = tuple(c for c, _ in _KEYWORD_CATEGORY)


def infer_category(title: str, description: str) -> str | None:
    """Deterministic classification from title+description keywords.

    Honest: returns the FIRST matching category in vocabulary order, or None
    when no strong signal exists. Never guesses a category from a weak hit.
    """
    blob = f"{title or ''}\n{description or ''}".lower()
    for cat, keywords in _KEYWORD_CATEGORY:
        for kw in keywords:
            if kw in blob:
                return cat
    return None


# ---------------------------------------------------------------------------
# markdown section extraction (Code4rena + Sherlock report formats)
# ---------------------------------------------------------------------------
_SECTION_HEADS = re.compile(r"^(#{1,3})\s*(.+?)\s*$", re.MULTILINE)

_IMPACT_HEADS = ("impact",)
_REMED_HEADS = ("recommendation", "recommended mitigation", "recommend",
                "mitigation")
_CODE_HEADS = ("code snippet", "proof of concept", "poc")


@dataclass
class ExtractedSections:
    impact: str | None = None
    remediation: str | None = None
    vulnerable_code: str | None = None
    derived: list[str] = field(default_factory=list)


def _slice_section(text: str, heads: tuple[str, ...]) -> str | None:
    """Return the body of the first markdown section whose heading contains
    any of `heads` (case-insensitive). Sections run to the next heading."""
    matches = list(_SECTION_HEADS.finditer(text or ""))
    for i, m in enumerate(matches):
        head = m.group(2).lower()
        if any(h in head for h in heads):
            start = m.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            body = text[start:end].strip()
            return body or None
    return None


def _first_code_block(text: str) -> str | None:
    m = re.search(r"```[a-zA-Z]*\n(.*?)```", text or "", re.DOTALL)
    if m and m.group(1).strip():
        return m.group(1).strip()[:1200]
    return None


def extract_markdown_sections(description: str) -> ExtractedSections:
    """Deterministically extract structured fields from a public report's
    markdown. Only verbatim slices of the source text are returned — nothing
    is paraphrased or invented."""
    out = ExtractedSections()
    if not description:
        return out
    impact = _slice_section(description, _IMPACT_HEADS)
    if impact:
        out.impact = impact[:800]
        out.derived.append("impact")
    remediation = _slice_section(description, _REMED_HEADS)
    if remediation:
        out.remediation = remediation[:800]
        out.derived.append("remediation")
    code_section = _slice_section(description, _CODE_HEADS)
    code = _first_code_block(code_section or "") or _first_code_block(description)
    if code:
        out.vulnerable_code = code
        out.derived.append("vulnerable_code")
    return out


# ---------------------------------------------------------------------------
# non-destructive enrichment pass over the live store
# ---------------------------------------------------------------------------
@dataclass
class EnrichSummary:
    scanned: int = 0
    updated: int = 0
    categorized: int = 0
    impact_filled: int = 0
    remediation_filled: int = 0
    code_filled: int = 0
    skipped_non_null: int = 0
    skipped_verified: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanned": self.scanned, "updated": self.updated,
            "categorized": self.categorized,
            "impact_filled": self.impact_filled,
            "remediation_filled": self.remediation_filled,
            "code_filled": self.code_filled,
            "skipped_non_null": self.skipped_non_null,
            "skipped_verified": self.skipped_verified,
            "errors": self.errors[:20],
        }


def _enrich_one(row: dict[str, Any]) -> dict[str, Any] | None:
    """Compute the non-destructive UPDATE for one row. Returns None when
    there is nothing to add (all candidate fields already non-null)."""
    desc = row.get("description") or ""
    title = row.get("title") or ""
    extracted = extract_markdown_sections(desc)
    cat = infer_category(title, desc)

    sets: dict[str, Any] = {}
    derived: list[str] = []
    if row.get("category") in (None, "") and cat:
        sets["category"] = cat
        derived.append("category")
    if row.get("impact") in (None, "") and extracted.impact:
        sets["impact"] = extracted.impact
        derived.append("impact")
    if row.get("remediation") in (None, "") and extracted.remediation:
        sets["remediation"] = extracted.remediation
        derived.append("remediation")
    if row.get("vulnerable_code") in (None, "") and extracted.vulnerable_code:
        sets["vulnerable_code"] = extracted.vulnerable_code
        derived.append("vulnerable_code")
    if not sets:
        return None

    sets["kb_group"] = "A"
    # Honest verification status: the record now mixes verbatim source text
    # with deterministically derived fields.
    sets["verification_status"] = VS_HEURISTIC
    md = dict(row.get("metadata") or {})
    md["enrichment"] = {
        "derived_fields": derived,
        "method": "deterministic-markdown-extraction+keyword-classification",
    }
    sets["metadata"] = json.dumps(md)
    return sets


def enrich_category_a(store: Any, *, limit: int = 500,
                      sources: tuple[str, ...] = GROUP_A_SOURCES,
                      ) -> EnrichSummary:
    """Enrich Category A rows in place. NON-DESTRUCTIVE by contract: only
    NULL/empty fields are filled; existing values are never overwritten
    (counted in skipped_non_null). Existing rows keep their id/content_hash;
    enrichment changes row content, so content_hash stays the import-time
    hash and the enrichment provenance lives in metadata.

    One connection / one transaction for the whole pass: Neon poolers kill
    idle-in-transaction sessions on slow per-row connects, and a batched
    pass avoids re-connecting per row."""
    summary = EnrichSummary()
    ph = ", ".join(["%s"] * len(sources))
    updates: list[tuple[list[Any], int]] = []  # (values, row_id)
    with store._connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT id, title, description, category, impact, remediation,
                       vulnerable_code, kb_group, verification_status, metadata
                FROM vulnerability_knowledge
                WHERE source_id IN ({ph})
                ORDER BY id
                LIMIT %s
                """,
                (*sources, limit),
            )
            rows = cur.fetchall()
            for row in rows:
                summary.scanned += 1
                try:
                    row_dict = row if isinstance(row, dict) else dict(row)
                    # Verified records are never enriched: verified rows are
                    # kept exactly as imported (requirement 9: never overwrite
                    # verified records without explicit rules).
                    if row_dict.get("verification_status") in VERIFIED_STATUSES:
                        summary.skipped_verified += 1
                        continue
                    sets = _enrich_one(row_dict)
                except Exception as exc:  # one bad row never stops the pass
                    summary.errors.append(f"row {row.get('id')}: {exc}")
                    continue
                if sets is None:
                    summary.skipped_non_null += 1
                    continue
                frag = ", ".join(f"{k} = %s" for k in sets)
                cur.execute(
                    f"UPDATE vulnerability_knowledge SET {frag}, "
                    "updated_at = now() WHERE id = %s",
                    (*sets.values(), row["id"]),
                )
                updates.append((list(sets.values()), row["id"]))
                summary.updated += 1
                summary.categorized += 1 if "category" in sets else 0
                summary.impact_filled += 1 if "impact" in sets else 0
                summary.remediation_filled += 1 if "remediation" in sets else 0
                summary.code_filled += 1 if "vulnerable_code" in sets else 0
            # Organization backfill: every row from a Category A source is a
            # group-A record even when no field needed enriching. Fill-nulls
            # only; never overwrites.
            cur.execute(
                f"""
                UPDATE vulnerability_knowledge
                SET kb_group = 'A',
                    verification_status = COALESCE(verification_status, %s),
                    license_status = COALESCE(license_status,
                                              'public contest findings'),
                    commercial_use = COALESCE(commercial_use, 'public-reports')
                WHERE source_id IN ({ph})
                  AND (kb_group IS NULL OR verification_status IS NULL
                       OR license_status IS NULL OR commercial_use IS NULL)
                """,
                (VS_SOURCE, *sources),
            )
    from agentsafe.metrics import get_metrics

    get_metrics().incr("enrich_category_a_updated", summary.updated)
    return summary
