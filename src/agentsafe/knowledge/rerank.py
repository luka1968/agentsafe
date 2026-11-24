"""Hybrid retrieval reranking signals (Phase 4).

A small, deterministic, documented reranker applied AFTER Reciprocal Rank
Fusion. It never invents relevance: every factor is computed from the query
string and the record's own stored fields, and the exact contributions are
returned as diagnostics so a caller can see WHY a record ranked where it did.

Signals (multiplicative, all bounded so RRF stays dominant):
  profile    category-class boost (see profiles.py) — unchanged behavior
  validation verification/quality status (reproduced > curated > source ...)
  evidence   presence of PoC / verification evidence / exploit context
  term       exact technical-term overlap between query and record
  code       query identifier appears in affected_function / vulnerable_code
  solc       query states a Solidity version and the record's matches

Nothing here fabricates a score: unknown facts leave a factor at 1.0.
"""

from __future__ import annotations

import re
from typing import Any

_TOKEN_RE = re.compile(r"[a-z0-9_]+")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
_KW_VERSION_RE = re.compile(
    r"(?:solidity|solc|pragma)\s*(?:version)?\s*\^?\s*(\d+)\.(\d+)(?:\.(\d+))?",
    re.IGNORECASE)
_TRIPLE_VERSION_RE = re.compile(r"\b(\d+)\.(\d+)\.(\d+)\b")
_BARE_VERSION_RE = re.compile(r"\b(\d+)\.(\d+)(?:\.(\d+))?\b")


def parse_version(text: str) -> tuple[int, int] | None:
    """Parse a bare `X.Y[.Z]` version (used for an EXPLICIT solc argument)."""
    m = _BARE_VERSION_RE.search(text or "")
    return (int(m.group(1)), int(m.group(2))) if m else None

# Documented, bounded weights. Reproduced > curated > sourced > heuristic.
VALIDATION_WEIGHTS: dict[str, float] = {
    "reproduced": 1.30,
    "curated": 1.20,
    "source": 1.06,
    "llm-enriched": 1.04,
    "heuristic": 1.00,
}
UNKNOWN_VALIDATION_FACTOR = 0.98
MAX_TERM_FACTOR = 1.25
CODE_FACTOR = 1.10
EVIDENCE_FACTOR = 1.12
EVIDENCE_CONTEXT_FACTOR = 1.06
SOLC_FACTOR = 1.12


def tokens(text: str) -> set[str]:
    return {t for t in _TOKEN_RE.findall((text or "").lower())
            if len(t) > 2 and not t.isdigit()}


def code_identifiers(code: str) -> set[str]:
    return {m.lower() for m in _IDENT_RE.findall(code or "")}


def parse_query_version(query: str) -> tuple[int, int] | None:
    """A Solidity version the query implies, or None. Only keyword-anchored
    (solidity/solc/pragma) or a full x.y.z triple is accepted — a bare '0.8'
    is NOT treated as a version to avoid false matches."""
    m = _KW_VERSION_RE.search(query or "")
    if m:
        return int(m.group(1)), int(m.group(2))
    m = _TRIPLE_VERSION_RE.search(query or "")
    if m:
        return int(m.group(1)), int(m.group(2))
    return None


def _record_version(row: dict[str, Any]) -> tuple[int, int] | None:
    v = str(row.get("solc_version") or "").strip()
    m = re.match(r"^(\d+)\.(\d+)", v)
    return (int(m.group(1)), int(m.group(2))) if m else None


def profile_factor(row: dict[str, Any], profile: dict[str, Any] | None) -> float:
    if not profile:
        return 1.0
    if row.get("kb_group") in profile.get("kb_groups", ()) \
            or row.get("category") in profile.get("categories", ()):
        return float(profile.get("boost", 1.0))
    return 1.0


def validation_factor(row: dict[str, Any]) -> float:
    vs = str(row.get("verification_status") or "").strip().lower()
    return VALIDATION_WEIGHTS.get(vs, UNKNOWN_VALIDATION_FACTOR)


def evidence_factor(row: dict[str, Any]) -> float:
    f = 1.0
    if any(row.get(k) for k in ("poc_code", "poc_reference", "test_result",
                                "verification_evidence")):
        f *= EVIDENCE_FACTOR
    if row.get("preconditions") and (row.get("attack_scenario")
                                     or row.get("exploit_sequence")):
        f *= EVIDENCE_CONTEXT_FACTOR
    return f


def _record_terms(row: dict[str, Any]) -> set[str]:
    parts = [row.get("title"), row.get("category"), row.get("subcategory"),
             row.get("affected_function"), row.get("affected_contract"),
             row.get("cwe_id"), row.get("swc_id"), row.get("root_cause")]
    tags = row.get("tags") or []
    if isinstance(tags, (list, tuple)):
        parts.extend(str(t) for t in tags)
    terms = tokens(" ".join(str(p) for p in parts if p))
    terms |= code_identifiers(str(row.get("vulnerable_code") or ""))
    return terms


def term_factor(query: str, row: dict[str, Any]) -> tuple[float, float]:
    """Return (factor, overlap_ratio). Ratio is |query tokens present| / |q|."""
    q = tokens(query)
    if not q:
        return 1.0, 0.0
    ratio = len(q & _record_terms(row)) / len(q)
    return 1.0 + min(MAX_TERM_FACTOR - 1.0, (MAX_TERM_FACTOR - 1.0) * ratio), ratio


def code_factor(query: str, row: dict[str, Any]) -> bool:
    qidents = tokens(query) & code_identifiers(
        f"{row.get('affected_function') or ''} "
        f"{row.get('vulnerable_code') or ''}")
    return bool(qidents)


def solc_factor(query: str, row: dict[str, Any], *, explicit: str | None = None
                ) -> bool:
    want = parse_query_version(query)
    if not want and explicit:
        want = parse_version(explicit)
    got = _record_version(row)
    return bool(want and got and want == got)


# Bounded weights for the target-contract context match (Phase 5).
_CTX_WEIGHT_NAME = 0.08      # function / state-var / external-call identifier
_CTX_WEIGHT_STANDARD = 0.06  # token standard
_CTX_WEIGHT_TRAIT = 0.04     # protocol characteristic
_CTX_WEIGHT_CATEGORY = 0.05  # vulnerability category
_CTX_WEIGHT_SOLC = 0.05      # solidity version
_CTX_MAX = 0.35


def context_factor(row: dict[str, Any], context: dict[str, Any] | None
                   ) -> tuple[float, list[str]]:
    """Match a record against the TARGET CONTRACT's context. Returns
    (factor, matched-signal labels). Honest: only real overlaps are reported."""
    if not context:
        return 1.0, []
    signals: list[str] = []
    bump = 0.0
    txt = " ".join(str(row.get(k) or "") for k in (
        "title", "description", "root_cause", "vulnerable_code",
        "affected_function", "attack_entry", "impact", "remediation",
        "category", "subcategory", "tags")).lower()
    rtoks = tokens(txt) | code_identifiers(str(row.get("vulnerable_code") or ""))
    for fn in context.get("functions") or []:
        if str(fn).lower() in rtoks:
            signals.append(f"function {fn}")
            bump += _CTX_WEIGHT_NAME
            break
    for sv in context.get("state_vars") or []:
        if str(sv).lower() in rtoks:
            signals.append(f"state variable {sv}")
            bump += _CTX_WEIGHT_NAME
            break
    row_ext = " ".join(str(x) for x in (row.get("external_calls") or [])).lower()
    for ec in context.get("external_calls") or []:
        if str(ec).lower() in row_ext or str(ec).lower() in txt:
            signals.append(f"external call {ec}")
            bump += _CTX_WEIGHT_NAME
            break
    for std in context.get("token_standards") or []:
        if str(std).lower() in txt:
            signals.append(f"token standard {std}")
            bump += _CTX_WEIGHT_STANDARD
    for tr in context.get("traits") or []:
        if str(tr).lower() in txt:
            signals.append(f"protocol trait {tr}")
            bump += _CTX_WEIGHT_TRAIT
    cats = [str(c).lower() for c in (context.get("categories") or [])]
    if row.get("category") and str(row["category"]).lower() in cats:
        signals.append(f"category {row['category']}")
        bump += _CTX_WEIGHT_CATEGORY
    want = context.get("solc")
    got = _record_version(row)
    if want and got and str(want) == f"{got[0]}.{got[1]}":
        signals.append(f"solidity {want}")
        bump += _CTX_WEIGHT_SOLC
    return 1.0 + min(_CTX_MAX, bump), sorted(set(signals))


def rerank(candidates: list[dict[str, Any]], *, query: str, profile: dict[str, Any]
           | None, solc: str | None = None,
           context: dict[str, Any] | None = None
           ) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Order candidates by base RRF times the bounded factors above.

    ``candidates`` items: {"key","row","rrf","vector_rank","lexical_rank"}.
    ``solc`` (optional) is an explicit version requirement to match against a
    record's stored solc_version (adds the solc signal even if the query text
    does not state one). Returns (ordered_candidates, diagnostics_by_key)."""
    diag: dict[str, dict[str, Any]] = {}
    scored: list[tuple[float, int, dict[str, Any]]] = []
    for idx, c in enumerate(candidates):
        row, key = c["row"], c["key"]
        pf = profile_factor(row, profile)
        vf = validation_factor(row)
        ef = evidence_factor(row)
        tf, ratio = term_factor(query, row)
        cf = code_factor(query, row)
        sf = solc_factor(query, row, explicit=solc)
        ctxf, ctxsig = context_factor(row, context)
        final = c["rrf"] * pf * vf * ef * tf * (CODE_FACTOR if cf else 1.0) \
            * (SOLC_FACTOR if sf else 1.0) * ctxf
        why: list[str] = []
        if c.get("vector_rank") is not None:
            why.append(f"vector rank {c['vector_rank'] + 1}")
        if c.get("lexical_rank") is not None:
            why.append(f"lexical rank {c['lexical_rank'] + 1}")
        if pf != 1.0:
            why.append(f"profile match x{pf:g}")
        if vf != 1.0:
            why.append(f"validation '{row.get('verification_status')}' x{vf:g}")
        if ef != 1.0:
            why.append(f"evidence present x{ef:g}")
        if cf:
            why.append("code/function identifier match")
        if sf:
            why.append("solidity version match")
        if ratio > 0:
            why.append(f"{int(round(ratio * 100))}% query-term overlap")
        for sig in ctxsig:
            why.append(f"target-context: {sig}")
        diag[key] = {
            "rrf_score": round(c["rrf"], 6),
            "boosted_score": round(final, 6),
            "profile": (profile or {}).get("name") if profile else None,
            "signals": {
                "profile": round(pf, 4), "validation": round(vf, 4),
                "evidence": round(ef, 4), "term_overlap": round(tf, 4),
                "code_match": bool(cf), "solc_match": bool(sf),
                "term_overlap_ratio": round(ratio, 4),
            },
            "why": why,
            "context_factor": round(ctxf, 4),
            "context_signals": ctxsig,
            "vector_rank": c.get("vector_rank"),
            "lexical_rank": c.get("lexical_rank"),
            "matched_legs": sum(1 for x in (c.get("vector_rank"),
                                            c.get("lexical_rank"))
                                if x is not None),
        }
        scored.append((final, idx, c))
    scored.sort(key=lambda t: (-t[0], t[1]))
    return [c for _s, _i, c in scored], diag
