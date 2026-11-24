"""Phase 6 — false-positive intelligence and counterexamples.

Detects the technical signals in the TARGET contract that commonly generate
false positives (non-reverting send/call, revert atomicity, per-account
mappings, unchecked arithmetic, compiler-bug versions, proxy-by-pattern, ...),
then retrieves the validated counterexample records (kb_group E/F) that argue
AGAINST such claims and renders them as a CHECKLIST.

A counterexample never rejects a finding by itself: the rendered block instructs
the agent to confirm the actual code/execution context and to report only when
the record's ``evidence_required`` criteria are met and it is not excluded by
``known_limitations``. Historical patterns are supporting intelligence, not
verdicts.
"""

from __future__ import annotations

from typing import Any

# Ordered by specificity (most specific triggers first) so that a contract only
# pulls the few counterexamples most relevant to it.
FP_TRIGGERS: list[dict[str, Any]] = [
    {"label": "transfer reverts (atomic rollback)",
     "markers": ("transfer(", "safetransfer", ".transfer"),
     "query": "transfer reverts transaction rollback atomic state error-handling"},
    {"label": "send() non-reverting return value",
     "markers": ("send(",),
     "query": "send returns false no revert check return value non-reverting"},
    {"label": "low-level call() success flag",
     "markers": ("call(", "call{", "delegatecall(", ".delegatecall("),
     "query": "low-level call success flag ignored non-reverting delegatecall"},
    {"label": "proxy classification requires evidence",
     "markers": ("proxy", "erc1967", "upgradeto", "implementationslot",
                 "delegatecall"),
     "query": "proxy classification storage slot evidence erc1967 upgrade"},
    {"label": "token decimals / unit scaling",
     "markers": ("decimals", "1e18", "1e6", "wad", "ray"),
     "query": "token decimals units scaling normalization false positive"},
    {"label": "per-account mapping isolation",
     "markers": ("mapping(", "balances[", "balanceof", "[msg.sender]"),
     "query": "mapping balances msg.sender per account isolated not summed"},
    {"label": "compiler-version bug is not proof",
     "markers": ("pragma solidity", "pragma"),
     "query": "compiler version historical bug list reachability trigger construct"},
    {"label": "unchecked / overflow arithmetic reachability",
     "markers": ("unchecked", "overflow", "**", "uint256("),
     "query": "unchecked arithmetic overflow reachability attacker control realistic values"},
    {"label": "integer division truncation",
     "markers": ("/ totalsupply", "/ totalassets", "/ rate", "/ 1e", "/ /**"),
     "query": "integer division truncation rounding direction false positive"},
]

MAX_TRIGGERS = 3


def detect_fp_triggers(text: str, context: Any = None) -> list[dict[str, Any]]:
    """Return up to MAX_TRIGGERS counterexample triggers evidenced by the code
    text (and contract context). Pure substring detection — no inference."""
    low = (text or "").lower()
    found: list[dict[str, Any]] = []
    for trig in FP_TRIGGERS:
        if any(m in low for m in trig["markers"]):
            found.append(trig)
        if len(found) >= MAX_TRIGGERS:
            break
    return found


def _query_for(triggers: list[dict[str, Any]], category: str | None) -> str:
    parts = [t["query"] for t in triggers]
    if category:
        parts.append(str(category))
    parts.append("false positive counterexample refutation evidence required")
    return " ".join(parts)


def retrieve_counterexamples(kb: Any, *, text: str = "", context: Any = None,
                             category: str | None = None, limit: int = 2
                             ) -> list[dict[str, Any]]:
    """Retrieve counterexample records (kb_group E/F) for the detected
    triggers. Compatible with the Neon store (context-aware) and the JSONL
    fallback. Returns [] when nothing is evidenced (never fabricated)."""
    if kb is None:
        return []
    triggers = detect_fp_triggers(text, context)
    if not triggers and not category:
        return []
    query = _query_for(triggers, category)
    solc = getattr(context, "solc", None) if context is not None else None
    match = context.to_match_dict() if hasattr(context, "to_match_dict") else None
    try:
        records = kb.search(query, focus="validation", limit=limit,
                            profile="false_positive", kb_groups=("E", "F"),
                            solc=solc, context=match)
    except TypeError:
        records = kb.search(query, focus="validation", limit=limit,
                            profile="false_positive", kb_groups=("E", "F"))
    labels = [t["label"] for t in triggers]
    for r in records:
        r.setdefault("_retrieval", {})["fp_triggers"] = labels
    return records


def _as_items(v: Any) -> list[str]:
    """Normalize a stored list field. The FP columns are TEXT, so a JSONL array
    round-trips as a Postgres array literal `{a,b}` — accept list, `{...}`, or
    plain string and return clean items."""
    if not v:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v if str(x).strip()]
    s = str(v).strip()
    if s.startswith("{") and s.endswith("}"):
        body, items, cur, inq, i = s[1:-1], [], "", False, 0
        while i < len(body):
            ch = body[i]
            if ch == '"':
                if inq and i + 1 < len(body) and body[i + 1] == '"':
                    cur += '"'
                    i += 2
                    continue
                inq = not inq
            elif ch == "," and not inq:
                items.append(cur)
                cur = ""
                i += 1
                continue
            else:
                cur += ch
            i += 1
        if cur:
            items.append(cur)
        return [x.strip().strip('"') for x in items if x.strip()]
    return [s]


def render_counterexamples(records: list[dict[str, Any]],
                           triggers: list[dict[str, Any]] | None = None) -> str:
    """Render counterexamples as an explicit false-positive CHECKLIST. Never a
    verdict — the agent must still confirm the actual code."""
    if not records:
        return ""
    labels = ", ".join(t["label"] for t in (triggers or []))
    lines = [
        "=== FALSE-POSITIVE / COUNTEREXAMPLE CHECKS "
        "(UNTRUSTED; validated public-doc patterns) ===",
        f"Detected target signals: {labels}" if labels else "",
        "These are KNOWN false-positive patterns. Use them to AVOID reporting",
        "incorrect findings. Do NOT reject a real finding merely because it",
        "resembles one of these: confirm the actual code path and execution",
        "context, and report ONLY if the code matches the pattern AND the",
        "'evidence required to overturn' criteria below are NOT met.",
    ]
    for i, r in enumerate(records, 1):
        fp = _as_items(r.get("fp_patterns"))
        ev = _as_items(r.get("evidence_required"))
        lim = _as_items(r.get("known_limitations"))
        lines.append(f"--- FP-{i}: {r.get('title') or r.get('id')} ---")
        if fp:
            lines.append("false-positive pattern: " + "; ".join(str(x) for x in fp))
        why = r.get("why_safe") or r.get("root_cause")
        if why:
            lines.append(f"why it is not a bug: {why}")
        if ev:
            lines.append("evidence required to overturn: "
                         + "; ".join(str(x) for x in ev))
        if lim:
            lines.append("known limitations (when the FP does NOT apply): "
                         + "; ".join(str(x) for x in lim))
    lines.append("=== END FALSE-POSITIVE CHECKS ===")
    return "\n".join(line for line in lines if line != "")
