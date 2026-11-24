"""Section 12 — finding quality: the required evidence package.

Every reported finding must carry the full evidence package. This module audits
that package deterministically (presence only — it never invents content) and
records what is missing, so a finding is never padded and severity is never
inflated to look valuable.

The fifteen required elements map onto existing fields / metadata:
title, severity, verdict, classification, location, vulnerable code, root
cause, attacker model, preconditions, attack sequence, state transitions,
impact, exploitability, supporting evidence, counterarguments, validation
outcome, PoC status, remediation, confidence.

Severity is kept strictly separate from confidence and verification status: a
HIGH-severity POTENTIAL finding is NOT a confirmed HIGH vulnerability.
"""

from __future__ import annotations

from typing import Any

__all__ = ["REQUIRED_ELEMENTS", "finding_quality", "ensure_poc_record"]

# Required elements in the section's order.
REQUIRED_ELEMENTS = (
    "title",
    "severity",
    "verdict",
    "classification",
    "location",
    "vulnerable_code",
    "root_cause",
    "attacker_model",
    "preconditions",
    "attack_sequence",
    "state_transitions",
    "impact",
    "exploitability",
    "supporting_evidence",
    "counterarguments",
    "validation_outcome",
    "poc_status",
    "remediation",
    "confidence",
)


def _md(f: Any, *path: str) -> Any:
    cur = getattr(f, "metadata", None) or {}
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _has(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, dict)):
        return len(value) > 0
    return True


def finding_quality(f: Any) -> dict[str, Any]:
    """Presence audit of the required evidence package. No content is created."""
    am = _md(f, "attacker_model") or {}
    present: dict[str, bool] = {
        "title": _has(getattr(f, "title", "")),
        "severity": getattr(f, "severity", None) is not None,
        "verdict": getattr(f, "status", None) is not None,
        "classification": _has(getattr(f, "swc_id", None))
        or _has(getattr(f, "cwe_id", None))
        or str(getattr(getattr(f, "category", None), "value", "unknown")) != "unknown",
        "location": _has(getattr(f, "file_path", None))
        and _has(getattr(f, "line_start", None)),
        "vulnerable_code": _has(getattr(f, "evidence", "")),
        "root_cause": _has(getattr(f, "description", "")),
        "attacker_model": bool(am),
        "preconditions": _has(getattr(f, "preconditions", "")),
        "attack_sequence": _has(getattr(f, "attack_scenario", "")),
        "state_transitions": _has(getattr(f, "state_dependencies", None))
        or _has(am.get("sequence")),
        "impact": _has(getattr(f, "impact", "")),
        "exploitability": _has(am.get("feasible")) or _has(_md(f, "disposition")),
        "supporting_evidence": _has(getattr(f, "supporting_evidence", None))
        or _has(getattr(f, "knowledge_references", None)),
        "counterarguments": _has(getattr(f, "contradicting_evidence", None))
        or _has(_md(f, "reconciliation")),
        "validation_outcome": _has(getattr(f, "validation_method", None))
        or _has(getattr(f, "validation_result", None)),
        "poc_status": _has(_md(f, "poc", "status")),
        "remediation": _has(getattr(f, "recommendation", "")),
        "confidence": getattr(f, "confidence", None) is not None,
    }
    missing = [name for name in REQUIRED_ELEMENTS if not present[name]]
    return {
        "present": present,
        "missing": missing,
        "present_count": len(REQUIRED_ELEMENTS) - len(missing),
        "required_count": len(REQUIRED_ELEMENTS),
        "complete": not missing,
    }


def ensure_poc_record(f: Any) -> None:
    """Guarantee a PoC status is present for every actionable finding. Planning
    is honest: when no plan was produced the status is ``not_attempted`` — never
    a fabricated result. Mutates ``f.metadata`` (caller owns the copy)."""
    md = getattr(f, "metadata", None)
    if not isinstance(md, dict):
        return
    if _has(md.get("poc", {}).get("status") if isinstance(md.get("poc"), dict) else None):
        return
    md["poc"] = {
        "status": "not_attempted",
        "reason": (
            "PoC not attempted: not prioritised (no execution backend and/or "
            "lower impact); confidence unchanged"
        ),
        "executed": False,
        "backend": "none",
    }
