"""Section 13 — specific, code-anchored remediation.

"For every confirmed finding, provide specific remediation guidance based on the
actual vulnerable implementation." This derives remediation anchored to the real
code (the verified mechanism and the exact location) when a deterministic rule
identified it. It never invents a fix: when nothing specific can be derived it
returns None and the existing recommendation is left untouched.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["specific_remediation", "apply_specific_remediation"]

_GENERIC = re.compile(
    r"recommend|consider|ensure|best\s+practice|should|harden|follow\s+best|"
    r"adhere|generally|review\s+the\s+code|proper\s+access",
    re.IGNORECASE,
)


def _md(f: Any, *path: str) -> Any:
    cur = getattr(f, "metadata", None) or {}
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _generic(text: str) -> bool:
    t = (text or "").strip()
    return (len(t) < 80) or bool(_GENERIC.search(t))


def specific_remediation(finding: Any, *, intel: Any = None) -> str | None:
    """Concrete remediation for a finding whose mechanism is deterministically
    known; None when it cannot be derived without inventing."""
    rule = str(_md(finding, "validation", "rule") or "")
    category = str(getattr(getattr(finding, "category", None), "value", ""))
    fp = getattr(finding, "file_path", None) or "the contract"
    ls = getattr(finding, "line_start", "?")
    loc = f"{fp}:{ls}"
    fns = getattr(finding, "affected_functions", None) or []
    fn = fns[0] if fns else "the affected function"
    ev_lines = [
        ln.strip()
        for ln in (getattr(finding, "evidence", "") or "").splitlines()
        if ln.strip()
    ]
    ev = ev_lines[0] if ev_lines else "the flagged statement"

    if rule.startswith("re1") or (category == "reentrancy" and "cei" in rule.lower()):
        return (
            f"Apply checks-effects-interactions in {fn} ({loc}): update all "
            f"affected state BEFORE the external call `{ev}` and perform the "
            f"call last; or guard {fn} with a reentrancy mutex (nonReentrant). "
            f"Verified mechanism: CEI violation"
            + (f" (rule {rule})." if rule else ".")
        )
    if rule.startswith("cr0"):
        return (
            f"At {loc}, remediate the exact statement `{ev}` in {fn} — the issue "
            f"is corroborated by independent tool evidence"
            + (f" (rule {rule})" if rule else "")
            + "; fix this specific implementation rather than applying generic "
            "hardening."
        )
    return None


def apply_specific_remediation(finding: Any, *, intel: Any = None) -> bool:
    """Set a specific remediation when the current one is missing or generic.
    Returns True when the recommendation was replaced."""
    current = (getattr(finding, "recommendation", "") or "").strip()
    if current and not _generic(current):
        return False
    spec = specific_remediation(finding, intel=intel)
    if not spec:
        return False
    finding.recommendation = spec
    return True
