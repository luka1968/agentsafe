"""Evidence-based severity assessment (documented, deterministic rubric).

Three orthogonal axes, never conflated:
- detection confidence  -> Finding.confidence (self-reported by LLM/detector;
  NEVER used to set severity)
- validation status     -> Finding.status (state machine; see schemas.py)
- impact severity       -> Finding.severity (THIS rubric)

Rubric
------
1. confirmed findings
   Severity starts from the claimed severity (the detector's or LLM's impact
   claim, preserved in `proposed_severity`), then is REDUCED one level for
   each of:
   a) privilege gate - exploitation requires an owner/admin/governance/
      role-holder key (compromise prerequisite, not a permissionless attack)
   b) mitigating controls - pausable, circuit breaker, timelock, rate limit,
      reentrancy guard, multisig-protected entry point in the flagged code
   Floor: low. The rubric never upgrades severity: corroboration upgrades
   the STATUS, not the impact score.
2. unvalidated candidates (potential, needs_manual_review)
   Capped at medium. A claim that nobody validated must not headline a
   customer report as critical/high. The original claim survives in
   `proposed_severity` and in by_status, so no genuine unresolved risk is
   silently discarded.
3. informational
   Severity is info by definition.
4. rejected
   Severity unchanged (rejected findings are excluded from the severity
   headline anyway and kept only for auditability).

Multi-LLM repetition never raises severity: only the state machine's
independent double-source rule upgrades a status, and confirmed findings
derive severity from THIS rubric, not from how many agents agreed.
"""

from __future__ import annotations

import re

from agentsafe.schemas import Finding, FindingStatus, Severity

_PRIVILEGE_GATE = re.compile(
    r"onlyowner|onlyadmin|onlygovernance|only\(\s*\w+\s*\)|"
    r"requires?\s+(?:the\s+)?(?:contract\s+)?(?:owner|admin|governance|operator)|"
    r"privileged\s+(?:role|caller|account)|authorized\s+accounts?\s+only",
    re.IGNORECASE,
)
_MITIGATION = re.compile(
    r"pausable|pause\(\)|circuit\s*breaker|timelock|time\s*lock|rate\s*limit|"
    r"nonreentrant|reentrancy\s*guard|multisig|multi\s*sig",
    re.IGNORECASE,
)

# Defect classes that are materially exploitable (fund/state loss, permanent
# harm) and, once CONFIRMED by double evidence, must never be under-reported
# as medium just because the LLM under-claimed.
_HIGH_IMPACT_CATEGORIES = {
    "reentrancy", "flash_loan", "oracle", "unhandled_exception",
    "accounting",
}

_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def _downgrade(s: Severity) -> Severity:
    """One level down, floored at low for confirmed findings (info never
    participates in confirmed-path reductions)."""
    if s is Severity.INFO:
        return s
    i = _ORDER.index(s)
    return _ORDER[min(i + 1, _ORDER.index(Severity.LOW))]


def _not_higher_than(s: Severity, cap: Severity) -> Severity:
    return s if _ORDER.index(s) >= _ORDER.index(cap) else cap


def assess(f: Finding) -> tuple[Severity, str]:
    """Return (assessed severity, documented basis string) for a finding that
    already carries its final validation status."""
    claimed = f.severity

    if f.status is FindingStatus.REJECTED:
        return claimed, "rubric:rejected_keeps_claim"

    if f.status is FindingStatus.INFORMATIONAL:
        return Severity.INFO, "rubric:informational"

    if f.status in (FindingStatus.POTENTIAL, FindingStatus.NEEDS_MANUAL_REVIEW):
        capped = _not_higher_than(claimed, Severity.MEDIUM)
        basis = (
            "rubric:unvalidated_capped_at_medium"
            if capped is not claimed
            else "rubric:unvalidated_within_cap"
        )
        return capped, basis

    # confirmed: claimed severity minus documented reductions, floor low
    text = " ".join(
        (f.title, f.description, f.evidence, f.preconditions, f.attack_scenario)
    )
    reductions: list[str] = []
    sev = claimed
    if _PRIVILEGE_GATE.search(text):
        sev = _downgrade(sev)
        reductions.append("privilege_gate")
    if _MITIGATION.search(text):
        sev = _downgrade(sev)
        reductions.append("mitigating_controls")
    # KB-corroborated double-evidence floor: when a defect class is CONFIRMED
    # by two independent sources (machine-proven + historical KB case), and it
    # is a materially-exploitable high-impact class, the customer report must
    # not under-report it as medium just because the LLM under-claimed. The
    # downward reductions above still apply first (a guarded reentrancy stays
    # downgraded). This is evidence-based, never claim-inflation.
    kb = (f.metadata.get("validation") or {}).get("kb_corroborated")
    if kb and f.category and f.category.value in _HIGH_IMPACT_CATEGORIES:
        # _ORDER is most-severe-first (CRITICAL=0 .. INFO=4): raise when the
        # current severity is LESS severe than HIGH (index HIGH+).
        if _ORDER.index(sev) > _ORDER.index(Severity.HIGH):
            sev = Severity.HIGH
            reductions.append("kb_corroborated_floor_high")
    basis = "rubric:confirmed" + (f"(-{'+'.join(reductions)})" if reductions else "")
    return sev, basis


# --- detector-id -> SWC enrichment (conservative, well-known ids only) --------
SWC_MAP: dict[str, str] = {
    "reentrancy-eth": "SWC-107",
    "reentrancy-no-eth": "SWC-107",
    "reentrancy-benign": "SWC-107",
    "reentrancy-event": "SWC-107",
    "reentrancy-unlimited-gas": "SWC-107",
    "integer-overflow": "SWC-101",
    "integer-underflow": "SWC-101",
    "arbitrary-send-eth": "SWC-105",
    "arbitrary-send-erc20": "SWC-105",
    "suicidal": "SWC-106",
    "unchecked-lowlevel": "SWC-104",
    "unchecked-transfer": "SWC-104",
    "unchecked-send": "SWC-104",
    "incorrect-equality": "SWC-115",
    "controlled-delegatecall": "SWC-112",
    "delegatecall-to-user-supplied-address": "SWC-112",
    "tx-origin": "SWC-115",
    "weak-prng": "SWC-120",
    "dependence-on-predictable-variable": "SWC-120",
    "timestamp-dependence": "SWC-116",
}


def enrich_swc(f: Finding) -> str | None:
    """Best-effort SWC id for a finding: explicit field > SWC-prefixed
    detector id > known detector map. Never guesses."""
    if f.swc_id:
        return f.swc_id
    det = (f.detector_id or "").strip()
    if det.upper().startswith("SWC-"):
        return det.upper()
    for key, swc in SWC_MAP.items():
        if key in det.lower():
            return swc
    return None
