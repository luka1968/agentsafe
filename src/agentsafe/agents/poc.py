"""Section 8 — executable verification / proof of concept.

Reality in this environment: no EVM execution backend is available. ``forge``
resolves to an unrelated npm shim, and there is no ``anvil``/``cast``/``solc``/
``geth``/``evm`` binary and no ``py-evm``/``eth-tester``/``revm``. The existing
Stage-8 harness (``validation/targeted_tests.py``) already reports
``not_executed`` honestly when Foundry is absent.

This module therefore implements the strongest RELIABLE alternative:

- a deterministic, machine-readable **PoC plan** per high-impact finding
  (realistic attacker, preconditions, concrete transaction sequence, expected
  state transition, and the impact predicate that must hold to prove impact),
  derived from the finding + attacker model + intel — never invented;
- an **honest status classifier** that distinguishes the five required
  outcomes: ``successful_exploitation`` / ``expected_revert`` / ``failed_attack``
  / ``inconclusive`` / ``environment_limitation``;
- a hard honesty gate: a run that merely compiles or passes WITHOUT
  demonstrating the claimed impact is NOT proof (-> ``inconclusive``), and no
  result is ever fabricated. A PoC can never, on its own, upgrade a finding's
  confidence; absence of a backend is an ``environment_limitation`` that
  retains the existing confidence level.

PoC work is prioritised for high-impact / financially significant findings.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "PoCPlan",
    "PoCResult",
    "build_poc_plan",
    "classify_poc_result",
    "assess_poc",
    "poc_priority",
    "foundry_available",
]

HIGH_IMPACT_SEVERITIES = {"critical", "high"}
HIGH_IMPACT_CATEGORIES = {"reentrancy", "access_control", "oracle", "arithmetic", "accounting"}
_FUND_IMPACT_RE = re.compile(
    r"fund|drain|steal|withdraw|loss|theft|insolven|solven|token|eth\b|"
    r"balance|mint|share|asset|collateral|liquidat",
    re.IGNORECASE,
)


@dataclass
class PoCPlan:
    """A minimal, honest reproduction plan. Not execution — a specification."""

    attacker: str = "unknown"
    preconditions: list[str] = field(default_factory=list)
    sequence: list[str] = field(default_factory=list)
    expected_state_transition: str = ""
    impact_assertion: str = ""
    priority: str = "normal"  # high | normal
    backend: str = "none"     # foundry | none

    def to_dict(self) -> dict[str, Any]:
        return {
            "attacker": self.attacker,
            "preconditions": list(self.preconditions),
            "sequence": list(self.sequence),
            "expected_state_transition": self.expected_state_transition,
            "impact_assertion": self.impact_assertion,
            "priority": self.priority,
            "backend": self.backend,
        }


@dataclass
class PoCResult:
    status: str = "inconclusive"
    reason: str = ""
    executed: bool = False
    backend: str = "none"
    environment: str = ""
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "executed": self.executed,
            "backend": self.backend,
            "environment": self.environment,
            "evidence": list(self.evidence),
        }


def foundry_available() -> bool:
    """True only when a REAL Foundry ``forge`` is present. The npm shim that
    happens to be named ``forge`` must never be mistaken for Foundry."""
    from agentsafe.validation.targeted_tests import FOUNDRY_BIN

    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, local tool probe
            [FOUNDRY_BIN, "--version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except Exception:
        return False
    if proc.returncode != 0:
        return False
    out = f"{proc.stdout or ''}\n{proc.stderr or ''}".lower()
    first = (proc.stdout or "").strip().splitlines()[:1]
    if first and re.match(r"\s*forge\s+\d", first[0]):
        return True
    return "foundry" in out


def poc_priority(finding: Any) -> str:
    """High-impact / financially-significant findings get PoC effort first."""
    sev = getattr(getattr(finding, "severity", None), "value", "")
    if sev in HIGH_IMPACT_SEVERITIES:
        return "high"
    cat = getattr(getattr(finding, "category", None), "value", "")
    if cat in HIGH_IMPACT_CATEGORIES:
        return "high"
    if _FUND_IMPACT_RE.search(str(getattr(finding, "impact", "") or "")):
        return "high"
    return "normal"


def build_poc_plan(
    finding: Any,
    *,
    attacker_model: dict[str, Any] | None = None,
    backend: str = "none",
) -> PoCPlan:
    """Deterministically assemble the plan from the finding's own evidence and
    its attacker model. No new assertions are invented here."""
    am = attacker_model
    if am is None:
        meta = getattr(finding, "metadata", None) or {}
        am = meta.get("attacker_model") if isinstance(meta, dict) else None
    am = am or {}

    preconds: list[str] = []
    caller = am.get("caller")
    if caller:
        preconds.append(f"attacker: {caller}")
    for p in am.get("permissions") or []:
        preconds.append(f"requires permission: {p}")
    for c in am.get("capital_required") or []:
        preconds.append(f"capital: {c}")
    if am.get("multi_transaction") in ("yes", "possible"):
        preconds.append("multiple transactions required")
    fp = str(getattr(finding, "preconditions", "") or "").strip()
    if fp:
        preconds.append(fp)

    sequence = list(am.get("sequence") or [])

    return PoCPlan(
        attacker=str(caller or "unknown"),
        preconditions=preconds,
        sequence=sequence,
        expected_state_transition=str(getattr(finding, "attack_scenario", "") or ""),
        impact_assertion=str(getattr(finding, "impact", "") or "").strip(),
        priority=poc_priority(finding),
        backend=backend,
    )


def classify_poc_result(
    run_result: str,
    *,
    impact_demonstrated: bool,
    revert_expected: bool = False,
    backend_available: bool = True,
) -> PoCResult:
    """Map an execution record to one of the five honest outcomes.

    ``run_result`` is the harness result: ``not_executed`` | ``passed`` |
    ``failed`` | ``error`` | ``skipped``. A pass WITHOUT a demonstrated impact
    is NOT proof (-> inconclusive)."""
    if run_result == "not_executed":
        if not backend_available:
            return PoCResult(
                status="environment_limitation",
                reason=(
                    "no EVM/Foundry execution backend is available in this "
                    "environment; the PoC was not executed — confidence is "
                    "unchanged and the plan is retained for a capable runner"
                ),
                executed=False,
                evidence=["backend unavailable"],
            )
        return PoCResult(
            status="inconclusive",
            reason="the PoC was not executed though a backend appears available",
            executed=False,
        )
    if run_result == "passed":
        if impact_demonstrated:
            return PoCResult(
                status="successful_exploitation",
                reason="execution reproduced the vulnerable state and the impact "
                "assertion held",
                executed=True,
                evidence=["impact assertion satisfied"],
            )
        return PoCResult(
            status="inconclusive",
            reason=(
                "the test passed but did NOT demonstrate the claimed impact; a "
                "passing or merely-compiling PoC is not proof"
            ),
            executed=True,
        )
    if run_result == "failed":
        if revert_expected:
            return PoCResult(
                status="expected_revert",
                reason="the call reverted as an existing protection dictates; the "
                "attack is blocked",
                executed=True,
                evidence=["revert observed as expected"],
            )
        return PoCResult(
            status="failed_attack",
            reason="execution ran but the attack did not reproduce the claimed "
            "impact",
            executed=True,
        )
    return PoCResult(
        status="inconclusive",
        reason=f"execution could not be interpreted (result={run_result!r})",
        executed=run_result in ("error",),
    )


def assess_poc(
    finding: Any,
    *,
    backend_available: bool,
    attacker_model: dict[str, Any] | None = None,
) -> tuple[PoCPlan, PoCResult]:
    """Plan a PoC for one finding and report its honest status in THIS
    environment (planning only; execution is delegated to the Stage-8 harness
    when a backend exists)."""
    plan = build_poc_plan(
        finding,
        attacker_model=attacker_model,
        backend="foundry" if backend_available else "none",
    )
    if not plan.impact_assertion:
        return plan, PoCResult(
            status="inconclusive",
            reason="no impact predicate to demonstrate; a PoC cannot prove a "
            "claim whose impact is unstated",
            backend=plan.backend,
        )
    if not backend_available:
        return plan, PoCResult(
            status="environment_limitation",
            reason=(
                "no EVM/Foundry execution backend is available in this "
                "environment; the PoC plan is retained but NOT executed — "
                "confidence unchanged"
            ),
            backend="none",
        )
    return plan, PoCResult(
        status="inconclusive",
        reason="PoC planned; execution is delegated to the Stage-8 targeted-test "
        "harness",
        backend="foundry",
    )
