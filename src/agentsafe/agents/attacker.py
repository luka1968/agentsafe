"""Section 5 — attacker simulation and exploitability analysis.

For every actionable candidate, build a concrete attacker model and an
execution sketch derived from the real code semantics (state reads/writes,
external calls and their order within the body). The model answers the
exploitability questions that decide whether a candidate can be a *confirmed*
vulnerability:

    who is the attacker, do they need permissions or capital, is the state
    reachable, are multiple transactions needed, does a third party or an
    external contract's behavior matter, and what is the plausible impact.

Honesty is structural: anything not evidenced stays ``unknown``; the model
never invents an execution order or a capital requirement. When the attack
depends on unreachable code, unavailable permissions, or the behavior of an
external contract whose source is absent, the model is infeasible and the
caller must NOT confirm the finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from agentsafe.agents.reachability import ReachabilityModel

__all__ = ["AttackerModel", "build_attacker_model"]

_PAUSE_RE = re.compile(r"pause|circuit\s*breaker|emergency", re.IGNORECASE)
_SEQ_HINT = re.compile(
    r"\b(then|subsequent|after\s+that|first|second|multi-?step|sequence|"
    r"followed\s+by)\b",
    re.IGNORECASE,
)
_FUND_IMPACT_RE = re.compile(
    r"fund|drain|steal|withdraw|loss|theft|token|eth\b|balance|mint|solvency|"
    r"insolven|steal|transfer",
    re.IGNORECASE,
)
# Only when the CLAIM itself leans on an external contract behaving a certain
# way does an unavailable external body become a blocker. An attacker-controlled
# callback (the attacker IS the external contract) is not such an assumption.
_EXT_ASSUMPTION = re.compile(
    r"oracle|price\s+feed|returns?\s+(?:true|false|a\s+value)|assumes?|"
    r"token\s+returns?|no-?return|usdt|rebasing|fee-?on-?transfer|chainlink|"
    r"twap|getreserves|latestround|protocol\s+returns|reverts?",
    re.IGNORECASE,
)


@dataclass
class AttackerModel:
    caller: str = "unknown"                     # who + ordinary vs privileged
    ordinary_external_account: str = "unknown"  # yes | no | unknown
    permissions: list[str] = field(default_factory=list)
    capital_required: list[str] = field(default_factory=list)
    flash_loan_relevant: str = "no"             # possible | no
    multi_transaction: str = "unknown"          # yes | no | unknown
    interruptible: str = "unknown"              # yes | no | unknown
    external_dependencies: list[str] = field(default_factory=list)
    external_behavior_required: str = "none identified"
    economic_worth: str = "unknown"             # never guessed
    max_impact: str = "not stated"
    feasible: str = "unknown"                   # yes | no | unknown
    blockers: list[str] = field(default_factory=list)
    sequence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "caller": self.caller,
            "ordinary_external_account": self.ordinary_external_account,
            "permissions": list(self.permissions),
            "capital_required": list(self.capital_required),
            "flash_loan_relevant": self.flash_loan_relevant,
            "multi_transaction": self.multi_transaction,
            "interruptible": self.interruptible,
            "external_dependencies": list(self.external_dependencies),
            "external_behavior_required": self.external_behavior_required,
            "economic_worth": self.economic_worth,
            "max_impact": self.max_impact,
            "feasible": self.feasible,
            "blockers": list(self.blockers),
            "sequence": list(self.sequence),
        }


def _unresolved_calls(intel: Any | None) -> set[str]:
    """Normalize ``unresolved_externals`` (entries look like
    ``"C.pay: token.transfer (external contract body not in source)"``) to the
    bare call tokens (``"token.transfer"``)."""
    out: set[str] = set()
    for raw in getattr(intel, "unresolved_externals", ()) or ():
        s = str(raw)
        if ": " in s:
            s = s.split(": ", 1)[1]
        s = s.split(" (", 1)[0].strip()
        if s:
            out.add(s)
    return out


def _sequence(fn: Any) -> list[str]:
    """Order the events the function's body actually performs (read / external
    call / write) by their first occurrence in the body. Semantics, not
    invention: if the body is unavailable, no sequence is produced."""
    body = getattr(fn, "body", "") or ""
    if not body:
        return []
    events: list[tuple[int, str]] = []
    for var in sorted(getattr(fn, "reads", ()) or ()):
        i = body.find(var)
        if i >= 0:
            events.append((i, f"read state {var}"))
    for call in sorted(getattr(fn, "external_calls", ()) or ()):
        member = str(call).split(".")[-1]
        i = body.find(member)
        if i >= 0:
            events.append((i, f"external call {call}"))
    for var in sorted(getattr(fn, "writes", ()) or ()):
        i = body.find(var)
        if i >= 0:
            events.append((i, f"write state {var}"))
    events.sort(key=lambda t: t[0])
    return [f"{n}. {label}" for n, (_i, label) in enumerate(events, start=1)]


def build_attacker_model(
    finding: Any,
    model: ReachabilityModel | None,
    *,
    intel: Any | None = None,
    paths: list[dict[str, Any]] | None = None,
) -> AttackerModel:
    """Build the attacker model for one finding from reachability + intel +
    enumerated attack paths. Deterministic; unknown stays unknown."""
    am = AttackerModel()
    claim = " ".join(
        str(getattr(finding, k, "") or "")
        for k in ("title", "description", "attack_scenario", "impact")
    )

    loc = None
    key = None
    fn = None
    if model is not None:
        loc = model.function_at(
            getattr(finding, "file_path", None), getattr(finding, "line_start", None)
        )
        if loc is not None:
            key = loc.key
            fn = loc.fn

    unresolved = _unresolved_calls(intel)

    # -- caller / permissions / reachability --------------------------------
    if model is not None and loc is not None:
        if model.attacker_can_reach(loc) is True:
            am.caller = "external account (no special role)"
            am.ordinary_external_account = "yes"
        elif key in model.reachable:
            gates = model.gating_guards(key)
            am.caller = "privileged caller"
            am.ordinary_external_account = "no"
            am.permissions = gates or ["authorization required"]
            am.blockers.append(
                "requires authorization: " + "; ".join(gates or ["restricted"])
            )
        elif model.reachability(loc) == "not_reachable":
            am.caller = "no external caller (internal only)"
            am.ordinary_external_account = "no"
            am.blockers.append(
                "function is not reachable from any external entry point"
            )

    if fn is not None:
        am.permissions = sorted(
            set(am.permissions + [f"modifier {m}" for m in (fn.modifiers or [])])
        )
        if fn.mutability == "payable" or "msg.value" in (fn.body or ""):
            am.capital_required.append("ETH via msg.value")
        if fn.token_calls:
            am.capital_required.append("token inflow/balance")
        am.external_dependencies = sorted(set(fn.external_calls or ()))

    am.flash_loan_relevant = "possible" if am.capital_required else "no"

    # -- external-contract assumption ---------------------------------------
    dep_on_unresolved: list[str] = []
    for c in am.external_dependencies:
        if c in unresolved or str(c).split(".")[0] in unresolved:
            dep_on_unresolved.append(c)
    if dep_on_unresolved:
        am.external_behavior_required = (
            "external contract(s) not in source (behavior not verified): "
            + ", ".join(dep_on_unresolved[:4])
        )
        if _EXT_ASSUMPTION.search(claim):
            am.external_behavior_required = (
                "yes — the claim assumes behavior of an external contract whose "
                "source is not provided"
            )
            am.blockers.append(
                "attack depends on the behavior of an external contract whose "
                "body is not in the analyzed source ("
                + ", ".join(dep_on_unresolved[:4])
                + ")"
            )

    # -- multiple transactions (grounded in enumerated paths) ---------------
    mt = "unknown"
    if paths and key:
        hits = [
            p for p in paths if key in (p.get("functions") or [])
        ]
        if any((p.get("transaction_count") or 1) > 1 for p in hits):
            mt = "yes"
        elif hits:
            mt = "no"
    if mt == "unknown" and _SEQ_HINT.search(claim):
        mt = "possible"
    am.multi_transaction = mt

    # -- interruptibility (admin pause / circuit breaker present) ------------
    blob_parts: list[str] = []
    if intel is not None:
        for c in getattr(intel, "contracts", ()) or ():
            blob_parts.extend(getattr(c, "state_vars", ()) or ())
            for f in getattr(c, "functions", ()) or ():
                blob_parts.append(f.name)
                blob_parts.extend(f.modifiers or ())
    am.interruptible = (
        "possible (admin pause / circuit breaker present)"
        if _PAUSE_RE.search(" ".join(blob_parts))
        else "unknown"
    )

    # -- impact / economic worth --------------------------------------------
    am.max_impact = str(getattr(finding, "impact", "") or "") or "not stated"
    if am.feasible != "no" and _FUND_IMPACT_RE.search(am.max_impact):
        am.economic_worth = "potentially (impact states fund/value loss)"
    # economic worth is never asserted as certain from prose alone.

    # -- feasibility ---------------------------------------------------------
    if am.blockers:
        am.feasible = "no"
    elif am.ordinary_external_account == "yes":
        am.feasible = "yes"
    else:
        am.feasible = "unknown"

    if fn is not None:
        am.sequence = _sequence(fn)
    return am
