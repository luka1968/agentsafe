"""Section 10 — explicit, evidence-based proxy / contract classification.

A contract is NEVER classified as a proxy merely because a name or a pattern
looks similar. The classification requires structural evidence and is explicit:

    CONFIRMED_PROXY  — an EIP-1967 storage slot (implementation/beacon/admin) or
                       a delegatecalling fallback (proxy execution context) is
                       present in the analyzed source
    PROBABLE_PROXY   — delegatecall and/or an upgrade mechanism + initializer
                       markers, but no storage-slot evidence
    REGULAR_CONTRACT — no delegatecall, no proxy slot, no upgrade mechanism
    UNKNOWN          — the provided source is insufficient to decide

Every classification records the evidence that produced it. Implementation
addresses are reported ONLY when an unambiguous literal is present; proxy →
implementation relationships are never invented.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "ProxyClass",
    "ProxyClassification",
    "classify_contract",
    "classify_contracts",
]

# Canonical EIP-1967 slot constants.
IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
BEACON_SLOT = ("0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50")
ADMIN_SLOT = ("0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103")


class ProxyClass:
    CONFIRMED = "CONFIRMED_PROXY"
    PROBABLE = "PROBABLE_PROXY"
    REGULAR = "REGULAR_CONTRACT"
    UNKNOWN = "UNKNOWN"


_DELEGATE_RE = re.compile(r"delegatecall\s*\(")
_UPGRADE_FN_RE = re.compile(r"upgradeto|upgradebeacontoandcall", re.IGNORECASE)
_INIT_RE = re.compile(
    r"initializer|reinitializer|disableinitializers|\binitialize\b", re.IGNORECASE
)
_NAME_HINT_RE = re.compile(r"proxy|upgradeable|uups|beacon", re.IGNORECASE)
_ADDR_RE = re.compile(r"(?<![0-9a-fA-F])0x[0-9a-fA-F]{40}(?![0-9a-fA-F])")


@dataclass
class ProxyClassification:
    contract: str
    classification: str = ProxyClass.UNKNOWN   # CONFIRMED | PROBABLE | REGULAR | UNKNOWN
    pattern: str = "none"                      # uups | transparent | beacon | unknown | none
    evidence: list[str] = field(default_factory=list)
    signals: dict[str, Any] = field(default_factory=dict)
    implementation_address: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": self.contract,
            "classification": self.classification,
            "pattern": self.pattern,
            "evidence": list(self.evidence),
            "signals": dict(self.signals),
            "implementation_address": self.implementation_address,
        }


def classify_contract(contract: Any) -> ProxyClassification:
    """Classify ONE contract from its own extracted structure. Conservatively
    UNKNOWN when there is nothing analyzable to decide from."""
    c = contract
    fns = list(getattr(c, "functions", ()) or ())
    svars = getattr(c, "state_vars", {}) or {}
    bodies = " ".join((getattr(f, "body", "") or "") for f in fns)
    svars_txt = " ".join(svars)
    names = " ".join(f.name for f in fns)
    mods = " ".join(m for f in fns for m in (getattr(f, "modifiers", ()) or ()))
    blob = f"{bodies} {svars_txt} {names} {mods}"
    low = blob.lower()

    if not fns and not svars_txt.strip():
        return ProxyClassification(
            contract=getattr(c, "name", "?"),
            classification=ProxyClass.UNKNOWN,
            pattern="unknown",
            evidence=[
                "insufficient source: no functions or state variables to analyze"
            ],
            signals={},
        )

    impl_slot = IMPL_SLOT in blob or "implementation_slot" in low or "erc1967" in low
    beacon_slot = BEACON_SLOT in blob or "beacon_slot" in low
    admin_slot = ADMIN_SLOT in blob or "admin_slot" in low
    deleg = bool(_DELEGATE_RE.search(low))
    has_fallback = any(f.name in ("fallback", "_fallback") for f in fns)
    # A delegatecalling fallback is the EIP-1967 proxy execution context; the
    # delegatecall may sit in a helper the fallback calls, so this is
    # contract-level (fallback present AND a delegatecall present).
    fallback_deleg = has_fallback and deleg
    upgrade_fn = bool(_UPGRADE_FN_RE.search(names))
    # `initializer` markers can be modifier definitions (captured in
    # state_vars), applied modifiers, or function names — search the whole blob.
    init = bool(_INIT_RE.search(blob))
    name_hint = bool(_NAME_HINT_RE.search(getattr(c, "name", "") or ""))

    evidence: list[str] = []
    if impl_slot:
        evidence.append("EIP-1967 implementation storage slot referenced")
    if beacon_slot:
        evidence.append("EIP-1967 beacon storage slot referenced")
    if admin_slot:
        evidence.append("EIP-1967 admin storage slot referenced")
    if fallback_deleg:
        evidence.append("fallback delegatecalls (proxy execution context)")
    if deleg and not fallback_deleg:
        evidence.append("delegatecall present")
    if upgrade_fn:
        evidence.append("upgrade mechanism present (upgradeTo/upgradeToAndCall/...)")
    if init:
        evidence.append("initializer / upgradeable markers present")
    if name_hint:
        evidence.append(
            f"contract name '{getattr(c, 'name', '?')}' resembles a proxy (weak)"
        )

    slot = impl_slot or beacon_slot or admin_slot
    if slot:
        cls = ProxyClass.CONFIRMED
    elif fallback_deleg:
        cls = ProxyClass.CONFIRMED
    elif deleg and upgrade_fn and init:
        cls = ProxyClass.PROBABLE
    elif deleg or upgrade_fn:
        cls = ProxyClass.PROBABLE
    else:
        cls = ProxyClass.REGULAR
        if name_hint:
            evidence.append(
                "name resembles a proxy but there is NO structural evidence; "
                "classified REGULAR_CONTRACT"
            )

    if beacon_slot or "upgradebeacontoandcall" in low:
        pattern = "beacon"
    elif admin_slot:
        pattern = "transparent"
    elif impl_slot and upgrade_fn:
        pattern = "uups"
    elif upgrade_fn and init and not admin_slot and not impl_slot:
        pattern = "uups"
    elif impl_slot and not upgrade_fn:
        pattern = "transparent"
    elif deleg:
        pattern = "unknown"
    else:
        pattern = "none"

    # Implementation address: only from an unambiguous literal. Never invented,
    # and never a proxy->implementation relationship.
    impl_addr: str | None = None
    literals = sorted(set(_ADDR_RE.findall(bodies)))
    if impl_slot and len(literals) == 1:
        impl_addr = literals[0]
        evidence.append(
            f"implementation address literal {impl_addr} present "
            "(relationship NOT independently verified)"
        )

    return ProxyClassification(
        contract=getattr(c, "name", "?"),
        classification=cls,
        pattern=pattern,
        evidence=evidence,
        signals={
            "eip1967_implementation_slot": impl_slot,
            "eip1967_beacon_slot": beacon_slot,
            "eip1967_admin_slot": admin_slot,
            "delegatecall": deleg,
            "fallback_delegatecall": fallback_deleg,
            "upgrade_mechanism": upgrade_fn,
            "initializer": init,
            "name_hint": name_hint,
        },
        implementation_address=impl_addr,
    )


def classify_contracts(intel: Any) -> list[ProxyClassification]:
    if intel is None:
        return []
    return [classify_contract(c) for c in getattr(intel, "contracts", ()) or ()]
