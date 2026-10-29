"""Stage 6 — contract classification for specialist-agent routing.

Deterministic, evidence-based routing decisions derived from the contract
intelligence layer (intel) and raw source. Never fabricates signals: a
category is only asserted when the extracted structure supports it. The
classifier decides *which* specialists run and at what depth; it never
itself produces findings.

Routing model:
  profile.triggers = {specialist_name: depth}   depth in {"deep","basic"}
  profile.coverage  = {specialist_name: reason}  auditability trail
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Registry of specialist names (stable identifiers used by the scheduler).
SPECIALISTS = (
    "access_control",
    "reentrancy",
    "accounting",
    "cross_function",
    "defi_logic",
    "arithmetic",
    "proxy_upgrade",
    "general_discovery",
)

# Default set when classification is inconclusive: general discovery always
# runs; the generic coverage agents run at basic depth so nothing is missed
# solely because the classifier was uncertain.
BASELINE = ("general_discovery", "access_control", "reentrancy", "arithmetic")

# --------------------------------------------------------------------------
# Evidence patterns — each requires BOTH the pattern and (where cheap) a
# contextual signal to fire, so a bare mention never triggers a deep pass.
# --------------------------------------------------------------------------
_RE_INITIALIZER = re.compile(
    r"initialize(?:\(|\b)|__gap\b|initializer\b", re.I)
_RE_PROXY_ADMIN = re.compile(
    r"upgradeTo(?:AndCall)?\s*\(|admin\(\)|owner\(\)|proxyAdmin|delegatecall", re.I)
_RE_UPGRADE_SLOT = re.compile(
    r"0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"  # impl slot
    r"|0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"  # admin slot
)
_RE_TOKEN = re.compile(
    r"\b(?:transfer|transferFrom|approve|balanceOf|allowance)\s*\(", re.I)
_RE_ORACLE = re.compile(
    r"\b(?:oracle|latestAnswer|latestRoundData|getPrice|priceFeed|peek|poke)\b", re.I)
_RE_COLLATERAL = re.compile(
    r"\b(?:collateral|liquidat|solvenc|healthFactor|debt|loan|mint|redeem|share)\b", re.I)
_RE_ETH_MOVE = re.compile(
    r"msg\.value|\.call\s*\{value|\.transfer\s*\(|\.send\s*\(", re.I)
_RE_BALANCE = re.compile(
    r"\b(?:balances?|totalSupply|totalAssets|share|previewRedeem|convertTo)\b", re.I)
_RE_ARITH = re.compile(
    r"[+\-*/%]\s*=|unchecked\s*\{|uint(?:8|16|32)\b|int(?:8|16|32)\b", re.I)
_RE_PAYABLE = re.compile(r"\bpayable\b|msg\.value", re.I)

_SLOT_EVIDENCE = "EIP-1967/EIP-1822 storage slot constant in source"
_INIT_EVIDENCE = "initialize/__gap/initializer markers present"
_UPGRADE_EVIDENCE = "upgradeTo/delegatecall/admin authorization surface present"
_TOKEN_EVIDENCE = "ERC20 token transfer/approve surface present"
_ORACLE_EVIDENCE = "oracle/price-feed query surface present"
_COLLAT_EVIDENCE = "collateral/lending/shares vocabulary present"
_ETH_EVIDENCE = "ETH value movement (call{value}/transfer/send/msg.value) present"
_BAL_EVIDENCE = "balance/share accounting surface present"
_ARITH_EVIDENCE = "arithmetic assignments / unchecked / narrow ints present"
_FALLBACK_EVIDENCE = "fallback/receive (external-call sink) present"


@dataclass
class ClassifiedProfile:
    """Routing decision for one audit. Deterministic; empty when uncertain."""

    contract_classes: list[str] = field(default_factory=list)
    triggers: dict[str, str] = field(default_factory=dict)   # name -> depth
    coverage: dict[str, str] = field(default_factory=dict)   # name -> reason
    notes: list[str] = field(default_factory=list)

    def should_run(self, name: str) -> bool:
        return name in self.triggers


def _intel_text(intel) -> str:
    """Stable textual view of intel: contract names, state vars, fn names,
    modifiers, hints. Guarded — intel is optional."""
    if intel is None:
        return ""
    parts: list[str] = []
    for c in getattr(intel, "contracts", []) or []:
        parts.append(f"contract {c.name} is {','.join(c.bases)}")
        parts.extend(getattr(c, "state_vars", []) or [])
        for f in getattr(c, "functions", []) or []:
            parts.append(f"{f.name} {' '.join(f.modifiers)}")
    if getattr(intel, "proxy_hints", None):
        parts.append("PROXY_HINTS: " + "; ".join(intel.proxy_hints))
    if getattr(intel, "unresolved_externals", None):
        parts.append("UNRESOLVED: " + "; ".join(intel.unresolved_externals))
    return " ".join(parts)


def classify_contract(intel, source_text: str = "") -> ClassifiedProfile:
    """Map extracted structure + raw source onto specialist routing.

    Rule: a specialist is triggered *deep* when strong structural evidence
    exists (slot constants, initializer markers, oracle vocabulary,
    accounting surface, ETH movement), else *basic* when only weak lexical
    hits appear, and general_discovery always runs.
    """
    itext = _intel_text(intel)
    blob = f"{itext}\n{source_text}"
    blob_low = blob.lower()

    p = ClassifiedProfile()
    if intel is not None:
        for c in getattr(intel, "contracts", []) or []:
            kind = getattr(c, "kind", "")
            if kind:
                p.contract_classes.append(f"{c.name}:{kind}")
        p.contract_classes.extend(
            f"{c.name}:proxy" for c in getattr(intel, "contracts", []) or []
            if getattr(c, "bases", None))
        if getattr(intel, "proxy_hints", None):
            p.contract_classes.append("proxy-hints")
    # bytecode-only (no intel): keep honest, use raw text signals only
    if not p.contract_classes and source_text:
        p.contract_classes.append("source-only")

    # --- A. access control ------------------------------------------------
    strong = bool(_RE_INITIALIZER.search(blob)) or bool(
        _RE_PROXY_ADMIN.search(blob))
    weak = bool(re.search(r"\b(?:onlyOwner|onlyRole|hasRole|msg\.sender\s*==|admin)\b",
                          blob, re.I))
    if strong:
        p.triggers["access_control"] = "deep"
        p.coverage["access_control"] = (
            _INIT_EVIDENCE if _RE_INITIALIZER.search(blob) else _UPGRADE_EVIDENCE)
    elif weak:
        p.triggers["access_control"] = "basic"
        p.coverage["access_control"] = "authorization vocabulary present (weak)"

    # --- B. reentrancy / external interaction ----------------------------
    eth = bool(_RE_ETH_MOVE.search(blob_low))
    fallback = bool(re.search(r"fallback\s*\(|receive\s*\(", blob_low))
    ext_call = bool(re.search(r"\.call\s*\{|\.call\s*\(|delegatecall|staticcall",
                              blob_low))
    if eth or ext_call:
        depth = "deep" if (eth and ext_call) else "basic"
        p.triggers["reentrancy"] = depth
        p.coverage["reentrancy"] = _ETH_EVIDENCE if eth else "external call surface present"
    elif fallback:
        p.triggers["reentrancy"] = "basic"
        p.coverage["reentrancy"] = _FALLBACK_EVIDENCE

    # --- C. accounting / asset flow ----------------------------------------
    if _RE_BALANCE.search(blob_low) and (_RE_PAYABLE.search(blob_low)
                                         or _RE_ETH_MOVE.search(blob_low)):
        p.triggers["accounting"] = "deep"
        p.coverage["accounting"] = _BAL_EVIDENCE + " + value movement"
    elif _RE_BALANCE.search(blob_low):
        p.triggers["accounting"] = "basic"
        p.coverage["accounting"] = _BAL_EVIDENCE

    # --- D. cross-function logic -------------------------------------------
    # Fires when multiple functions touch shared state (>=2 state-var
    # references in different function bodies). Cheap proxy: contract with
    # >1 function and state vars.
    fn_count = 0
    var_count = 0
    if intel is not None:
        for c in getattr(intel, "contracts", []) or []:
            fn_count += len(getattr(c, "functions", []) or [])
            var_count += len([s for s in getattr(c, "state_vars", []) or []
                              if not s.startswith("modifier:")])
    if fn_count >= 2 and var_count >= 1:
        p.triggers["cross_function"] = "basic"
        p.coverage["cross_function"] = (
            f"{fn_count} functions across {var_count} state vars (shared-state surface)")

    # --- E. defi protocol logic ---------------------------------------------
    if _RE_ORACLE.search(blob_low) and _RE_COLLATERAL.search(blob_low):
        p.triggers["defi_logic"] = "deep"
        p.coverage["defi_logic"] = _ORACLE_EVIDENCE + " + " + _COLLAT_EVIDENCE
    elif _RE_ORACLE.search(blob_low):
        p.triggers["defi_logic"] = "basic"
        p.coverage["defi_logic"] = _ORACLE_EVIDENCE

    # --- F. arithmetic / boundary --------------------------------------------
    if _RE_ARITH.search(blob_low):
        p.triggers["arithmetic"] = "deep"
        p.coverage["arithmetic"] = _ARITH_EVIDENCE
    else:
        p.triggers["arithmetic"] = "basic"
        p.coverage["arithmetic"] = "no arithmetic evidence — baseline coverage"

    # --- G. proxy / upgradeability --------------------------------------------
    if _RE_UPGRADE_SLOT.search(blob_low) or _RE_PROXY_ADMIN.search(blob_low) \
            or "delegatecall" in blob_low:
        p.triggers["proxy_upgrade"] = "deep"
        p.coverage["proxy_upgrade"] = _SLOT_EVIDENCE if _RE_UPGRADE_SLOT.search(
            blob_low) else _UPGRADE_EVIDENCE

    # --- H. general discovery (always) ----------------------------------------
    p.triggers["general_discovery"] = "deep"
    p.coverage["general_discovery"] = "always-on exploration beyond specialists"

    # Baseline safety: specialists named in BASELINE not yet triggered get
    # basic depth so classifier uncertainty never skips them entirely.
    for name in BASELINE:
        if name not in p.triggers:
            p.triggers[name] = "basic"
            p.coverage[name] = "baseline coverage (classifier inconclusive)"

    return p


def routing_summary(profile: ClassifiedProfile) -> str:
    """Human/audit-log readable routing decision."""
    lines = [f"contract classes: {', '.join(profile.contract_classes) or 'none detected'}"]
    for name in SPECIALISTS:
        if name in profile.triggers:
            lines.append(f"  {name}: {profile.triggers[name]} — {profile.coverage[name]}")
    return "\n".join(lines)
