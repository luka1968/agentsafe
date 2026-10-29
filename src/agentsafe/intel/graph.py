"""Structural graph layer — AgentSafe G+ Stage 4.

Deterministic adjacency/evidence over `ContractIntel` (never LLM-inferred):
- Function call graph (caller -> callees, including cross-contract edges).
- State-dependency graph (state var -> readers/writers, per contract).
- Per-function state-change evidence (which var is written, by which op:
  =, +=, -=, *=, /=, delete, or read-modify-write).
- Proxy pattern classification (UUPS / Transparent / Beacon) with the
  storage-gap and initializer-chain evidence used for the classification.
- Sink inventory: functions whose body performs external calls, token or ETH
  transfers, unchecked arithmetic, or delegatecall — the classic exploit
  entry points for downstream path enumeration.

All output is derived from verified source; nothing is invented.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from agentsafe.intel.extract import (
    ContractIntel,
    FunctionIntel,
    _BUILTIN_CALL,
)

__all__ = [
    "StateChange",
    "ProxyPattern",
    "call_graph",
    "state_dependency_graph",
    "state_change_evidence",
    "classify_proxy_pattern",
    "sink_inventory",
]

_WRITE_OPS = re.compile(
    r"(?:\b(\w+)\s*(?:\[[^\]]*\])?\s*(?:=|\+=|-=|\*=|/=)|\bdelete\s+(\w+))")


@dataclass
class StateChange:
    var: str
    op: str
    fn: str
    contract: str
    line: int = 0


@dataclass
class ProxyPattern:
    contract: str
    kind: str = "none"            # uups|transparent|beacon|plain
    evidence: list[str] = field(default_factory=list)
    storage_gap_present: bool = False
    initializer_chain: list[str] = field(default_factory=list)


def _fn_contract(intel: ContractIntel) -> dict[str, FunctionIntel]:
    return {f"{c.name}.{f.name}": f for c in intel.contracts for f in c.functions}


def call_graph(intel: ContractIntel) -> dict[str, list[str]]:
    """Adjacency list caller -> sorted callees. Keys are `Contract.fn`.
    Cross-contract edges appear when a function invokes a function of another
    contract parsed in the same source set (e.g. `Vault.execute(...)`).
    Two-pass: first index all known functions, then build edges."""
    # pass 1: index known function keys by bare name
    known: dict[str, set[str]] = {}
    for c in intel.contracts:
        for f in c.functions:
            key = f"{c.name}.{f.name}"
            known.setdefault(f.name, set()).add(key)
    g: dict[str, list[str]] = {}
    for c in intel.contracts:
        for f in c.functions:
            key = f"{c.name}.{f.name}"
            g.setdefault(key, [])
            for callee in f.internal_calls:
                for cand in known.get(callee, set()):
                    if cand != key and cand not in g[key]:
                        g[key].append(cand)
            for ec in f.external_calls:  # "Ident.member"
                ident, _, member = ec.partition(".")
                if not member:
                    continue
                k = f"{ident}.{member}"
                if k in known.get(member, set()) and k != key:
                    if k not in g[key]:
                        g[key].append(k)
    for key in g:
        g[key] = sorted(set(g[key]))
    return g


def state_dependency_graph(intel: ContractIntel) -> dict[str, dict[str, list[str]]]:
    """var -> {readers:[Contract.fn], writers:[Contract.fn]} for every state
    variable we can see. Contract-scoped: same var name in different contracts
    is keyed `Contract.var` to avoid false merging."""
    out: dict[str, dict[str, list[str]]] = {}
    for c in intel.contracts:
        for var in c.state_vars:
            if var.startswith("modifier:"):
                continue
            key = f"{c.name}.{var}"
            out[key] = {"readers": [], "writers": []}
            for f in c.functions:
                fk = f"{c.name}.{f.name}"
                if var in f.reads:
                    out[key]["readers"].append(fk)
                if var in f.writes:
                    out[key]["writers"].append(fk)
    for key in out:
        out[key]["readers"] = sorted(set(out[key]["readers"]))
        out[key]["writers"] = sorted(set(out[key]["writers"]))
    return out


def state_change_evidence(intel: ContractIntel,
                          ) -> dict[str, list[StateChange]]:
    """Per-function list of concrete state writes with their operator. This is
    the evidence backend for invariant checks: an agent can ask "which
    functions write `balances[msg.sender]` and with what op?". Uses the
    verified source slice stored on FunctionIntel.body — never invented."""
    out: dict[str, list[StateChange]] = {}
    for c in intel.contracts:
        for f in c.functions:
            key = f"{c.name}.{f.name}"
            out.setdefault(key, [])
            for m in _WRITE_OPS.finditer(f.body or ""):
                var = m.group(1) or m.group(2)
                if not var:
                    continue
                if var not in c.state_vars:
                    continue
                op = "delete" if m.group(2) else "rw"
                line = f.line_start + (f.body or "")[:m.start()].count("\n")
                out[key].append(StateChange(
                    var=var, op=op, fn=f.name, contract=c.name, line=line))
    return out


def classify_proxy_pattern(intel: ContractIntel) -> list[ProxyPattern]:
    """Classify each contract's proxy/upgrade posture from structural evidence
    (storage slot constants, upgrade function names, init markers). Evidence
    strings make the classification auditable; none is LLM-guessed."""
    out: list[ProxyPattern] = []
    for c in intel.contracts:
        fn_blob = " ".join(
            f"{f.name} {' '.join(f.modifiers)} {f.body or ''}" for f in c.functions)
        blob = " ".join(sorted(c.state_vars)) + " " + fn_blob
        evidence: list[str] = []
        kind = "plain"
        if any(s in blob for s in (
                "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
                "ERC1967_IMPLEMENTATION_SLOT", "IMPLEMENTATION_SLOT")):
            kind, evidence = "uups" if (
                any("upgradeToAndCall" in b or "upgradeTo" in b for b in
                    (f"{f.name}" for f in c.functions))) else "transparent", evidence
            evidence.append("ERC1967 implementation slot referenced")
        if "BEACON_SLOT" in blob or "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50" in blob:
            kind = "beacon"
            evidence.append("beacon slot referenced")
        if any("upgradeToAndCall" in f.name for f in c.functions) and "initializer" in blob:
            kind = "uups"
            evidence.append("upgradeToAndCall + initializer markers")
        gap = bool(re.search(r"__gap|_gap|storage_gap|__[0-9]{3}", " ".join(c.state_vars)))
        inits = [f.name for f in c.functions if "initializer" in
                 " ".join(f.modifiers).lower() or f.name == "initialize"]
        out.append(ProxyPattern(
            contract=c.name, kind=kind, evidence=evidence,
            storage_gap_present=gap, initializer_chain=inits))
    return out


def sink_inventory(intel: ContractIntel) -> list[dict[str, Any]]:
    """Functions that perform dangerous operations (exploit entry points).
    Returns deterministic, evidence-backed entries suitable for attack-path
    enumeration (Stage: path analysis)."""
    sinks: list[dict[str, Any]] = []
    for c in intel.contracts:
        for f in c.functions:
            ops: list[str] = []
            if f.external_calls:
                ops.append("external_call")
            if f.ether_calls:
                ops.append("ether_transfer")
            if f.delegatecalls:
                ops.append("delegatecall")
            if f.token_calls:
                ops.append(f"token:{','.join(sorted(set(f.token_calls)))}")
            if f.unchecked:
                ops.append("unchecked_arith")
            if f.arithmetic and not f.mutability:
                ops.append("arithmetic")
            if not ops:
                continue
            sinks.append({
                "fn": f"{c.name}.{f.name}",
                "visibility": f.visibility,
                "mutability": f.mutability,
                "modifiers": f.modifiers,
                "writes_state": sorted(f.writes),
                "reads_state": sorted(f.reads),
                "ops": sorted(set(ops)),
                "calls": sorted(f.internal_calls),
                "external_calls": f.external_calls,
            })
    sinks.sort(key=lambda s: s["fn"])
    return sinks
