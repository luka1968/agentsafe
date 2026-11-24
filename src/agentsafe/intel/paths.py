"""Stage 7 — bounded cross-function attack-path enumeration.

Core requirement: functions are never analyzed in isolation. For suspicious
state variables and security properties we:
1. Identify relevant readers and writers (state_dependency_graph).
2. Determine access restrictions and prerequisites (modifiers/guards).
3. Trace internal calls and relevant external interactions (call_graph).
4. Generate BOUNDED candidate sequences of state-changing operations.
5. Record the exact functions, state variables, and prerequisites.

Targeted exploration over unbounded enumeration: paths start from either
(a) a suspicious state variable (write -> callers -> external entry) or
(b) an external entry point -> sink (external call / transfer / delegatecall /
unchecked arithmetic). Depth and path-count limits come from explicit bounds.

Every path is inferred from static evidence. `reproduced` stays False unless
an external test harness confirms it — inferred != reproduced, always stated.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from agentsafe.intel.extract import ContractIntel, FunctionIntel
from agentsafe.intel.graph import (
    call_graph,
    sink_inventory,
    state_dependency_graph,
)

__all__ = [
    "AttackPath",
    "PathOrigin",
    "enumerate_attack_paths",
    "suspicious_state_variables",
    "render_paths",
]

# "state_var_followup" | "sink_enumeration" | "cross_read_write" | "multi_tx_sequence"
PathOrigin = str


def _field(obj: Any, name: str, default: Any = None) -> Any:
    """Read a field from either an AttackPath object or its dict form. The
    interchange form is the dict (report + agent material), so renderers must
    accept both - a renderer that only accepts objects silently drops the
    hypotheses."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


@dataclass
class AttackPath:
    functions: list[str] = field(default_factory=list)     # entry -> ... -> step
    entry_points: list[str] = field(default_factory=list)  # external entry fns
    state_variables: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)  # per-step modifiers/guards
    origin: PathOrigin = "sink_enumeration"
    depth: int = 0
    reproduced: bool = False        # True only after external test confirmation
    evidence: list[str] = field(default_factory=list)      # per-step source slices
    # --- Stage C attack-path attributes (evidence-derived; empty = unknown) ---
    required_permissions: list[str] = field(default_factory=list)  # modifiers on chain
    state_transitions: list[str] = field(default_factory=list)     # writes along chain
    external_dependencies: list[str] = field(default_factory=list)  # external calls
    attacker_controlled_inputs: list[str] = field(default_factory=list)  # inputs
    capital_requirements: list[str] = field(default_factory=list)  # ETH/token balance
    impact: list[str] = field(default_factory=list)                # ETH/delegatecall/tokens
    cross_contract: bool = False
    transaction_count: int = 1      # >1 for multi-transaction sequences
    attacker_reachable: str = "unknown"  # yes | no | unknown (annotated from reachability)

    def to_dict(self) -> dict[str, Any]:
        return {
            "functions": list(self.functions),
            "entry_points": sorted(set(self.entry_points)),
            "state_variables": sorted(set(self.state_variables)),
            "prerequisites": list(self.prerequisites),
            "origin": self.origin,
            "depth": self.depth,
            "reproduced": self.reproduced,
            "evidence": list(self.evidence),
            "required_permissions": sorted(set(self.required_permissions)),
            "state_transitions": list(self.state_transitions),
            "external_dependencies": sorted(set(self.external_dependencies)),
            "attacker_controlled_inputs": sorted(set(self.attacker_controlled_inputs)),
            "capital_requirements": list(self.capital_requirements),
            "impact": sorted(set(self.impact)),
            "cross_contract": self.cross_contract,
            "transaction_count": self.transaction_count,
            "attacker_reachable": self.attacker_reachable,
        }


# ---------------------------------------------------------------------------
# suspicious state selection (targeted, evidence-driven)
# ---------------------------------------------------------------------------

_SUSPICIOUS_NAMES = re.compile(
    r"(balance|balances|total|assets|shares|debt|collateral|lock|paused|"
    r"initialized|authorized|limit|reserve|fee|price|rate)", re.IGNORECASE)


def suspicious_state_variables(
    intel: ContractIntel,
    state: dict[str, dict[str, list[str]]],
    max_vars: int = 12,
) -> list[str]:
    """State vars that both READERS and WRITERS touch AND whose name matches a
    security-relevant category. Cross-function relevance = read by >=1 fn and
    written by a DIFFERENT fn (a single-fn self-contained var is not a
    cross-function target)."""
    out: list[str] = []
    for key, deps in state.items():
        readers = deps["readers"]
        writers = deps["writers"]
        if not readers or not writers:
            continue
        # cross-function: a reader is not among the writers (different fns)
        if not (set(readers) - set(writers)):
            continue
        var = key.split(".")[1]
        if not _SUSPICIOUS_NAMES.search(var):
            continue
        out.append(key)
        if len(out) >= max_vars:
            break
    return out


def _entry_points(intel: ContractIntel) -> list[FunctionIntel]:
    return [f for c in intel.contracts for f in c.functions
            if f.visibility == "external"
            or (f.visibility == "public" and f.mutability not in ("view", "pure"))]


def _fn_key(f: FunctionIntel) -> str:
    return f"{f.contract}.{f.name}"


def _fn_lookup(intel: ContractIntel) -> dict[str, FunctionIntel]:
    return {_fn_key(f): f for c in intel.contracts for f in c.functions}


def _prereq_of(f: FunctionIntel) -> list[str]:
    out = []
    for m in f.modifiers:
        out.append(f"modifier:{m}")
    for g in f.guards:
        out.append(f"guard:{g[:70]}")
    return out


def _attacker_inputs(f: FunctionIntel) -> list[str]:
    """Inputs an attacker controls on this step: declared parameters plus
    msg.sender/msg.value when the body actually uses them."""
    out: list[str] = []
    for part in (f.params or "").split(","):
        idents = re.findall(r"[A-Za-z_]\w*", part)
        if idents:
            out.append(idents[-1])
    body = f.body or ""
    if "msg.sender" in body:
        out.append("msg.sender")
    if "msg.value" in body:
        out.append("msg.value")
    return sorted(set(out))


def _impact_of(f: FunctionIntel) -> list[str]:
    """Impact surface this step can reach, from extracted call evidence."""
    out: list[str] = []
    if f.ether_calls:
        out.append("ETH transfer")
    if f.delegatecalls:
        out.append("delegatecall")
    if f.token_calls:
        out.append("token transfer")
    return out


# ---------------------------------------------------------------------------
# enumeration
# ---------------------------------------------------------------------------

def enumerate_attack_paths(
    intel: ContractIntel,
    max_depth: int = 3,
    max_paths: int = 24,
    include_sinks: bool = True,
) -> list[AttackPath]:
    """Bounded, targeted path enumeration.

    Pass A (state_var_followup): reverse BFS from every suspicious state
    variable's writers up to external entry points.
    Pass B (sink_enumeration): forward BFS from each external entry through
    internal calls until a sink (external call / transfer / delegatecall /
    unchecked arithmetic) is reached.
    Pass C (cross_read_write): chains where fn A writes a var that fn B reads
    in a different contract/function sequence.

    All bounds are explicit (max_depth, max_paths). Nothing is invented.
    """
    if not intel.contracts:
        return []
    cg = call_graph(intel)
    state = state_dependency_graph(intel)
    lookup = _fn_lookup(intel)
    entry_keys = {_fn_key(e) for e in _entry_points(intel)}
    paths: list[AttackPath] = []
    seen: set[tuple[str, ...]] = set()

    def _add(path: list[str], origin: PathOrigin,
             svars: list[str] | None = None,
             transaction_count: int = 1) -> None:
        t = tuple(path)
        if t in seen:
            return
        seen.add(t)
        paths.append(_build_path(intel, lookup, cg, path, origin, svars,
                                 transaction_count))
        return

    # -- pass A: suspicious state var -> writers -> callers -> entry ----------
    suspicious = suspicious_state_variables(intel, state)
    if suspicious:
        for var in suspicious:
            writers = state[var]["writers"]
            for w in writers:
                chain = _reverse_to_entry(cg, w, max_depth=max_depth)
                if chain:
                    _add(chain, "state_var_followup", [var])
                else:
                    # writer not reachable from an entry in-bounds: record the
                    # writer chain as far as it goes (still useful evidence).
                    _add([w], "state_var_followup", [var])
            if len(paths) >= max_paths:
                break

    # -- pass B: entry -> sinks ----------------------------------------------
    if include_sinks:
        sink_fns = {s["fn"]: s for s in sink_inventory(intel)}
        for entry in _entry_points(intel):
            key = _fn_key(entry)
            for chain in _forward_to_sink(cg, key, sink_fns,
                                          max_depth=max_depth):
                _add(chain, "sink_enumeration")
                if len(paths) >= max_paths:
                    break
            if len(paths) >= max_paths:
                break

    # -- pass C: cross read/write pairs (single-tx chain, or a 2-transaction
    #    sequence when a writer ENTRY and a reader ENTRY are distinct calls) ---
    for key, deps in state.items():
        readers, writers = deps["readers"], deps["writers"]
        cross = (set(readers) - set(writers)) and (set(writers) - set(readers))
        if not cross:
            continue
        for w in sorted(set(writers))[:2]:
            for r in sorted(set(readers))[:2]:
                both_entries = w in entry_keys and r in entry_keys
                _add(
                    [w, r],
                    "multi_tx_sequence" if both_entries else "cross_read_write",
                    [key],
                    2 if both_entries else 1,
                )
                if len(paths) >= max_paths:
                    break
            if len(paths) >= max_paths:
                break
        if len(paths) >= max_paths:
            break

    paths.sort(key=lambda p: (p.origin, p.depth))
    return paths[:max_paths]


def _build_path(intel: ContractIntel,
                lookup: dict[str, FunctionIntel],
                cg: dict[str, list[str]],
                seq: list[str],
                origin: PathOrigin,
                svars: list[str] | None,
                transaction_count: int = 1) -> AttackPath:
    path = AttackPath(functions=list(seq), origin=origin,
                      depth=len(seq) - 1, transaction_count=transaction_count)
    if svars:
        path.state_variables = list(svars)
    contracts: set[str] = set()
    for key in seq:
        f = lookup.get(key)
        if f is None:
            continue
        contracts.add(f.contract)
        path.prerequisites.extend(_prereq_of(f))
        path.required_permissions.extend(f.modifiers)
        if f.writes:
            path.state_transitions.append(
                f"{key} writes {','.join(sorted(f.writes))}")
        path.external_dependencies.extend(f.external_calls)
        path.attacker_controlled_inputs.extend(_attacker_inputs(f))
        if f.mutability == "payable" or "msg.value" in (f.body or ""):
            path.capital_requirements.append(f"{key}: ETH (msg.value)")
        if f.token_calls:
            path.capital_requirements.append(f"{key}: token balance")
        path.impact.extend(_impact_of(f))
        path.evidence.append(
            f"{key} [{f.visibility}/{f.mutability or 'nonpayable'} "
            f"mods:{','.join(f.modifiers) or '-'}] "
            f"writes:{','.join(sorted(f.writes)) or '-'} "
            f"reads:{','.join(sorted(f.reads)) or '-'}")
        if f.visibility == "external" or (
                f.visibility == "public" and f.mutability not in ("view", "pure")):
            if key not in path.entry_points:
                path.entry_points.append(key)
    path.entry_points = sorted(set(path.entry_points))
    path.cross_contract = len(contracts) > 1
    return path


def _reverse_to_entry(cg: dict[str, list[str]], fn: str,
                      max_depth: int) -> list[str] | None:
    """Reverse BFS from fn up to a function with no callers (entry)."""
    if not _callers_of(cg, fn):
        return [fn]
    frontier = [(fn, [fn])]
    seen: set[str] = set()
    while frontier:
        cur, path = frontier.pop(0)
        if len(path) - 1 >= max_depth:
            continue
        for caller in _callers_of(cg, cur):
            if caller in seen:
                continue
            seen.add(caller)
            new_path = [caller] + path
            if not _callers_of(cg, caller):
                return new_path  # top of the call tree
            frontier.append((caller, new_path))
    return None


def _forward_to_sink(cg: dict[str, list[str]], entry: str,
                     sink_fns: dict[str, Any],
                     max_depth: int) -> list[list[str]]:
    """Forward BFS from an entry until a sink function is reached."""
    out: list[list[str]] = []
    frontier = [(entry, [entry])]
    seen: set[str] = set()
    while frontier:
        cur, path = frontier.pop(0)
        if len(path) - 1 >= max_depth:
            continue
        if cur in sink_fns and len(path) > 1:
            out.append(path)
            continue
        for callee in cg.get(cur, []):
            if callee in seen:
                continue
            seen.add(callee)
            frontier.append((callee, path + [callee]))
    return out


def _callers_of(cg: dict[str, list[str]], fn: str) -> list[str]:
    return sorted(k for k, v in cg.items() if fn in v)


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def render_paths(paths: list[Any]) -> str:
    """Human-readable section for the report / agent material. Accepts both
    AttackPath objects and their dict form: the agent material carries dicts,
    so a renderer that demanded objects would silently drop every hypothesis."""
    if not paths:
        return "[no cross-function attack paths enumerated (bounded)]"
    lines = ["CROSS-FUNCTION ATTACK PATHS (bounded enumeration, inferred):"]
    for i, p in enumerate(paths, start=1):
        functions = _field(p, "functions", []) or []
        origin = _field(p, "origin", "?")
        depth = _field(p, "depth", 0)
        reproduced = _field(p, "reproduced", False)
        reach = _field(p, "attacker_reachable", "unknown")
        txs = _field(p, "transaction_count", 1) or 1
        status = "reproduced-in-test" if reproduced else "inferred"
        lines.append(
            f"- #{i} [{origin}] {status} depth={depth} txs={txs} "
            f"attacker_reachable={reach} {' -> '.join(functions)}")
        svars = _field(p, "state_variables", []) or []
        if svars:
            lines.append(f"    state: {', '.join(svars)}")
        perms = _field(p, "required_permissions", []) or []
        if perms:
            lines.append(f"    permissions required: {', '.join(perms)}")
        deps = _field(p, "external_dependencies", []) or []
        if deps:
            lines.append(f"    external calls: {', '.join(deps)}")
        inputs = _field(p, "attacker_controlled_inputs", []) or []
        if inputs:
            lines.append(f"    attacker-controlled inputs: {', '.join(inputs[:6])}")
        impact = _field(p, "impact", []) or []
        if impact:
            lines.append(f"    impact surface: {', '.join(impact)}")
        for pre in (_field(p, "prerequisites", []) or [])[:3]:
            lines.append(f"    prerequisite: {pre}")
    lines.append(
        "NOTE: inferred paths are static hypotheses. They are attack-path "
        "candidates, not findings; each requires validation before reporting. "
        "attacker_reachable=no means every external entry on the path is "
        "authorization-gated in the analyzed source.")
    return "\n".join(lines)
