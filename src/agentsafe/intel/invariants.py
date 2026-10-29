"""Stage 7 — candidate invariants: proposal, tracking, explicit validation.

Sources for invariant proposals (never invented):
- Source code patterns (deterministic regex + state-graph evidence).
- Protocol interfaces present in the source set (interface contracts).
- Optional protocol documentation strings supplied by the caller.
- Optional historical cases (KB retrieval) — provenance only, never proof.

Every record carries: statement, invariant type, relevant functions, state
variables, supporting source, evidence (verified source slices), prerequisites,
validation method, and an EXPLICIT result drawn from:

  holds_under_tested_conditions | violated | inconclusive | not_applicable

Passing finite static checks never proves an invariant always holds — the
limitations field states this per record. `violated` requires a concrete
evidence chain (a reachable call path + a state write that breaks the
statement), never a pattern smell.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal

from agentsafe.intel.graph import (
    call_graph,
    sink_inventory,
    state_change_evidence,
    state_dependency_graph,
)
from agentsafe.intel.extract import ContractIntel, FunctionIntel

__all__ = [
    "InvariantResult",
    "INVARIANT_RESULTS",
    "InvariantRecord",
    "INVARIANT_TYPES",
    "extract_invariants",
    "validate_invariants",
    "invariant_type_for",
    "render_invariants",
]

InvariantResult = Literal[
    "holds_under_tested_conditions", "violated", "inconclusive", "not_applicable"
]
INVARIANT_RESULTS = (
    "holds_under_tested_conditions", "violated", "inconclusive", "not_applicable"
)

INVARIANT_TYPES = (
    "asset_liability_accounting",   # totalAssets/totalSupply/balances consistency
    "withdrawal_limit",             # user can never withdraw more than their balance
    "collateral_debt",              # collateral >= debt / health-factor bounds
    "share_asset_conversion",       # convertToAssets(convertToShares(x)) round-trip
    "privileged_state",             # privileged state only mutable by authorized roles
    "valid_initialization",         # init runs at most once, before any use
    "token_accounting",             # transfers/burns mirrored in internal accounting
)

# ---------------------------------------------------------------------------
# record
# ---------------------------------------------------------------------------

@dataclass
class InvariantRecord:
    statement: str
    invariant_type: str
    functions: list[str] = field(default_factory=list)      # relevant Contract.fn
    state_variables: list[str] = field(default_factory=list)
    supporting_source: str = ""      # "source:<path>" | "interface:<c>" | "documentation" | "historical:<kb-id>"
    evidence: list[str] = field(default_factory=list)       # verified source slices
    prerequisites: list[str] = field(default_factory=list)
    validation_method: str = ""      # static_pattern | sequence_simulation | external_test | historical_case
    result: InvariantResult = "inconclusive"
    limitations: list[str] = field(default_factory=list)
    attack_path: str | None = None   # set only when violated: the concrete path

    def to_dict(self) -> dict[str, Any]:
        return {
            "statement": self.statement,
            "invariant_type": self.invariant_type,
            "functions": sorted(set(self.functions)),
            "state_variables": sorted(set(self.state_variables)),
            "supporting_source": self.supporting_source,
            "evidence": list(self.evidence),
            "prerequisites": list(self.prerequisites),
            "validation_method": self.validation_method,
            "result": self.result,
            "limitations": list(self.limitations),
            "attack_path": self.attack_path,
        }


# ---------------------------------------------------------------------------
# proposal
# ---------------------------------------------------------------------------

def _fn_contract(f: FunctionIntel) -> str:
    return f"{f.contract}.{f.name}"


def _slices(body: str, needles: tuple[str, ...], max_slices: int = 3) -> list[str]:
    """Extract the source lines containing any needle (evidence backend)."""
    out: list[str] = []
    for i, line in enumerate((body or "").splitlines(), start=1):
        if any(n in line for n in needles):
            out.append(line.strip()[:160])
        if len(out) >= max_slices:
            break
    return out


def invariant_type_for(intel: ContractIntel) -> list[str]:
    """Which invariant categories apply to THIS contract set (honest gating:
    no keywords → category absent, not 'assumed')."""
    blob = " ".join(c.name for c in intel.contracts).lower()
    for c in intel.contracts:
        blob += " " + " ".join(f.name for f in c.functions).lower()
    blob += " " + " ".join(
        f"{f.contract}.{f.name}" for c in intel.contracts for f in c.functions)
    types: list[str] = []
    if any(k in blob for k in ("totalassets", "totalsupply", "balances",
                               "converttoassets", "converttoshares",
                               "previewredeem", "shares")):
        types.append("asset_liability_accounting")
    if any(k in blob for k in ("withdraw", "redeem", "burn")):
        types.append("withdrawal_limit")
    if any(k in blob for k in ("collateral", "debt", "healthfactor", "liquidat")):
        types.append("collateral_debt")
    if any(k in blob for k in ("converttoassets", "converttoshares",
                               "previewdeposit", "previewredeem")):
        types.append("share_asset_conversion")
    if any(k in blob for k in ("onlyowner", "onlyrole", "hasrole", "owner", "admin")):
        types.append("privileged_state")
    if intel.initializer_functions or any(
            f.name == "initialize" for c in intel.contracts for f in c.functions):
        types.append("valid_initialization")
    if any(k in blob for k in ("transfer", "burn")):
        types.append("token_accounting")
    return types


def _propose_accounting(intel: ContractIntel, state: dict[str, dict[str, list[str]]],
                        records: list[InvariantRecord]) -> None:
    total = [k for k in state if k.split(".")[1] in ("totalSupply", "totalAssets")]
    balances = [k for k in state if k.split(".")[1] in ("balances", "balanceOf")]
    if not (total or balances):
        return
    record = InvariantRecord(
        statement=("Asset/liability accounting stays consistent: any write to "
                   "balances / totalSupply / totalAssets has a corresponding "
                   "offsetting write reachable in the same contract."),
        invariant_type="asset_liability_accounting",
        functions=[],
        state_variables=total + balances,
        supporting_source="source:state-variable write sets",
        validation_method="static_pattern",
    )
    # evidence: concrete += / -= pairs per function via state_change_evidence
    seen_ops: dict[str, list[str]] = {}
    for fn, changes in state_change_evidence(intel).items():
        for ch in changes:
            if ch.var in (t.split(".")[1] for t in total) or \
               ch.var in (b.split(".")[1] for b in balances):
                seen_ops.setdefault(fn, []).append(f"{ch.var}:{ch.op}")
    for fn, ops in seen_ops.items():
        record.functions.append(fn)
        record.evidence.append(f"{fn}: {', '.join(sorted(set(ops)))}")
    # asymmetric write sets (only +=, no -=) are a violation candidate
    for fn, ops in sorted(seen_ops.items()):
        has_add = any("rw" in o or "+=" in o for o in ops)
        has_sub = any("-=" in o for o in ops)
        if has_add and not has_sub:
            record.result = "inconclusive"
            record.limitations.append(
                f"{fn}: adds without visible subtraction; static check cannot "
                "prove imbalance (offsetting write may live in another path)")
    if record.functions:
        records.append(record)


def _propose_withdrawal(intel: ContractIntel, state: dict[str, dict[str, list[str]]],
                        records: list[InvariantRecord]) -> None:
    for c in intel.contracts:
        for f in c.functions:
            if f.name not in ("withdraw", "redeem", "burn"):
                continue
            body = f.body or ""
            bal_names = [v for v in c.state_vars if "balance" in v.lower() or v == "balances"]
            if not bal_names:
                continue
            guarded = bool(re.search(
                r"require\s*\([^)]*\b(?:balances?|balanceOf)\b[^)]*(?:>=|>)",
                body))
            record = InvariantRecord(
                statement=(f"{f.contract}.{f.name} never releases more than the "
                           "caller's recorded balance (no negative balance)."),
                invariant_type="withdrawal_limit",
                functions=[_fn_contract(f)],
                state_variables=bal_names,
                supporting_source=f"source:{c.name}.{f.name}",
                validation_method="static_pattern",
                evidence=_slices(body, ("require", "balances", "balanceOf")),
            )
            if guarded:
                record.result = "holds_under_tested_conditions"
                record.limitations.append(
                    "guard present in tested source; passing finite static check "
                    "is not a proof for all inputs/orders")
            else:
                writes = [ch for ch in state_change_evidence(intel)
                          .get(_fn_contract(f), [])
                          if ch.var in bal_names]
                if writes:
                    # release without an explicit >= guard in the same function
                    record.result = "inconclusive"
                    record.limitations.append(
                        f"{_fn_contract(f)} writes balances without an explicit "
                        ">= guard in this function; guard may live in a modifier "
                        "or prerequisite — static result is inconclusive, not "
                        "a finding.")
                else:
                    record.result = "not_applicable"
            records.append(record)


def _propose_privileged(intel: ContractIntel,
                        records: list[InvariantRecord]) -> None:
    mod_blob = " ".join(
        f"{c.name}:{' '.join(f.modifiers)}" for c in intel.contracts
        for f in c.functions).lower()
    if not any(k in mod_blob for k in ("owner", "role", "auth", "admin")):
        return
    privileged_writers: list[str] = []
    for c in intel.contracts:
        for f in c.functions:
            mods = " ".join(f.modifiers).lower()
            if any(k in mods for k in ("owner", "role", "auth", "admin")):
                if f.writes:
                    privileged_writers.append(
                        f"{_fn_contract(f)} -> {','.join(sorted(f.writes))}")
    record = InvariantRecord(
        statement=("Privileged state (owner/admin-controlled state) is only "
                   "mutable through functions carrying an authorization "
                   "modifier."),
        invariant_type="privileged_state",
        functions=[w.split("->")[0].strip() for w in privileged_writers],
        state_variables=[s.strip() for w in privileged_writers
                         for s in w.split("->")[1].split(",")],
        supporting_source="source:modifier sets",
        validation_method="static_pattern",
        evidence=privileged_writers,
    )
    # every privileged write set is authorized by construction (modifier seen)
    if privileged_writers:
        record.result = "holds_under_tested_conditions"
        record.limitations.append(
            "modifier presence is not proof of correct enforcement for all "
            "paths (shadowing, delegatecall, missing modifier on related writes).")
    records.append(record)


def _propose_initialization(intel: ContractIntel,
                            records: list[InvariantRecord]) -> None:
    if not (intel.initializer_functions or any(
            f.name == "initialize" for c in intel.contracts for f in c.functions)):
        return
    init_fns = intel.initializer_functions or [
        f"{c.name}.initialize" for c in intel.contracts
        for f in c.functions if f.name == "initialize"]
    record = InvariantRecord(
        statement=("The contract is initialized exactly once, before any "
                   "state-changing use (re-initialization must be blocked)."),
        invariant_type="valid_initialization",
        functions=sorted(set(init_fns)),
        state_variables=[v for c in intel.contracts for v in c.state_vars
                         if v.lower() in ("initialized", "_initialized",
                                          "initializing")],
        supporting_source="source:initializer markers",
        validation_method="static_pattern",
        evidence=[f"{f} [modifiers: {' '.join(f.modifiers)}]" for c in intel.contracts
                  for f in c.functions if f.name == "initialize"
                  or any("initializer" in m.lower() for m in f.modifiers)],
    )
    has_guard = any(
        "initializer" in m.lower() or "reinitializer" in m.lower()
        for c in intel.contracts for f in c.functions
        for m in f.modifiers)
    record.result = ("holds_under_tested_conditions" if has_guard
                     else "inconclusive")
    record.limitations.append(
        "static check: initializer modifier/guard seen in the extracted "
        "modifiers; passing finite static check is not a proof for upgrade "
        "paths and re-initialization via delegatecall" if has_guard else
        "initialize present without an initializer guard in the extracted "
        "modifiers; upgradeable proxies re-invoke init on implementation — "
        "verify upstream (inconclusive here).")
    records.append(record)


def _propose_token_accounting(intel: ContractIntel,
                              records: list[InvariantRecord]) -> None:
    for c in intel.contracts:
        for f in c.functions:
            if not f.token_calls:
                continue
            if not f.writes:
                continue
            record = InvariantRecord(
                statement=(f"{_fn_contract(f)} mirrors token transfer/burn in "
                           "internal accounting state (no silent divergence)."),
                invariant_type="token_accounting",
                functions=[_fn_contract(f)],
                state_variables=sorted(f.writes),
                supporting_source=f"source:{c.name}.{f.name}",
                validation_method="static_pattern",
                evidence=_slices(f.body or "",
                                 tuple(f.token_calls) + tuple(sorted(f.writes))),
            )
            record.result = "inconclusive"
            record.limitations.append(
                "transfer alongside a state write is visible; whether the two "
                "quantities always match requires value-level analysis "
                "(static result inconclusive).")
            records.append(record)


def extract_invariants(
    intel: ContractIntel,
    documentation: dict[str, str] | None = None,
    kb_hits: list[str] | None = None,
) -> list[InvariantRecord]:
    """Propose candidate invariants from source patterns (+ optional doc
    strings and historical-case provenance). Deterministic; nothing invented.
    Doc/KB inputs only widen `supporting_source` provenance — they never
    fabricate statements on their own."""
    records: list[InvariantRecord] = []
    state = state_dependency_graph(intel)
    _propose_accounting(intel, state, records)
    _propose_withdrawal(intel, state, records)
    _propose_privileged(intel, records)
    _propose_initialization(intel, records)
    _propose_token_accounting(intel, records)
    # collateral/debt + share-asset categories need both keywords and are
    # proposed from function presence (gated by invariant_type_for honesty).
    types = set(invariant_type_for(intel))
    if "collateral_debt" in types:
        records.append(InvariantRecord(
            statement="Collateral never falls below the debt/health-factor "
                      "threshold after any reachable state change.",
            invariant_type="collateral_debt",
            functions=[_fn_contract(f) for c in intel.contracts
                       for f in c.functions
                       if any(k in f.name.lower() for k in
                              ("collateral", "debt", "liquidat", "health"))],
            supporting_source="source:function names",
            validation_method="static_pattern",
            result="inconclusive",
            limitations=[
                "solvency requires value-level simulation; static check cannot "
                "establish bounds."],
        ))
    if "share_asset_conversion" in types:
        conv = [_fn_contract(f) for c in intel.contracts for f in c.functions
                if any(k in f.name.lower() for k in
                       ("convert", "preview", "redeem", "deposit", "withdraw"))]
        records.append(InvariantRecord(
            statement="Share-to-asset conversion is monotone and round-trip "
                      "consistent (convertToAssets(convertToShares(x)) == x) "
                      "under stable totalAssets.",
            invariant_type="share_asset_conversion",
            functions=conv,
            supporting_source="source:conversion function names",
            validation_method="static_pattern",
            result="inconclusive",
            limitations=[
                "round-trip exactness depends on rounding direction per "
                "operation; needs value-level simulation."],
        ))
    if documentation:
        for k, v in documentation.items():
            needle = re.search(r"(?:must|shall|never|always|only|after)\s+.{8,120}",
                               v, re.IGNORECASE)
            if needle:
                records.append(InvariantRecord(
                    statement=needle.group(0).strip()[:200],
                    invariant_type="privileged_state",
                    supporting_source=f"documentation:{k}",
                    validation_method="historical_case",
                    result="not_applicable",
                    limitations=[
                        "documentation statement; applicability to this code "
                        "requires an explicit mapping to a state variable.",
                        "not validated against execution."],
                ))
    if kb_hits:
        records.append(InvariantRecord(
            statement="Historical cases retrieved from the knowledge base are "
                      "referenced for pattern awareness only; they neither "
                      "prove nor disprove an invariant of this code.",
            invariant_type="privileged_state",
            supporting_source=";".join(f"historical:{h[:60]}" for h in kb_hits[:3]),
            validation_method="historical_case",
            result="not_applicable",
            limitations=[
                "provenance-only: historical case similarity is not evidence "
                "for the audited contract."],
        ))
    return records


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------

def validate_invariants(intel: ContractIntel,
                        records: list[InvariantRecord]) -> list[InvariantRecord]:
    """Explicit per-record result. Static validation only — results are
    honest: pattern checks yield holds_under_tested_conditions at best, and
    everything else stays inconclusive unless a concrete violation path is
    enumerated. `violated` requires (a) an external-reachable path and (b) a
    state write that breaks the statement."""
    cg = call_graph(intel)
    sinks = sink_inventory(intel)
    sink_fns = {s["fn"] for s in sinks}
    entry_fns = {f"{c.name}.{f.name}" for c in intel.contracts
                 for f in c.functions
                 if f.visibility == "external" or
                 (f.visibility == "public" and f.mutability not in ("view", "pure"))}
    for rec in records:
        if rec.result != "inconclusive":
            continue
        # withdrawal-limit style: an externally-reachable writer with no guard
        # anywhere on its call chain => concrete violation candidate.
        for fn in rec.functions:
            chain = _call_chain(cg, fn, entry_fns, max_depth=4)
            if not chain:
                continue
            writer = next((ch for ch in state_change_evidence(intel)
                           .get(fn, []) if ch.var in rec.state_variables), None)
            if writer and writer.op == "rw" and not _guarded_chain(intel, chain):
                rec.result = "violated"
                rec.attack_path = " -> ".join(chain)
                rec.limitations.append(
                    "static violation candidate: reachable external chain "
                    "writes the invariant state without an explicit guard on "
                    "the chain; requires test-level confirmation before "
                    "reporting as a finding.")
                break
        else:
            continue
        break
    return records


def _call_chain(cg: dict[str, list[str]], fn: str, entries: set[str],
                max_depth: int) -> list[str] | None:
    """Reverse BFS from fn up to an external entry point; returns the chain
    (entry -> ... -> fn) or None when fn is unreachable from any entry."""
    if fn in entries:
        return [fn]
    frontier = [(fn, [fn])]
    seen: set[str] = set()
    while frontier:
        cur, path = frontier.pop(0)
        if len(path) > max_depth:
            continue
        for caller in _callers_of(cg, cur):
            if caller in seen:
                continue
            seen.add(caller)
            new_path = [caller] + path
            if caller in entries:
                return new_path
            frontier.append((caller, new_path))
    return None


def _callers_of(cg: dict[str, list[str]], fn: str) -> list[str]:
    return sorted(k for k, v in cg.items() if fn in v)


def _guarded_chain(intel: ContractIntel, chain: list[str]) -> bool:
    for key in chain:
        cname, _, fname = key.partition(".")
        for c in intel.contracts:
            if c.name != cname:
                continue
            for f in c.functions:
                if f.name != fname:
                    continue
                if any(k in " ".join(f.modifiers).lower()
                       for k in ("owner", "role", "auth", "nonreentrant",
                                 "reentrancyguard")):
                    return True
                if "require" in (f.body or ""):
                    return True
    return False


def render_invariants(records: list[InvariantRecord]) -> str:
    """Human-readable section for the report / agent material."""
    if not records:
        return "[no invariants proposed — no applicable categories]"
    lines = ["INVARIANTS (explicit results):"]
    for r in records:
        lines.append(
            f"- [{r.result}] ({r.invariant_type}) {r.statement}")
        for lim in r.limitations[:2]:
            lines.append(f"    limitation: {lim}")
        if r.attack_path:
            lines.append(f"    attack path: {r.attack_path}")
    return "\n".join(lines)
