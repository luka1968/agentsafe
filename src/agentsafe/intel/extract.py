"""Deterministic Solidity contract intelligence extraction.

Design contract (docs/baseline.md, upgrade target 1):
- Parses verified Solidity source into structured intel: contracts,
  inheritance, functions, modifiers, state variables, per-function read/write
  sets, internal/external call edges, transfer sites, arithmetic ops, guards,
  emitted events, proxy/upgrade patterns, privileged and initializer
  functions.
- Deterministic extraction only; nothing is invented. Bodies we cannot see
  (interfaces, unknown externals) are recorded as *unresolved* so downstream
  agents must argue from evidence.
- No dependency on the slither Python package (the worker runs slither as a
  CLI); `enrich_from_slither_json()` merges Slither detector JSON when the
  worker already produced it.
- Line numbers are 1-indexed and derived from source offsets (stable).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "FunctionIntel",
    "ContractEntry",
    "ContractIntel",
    "extract_contract_intel",
    "enrich_from_slither_json",
]

_COMMENT_BLOCK = re.compile(r"/\*.*?\*/", re.DOTALL)
_COMMENT_LINE = re.compile(r"//[^\n]*")
_CONTRACT_RE = re.compile(
    r"^\s*(?:abstract\s+)?(contract|interface|library)\s+([A-Za-z_]\w*)"
    r"(?:\s+is\s+([^{]+))?\s*\{",
    re.MULTILINE,
)
_STATE_VAR_RE = re.compile(
    r"^\s*((?:mapping\s*\(.+?\)|[A-Za-z_][\w\.\[\]]*(?:\s*\[[^\]]*\])?)\s+)"
    r"(?:immutable\s+|constant\s+|override\s+|transient\s+)*"
    r"(public|private|internal)\s+([A-Za-z_]\w*)\s*(?:=|;)",
    re.MULTILINE,
)
_EVENT_RE = re.compile(r"\bevent\s+([A-Za-z_]\w*)\s*\(")
_FUNC_RE = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*([^{;]*)\{")
_MODIFIER_DEF_RE = re.compile(r"\bmodifier\s+([A-Za-z_]\w*)\s*\(")
_ETHER_RE = re.compile(r"\.\s*call\s*\{|\.call\s*\(|\.send\s*\(|\.transfer\s*\(")
_DELEGATE_RE = re.compile(r"\bdelegatecall\s*\(|\.delegatecall\s*\(")
_TOKEN_RE = re.compile(
    r"\.\s*(transfer\s*\(|transferFrom\s*\(|approve\s*\(|safeTransfer\s*\(|"
    r"safeTransferFrom\s*\(|safeApprove\s*\(|mint\s*\(|burn\s*\()"
)
_ARITH_RE = re.compile(r"(\+=|-=|\*=|/=|\*\*|\+|-|\*|/|%)")
_UNCHECKED_RE = re.compile(r"\bunchecked\s*\{")
_GUARD_RE = re.compile(r"\b(require\s*\(|assert\s*\(|revert\s+[A-Za-z_]\w*\s*\(|revert\s*\()")
_EMIT_RE = re.compile(r"\bemit\s+([A-Za-z_]\w*)\s*\(")
_INTERNAL_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_EXTERNAL_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\(")
_STORAGE_SLOT_RE = re.compile(
    r"0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
    r"|0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
    r"|0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
    r"|ERC1967|IMPLEMENTATION_SLOT|ADMIN_SLOT|BEACON_SLOT|UPGRADE_INTERFACE_VERSION"
)
_UPGRADE_RE = re.compile(r"\b(upgradeTo|upgradeToAndCall|upgradeBeaconToAndCall|"
                         r"upgradeToAndCall)\b")
_INIT_RE = re.compile(r"\b(initialize|initializer|reinitializer|disableInitializers|"
                      r"_disableInitializers)\b")
_PROXY_HINT_RE = re.compile(
    r"(Proxy|Upgradeable|TransparentUpgradeableProxy|BeaconProxy|UUPS)")
_KEYWORD_TAIL = re.compile(
    r"\b(?:public|private|internal|external|view|pure|payable|virtual|"
    r"override|returns|nonpayable)\b"
)
_PRIVILEGED_NAME_RE = re.compile(
    r"(upgrade|setowner|setadmin|setrole|grantrole|revoke|pause|unpause|"
    r"withdraw|mint|burn|sweep|rescue|transferownership|renounce)", re.IGNORECASE)
_BUILTIN_CALL = {
    "require", "assert", "revert", "emit", "return", "address", "abi",
    "keccak256", "new", "if", "for", "while", "delete", "mapping", "uint",
    "int", "bool", "bytes", "string", "type", "delegatecall", "super",
    "selfdestruct", "block", "msg", "extcodesize", "sha3", "blockhash",
    "addmod", "mulmod", "ecrecover", "gasleft", "payable", "call", "send",
    "transfer", "emit", "unchecked", "assembly", "try", "catch", "constructor",
}


@dataclass
class FunctionIntel:
    """One extracted function."""

    name: str
    contract: str
    params: str = ""
    visibility: str = "internal"
    mutability: str = ""  # view|pure|payable|""
    modifiers: list[str] = field(default_factory=list)
    returns: str = ""
    line_start: int = 0
    line_end: int = 0
    reads: set[str] = field(default_factory=set)
    writes: set[str] = field(default_factory=set)
    internal_calls: set[str] = field(default_factory=set)
    external_calls: list[str] = field(default_factory=list)  # "ident.member"
    ether_calls: int = 0
    delegatecalls: int = 0
    token_calls: list[str] = field(default_factory=list)
    arithmetic: set[str] = field(default_factory=set)
    unchecked: int = 0
    guards: list[str] = field(default_factory=list)
    emits: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = self.__dict__.copy()
        for k in ("reads", "writes", "internal_calls", "arithmetic"):
            d[k] = sorted(d[k])
        return d


@dataclass
class ContractEntry:
    name: str
    kind: str
    is_abstract: bool = False
    bases: list[str] = field(default_factory=list)
    state_vars: dict[str, str] = field(default_factory=dict)
    events: list[str] = field(default_factory=list)
    functions: list[FunctionIntel] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "kind": self.kind, "is_abstract": self.is_abstract,
            "bases": self.bases, "state_vars": self.state_vars,
            "events": self.events,
            "functions": [f.to_dict() for f in self.functions],
        }


@dataclass
class ContractIntel:
    """Whole-audit intelligence from verified source (+ optional slither)."""

    contracts: list[ContractEntry] = field(default_factory=list)
    proxy_hints: list[str] = field(default_factory=list)
    privileged_functions: list[str] = field(default_factory=list)
    initializer_functions: list[str] = field(default_factory=list)
    unresolved_externals: set[str] = field(default_factory=set)
    slither_detectors: list[dict[str, Any]] = field(default_factory=list)
    extraction_warnings: list[str] = field(default_factory=list)

    # -- graph helpers -----------------------------------------------------
    def callers_of(self, fn: str) -> list[str]:
        """Names of functions whose internal_calls include `fn`."""
        return sorted({
            f.name
            for c in self.contracts for f in c.functions
            if fn in f.internal_calls
        })

    def functions_named(self, fn: str) -> list[FunctionIntel]:
        return [f for c in self.contracts for f in c.functions if f.name == fn]

    def writers_of_state(self, var: str) -> list[str]:
        return sorted({f.name for c in self.contracts for f in c.functions
                       if var in f.writes})

    def readers_of_state(self, var: str) -> list[str]:
        return sorted({f.name for c in self.contracts for f in c.functions
                       if var in f.reads})

    def external_entry_points(self) -> list[FunctionIntel]:
        return [f for c in self.contracts for f in c.functions
                if f.visibility == "external"
                or (f.visibility == "public" and f.mutability not in ("view", "pure"))]

    def to_dict(self) -> dict[str, Any]:
        return {
            "contracts": [c.to_dict() for c in self.contracts],
            "proxy_hints": sorted(set(self.proxy_hints)),
            "privileged_functions": sorted(set(self.privileged_functions)),
            "initializer_functions": sorted(set(self.initializer_functions)),
            "unresolved_externals": sorted(self.unresolved_externals),
            "slither_detector_count": len(self.slither_detectors),
            "extraction_warnings": self.extraction_warnings,
        }


def _strip_comments(src: str) -> str:
    """Blank comments but keep newlines (stable line numbers)."""
    def _block(m: re.Match) -> str:
        return "\n" * m.group(0).count("\n")
    return _COMMENT_LINE.sub("", _COMMENT_BLOCK.sub(_block, src))


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _match_brace(text: str, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(text)


def _parse_tail(tail: str) -> tuple[str, str, str, list[str]]:
    """-> (visibility, mutability, returns, modifiers)."""
    vis = next((v for v in ("external", "public", "internal", "private")
                if re.search(rf"\b{v}\b", tail)), "internal")
    mut = next((v for v in ("payable", "view", "pure")
                if re.search(rf"\b{v}\b", tail)), "")
    ret = ""
    rm = re.search(r"returns\s*\(([^)]*)\)", tail)
    if rm:
        ret = " ".join(rm.group(1).split())
    stripped = re.sub(r"returns\s*\([^)]*\)", "", tail)
    stripped = _KEYWORD_TAIL.sub("", stripped)
    mods = [x for x in re.findall(r"[A-Za-z_]\w*", stripped)
            if x not in _BUILTIN_CALL]
    return vis, mut, ret, mods[:8]


def _analyze_body(fi: FunctionIntel, body: str, entry: ContractEntry,
                  intel: ContractIntel) -> None:
    fi.ether_calls = len(_ETHER_RE.findall(body))
    fi.delegatecalls = len(_DELEGATE_RE.findall(body))
    fi.token_calls = [m.group(1).rstrip("(") for m in _TOKEN_RE.finditer(body)]
    fi.arithmetic.update(_ARITH_RE.findall(body))
    fi.unchecked = len(_UNCHECKED_RE.findall(body))
    for m in _GUARD_RE.finditer(body):
        seg = body[m.start():m.start() + 90].split("\n")[0]
        fi.guards.append(seg[:88])
    fi.emits = _EMIT_RE.findall(body)

    own_fns = {f.name for f in entry.functions}
    own_mods = {f"modifier:{n}" for n in entry.state_vars
                if n.startswith("modifier:")}
    mod_names = {n.split(":", 1)[1] for n in own_mods}
    param_ids = {p.strip().split()[0]
                 for p in (fi.params.split(",") if fi.params else []) if p.strip()}
    local_ids = param_ids
    # A copy with `emit X` sites blanked so `Deposit(...)` is not mistaken
    # for a constructor call / new-contract creation.
    call_body = re.sub(r"\bemit\s+", "", body)

    for m in _EXTERNAL_CALL_RE.finditer(call_body):
        ident, member = m.group(1), m.group(2)
        if ident in ("msg", "block", "super", "address", "type", "abi"):
            continue
        fi.external_calls.append(f"{ident}.{member}")
        # ident is a state var (interface-typed) or an unknown local/param
        # whose target contract body is NOT in this source set: record as
        # unresolved so agents never assume behavior.
        is_known_contract = any(ident == c.name for c in intel.contracts)
        if not is_known_contract and ident not in local_ids:
            intel.unresolved_externals.add(
                f"{entry.name}.{fi.name}: {ident}.{member} "
                f"(external contract body not in source)")
    for m in _INTERNAL_CALL_RE.finditer(call_body):
        callee = m.group(1)
        if callee in _BUILTIN_CALL or callee in mod_names:
            continue
        if callee in entry.state_vars:  # state var used as a callable address
            continue
        if callee in own_fns or any(callee == c2.name for c2 in intel.contracts) \
                or callee in (b for b in entry.bases):
            fi.internal_calls.add(callee)
        elif callee[0].isupper():  # external contract constructor call
            intel.unresolved_externals.add(
                f"{entry.name}.{fi.name}: new {callee} (contract not in source)")
        else:
            fi.internal_calls.add(callee)  # likely inherited; still an edge


def _extract_contract(src: str, body: str, kind: str, name: str,
                      bases: list[str], start_line: int, intel: ContractIntel) -> ContractEntry:
    entry = ContractEntry(name=name, kind=kind, bases=[b.strip() for b in bases])
    for m in _STATE_VAR_RE.finditer(body):
        typ = " ".join(m.group(1).split())
        entry.state_vars[m.group(3)] = f"{typ} {m.group(2)}"
    for m in _EVENT_RE.finditer(body):
        entry.events.append(m.group(1))
    for m in _MODIFIER_DEF_RE.finditer(body):
        entry.state_vars[f"modifier:{m.group(1)}"] = "modifier"
    if kind == "interface":
        return entry

    for fm in _FUNC_RE.finditer(body):
        vis, mut, ret, mods = _parse_tail(fm.group(3))
        fi = FunctionIntel(
            name=fm.group(1), contract=name,
            params=" ".join(fm.group(2).split()),
            visibility=vis, mutability=mut, modifiers=mods, returns=ret,
            line_start=start_line + body[:fm.start()].count("\n"),
        )
        open_idx = fm.end() - 1
        fbody = body[open_idx:_match_brace(body, open_idx)]
        fi.line_end = fi.line_start + fbody.count("\n") + 1
        for sv in entry.state_vars:
            if re.search(rf"\b{re.escape(sv)}\b", fbody):
                if re.search(
                    rf"(?:\b{re.escape(sv)}\b\s*(?:\[[^\]]*\])?\s*"
                    rf"(?:=|\+=|-=|\*=|/=)|\bdelete\s+{re.escape(sv)}\b)",
                    fbody,
                ):
                    fi.writes.add(sv)
                else:
                    fi.reads.add(sv)
        _analyze_body(fi, fbody, entry, intel)
        entry.functions.append(fi)
    return entry


def extract_contract_intel(files: dict[str, str]) -> ContractIntel:
    """Extract intel from {path: content}. Records warnings instead of raising
    (partial, honest intel beats no intel)."""
    intel = ContractIntel()
    if not files:
        intel.extraction_warnings.append("no source files provided")
        return intel
    for path, content in files.items():
        try:
            src = _strip_comments(content)
            found_any = False
            for m in _CONTRACT_RE.finditer(src):
                found_any = True
                open_idx = m.end() - 1
                body = src[open_idx:_match_brace(src, open_idx)]
                abstract = bool(re.match(r"\s*abstract\s*$",
                                         src[max(0, m.start() - 12):m.start() + 12]
                                         .split("contract")[0], re.DOTALL)) \
                    or "abstract contract" in src[max(0, m.start() - 12):m.end()]
                entry = _extract_contract(src, body, m.group(1), m.group(2),
                                          (m.group(3) or "").split(","), 
                                          _line_of(src, m.start()), intel)
                entry.is_abstract = abstract
                intel.contracts.append(entry)
                if _STORAGE_SLOT_RE.search(body) or _UPGRADE_RE.search(body) \
                        or _PROXY_HINT_RE.search(m.group(2) or ""):
                    intel.proxy_hints.append(f"{path}:{entry.name}")
                for f in entry.functions:
                    full = f"{entry.name}.{f.name}"
                    mods_l = " ".join(f.modifiers).lower()
                    if any(k in mods_l for k in ("owner", "admin", "role", "auth")) \
                            or _PRIVILEGED_NAME_RE.search(f.name):
                        intel.privileged_functions.append(
                            f"{full} [{f.visibility}/{f.mutability or 'nonpayable'}]")
                    if _INIT_RE.search(f.name) \
                            or "initial" in mods_l:
                        intel.initializer_functions.append(full)
            if not found_any:
                intel.extraction_warnings.append(
                    f"{path}: no top-level contract parsed (assembly/pseudo?)")
        except Exception as exc:  # pragma: no cover - defensive
            intel.extraction_warnings.append(f"{path}: extraction error: {exc}")
    return intel


def enrich_from_slither_json(intel: ContractIntel, slither_stdout: str) -> None:
    """Merge slither --json output (the worker already runs slither). Detector
    dicts preserved verbatim; unparsable input is a warning, never a crash."""
    try:
        data = json.loads(slither_stdout) if slither_stdout else {}
    except (ValueError, TypeError):
        intel.extraction_warnings.append("slither json unparsable; enrichment skipped")
        return
    for det in ((data.get("results") or {}).get("detectors") or []):
        intel.slither_detectors.append({
            "check": det.get("check"),
            "impact": det.get("impact"),
            "confidence": det.get("confidence"),
            "description": (det.get("description") or "")[:240],
        })
