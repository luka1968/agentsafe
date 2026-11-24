"""Deterministic external-reachability model — the adversarial-review substrate.

Answers ONE question with evidence: *can an unprivileged external caller reach
the code a finding points at?* This is the single most important check missing
from the discovery pipeline, and the documented root cause of a whole class of
production false positives (docs/baseline.md): internal-only or
authorization-guarded functions reported as externally exploitable.

The model is built from the SAME verified source the agents saw, through the
canonical contract-intel extractor. Nothing is invented:

- ``reachable``           : some external entry point reaches the function
                            through the internal call graph (any path).
- ``attacker_reachable``  : some external entry point reaches it WITHOUT
                            passing through an authorization-guarded function.
                            When a function is reachable but NOT
                            attacker-reachable, every external path to it is
                            gated by an authorization check.
- ``not_reachable``       : the function is internal/private, is not reached
                            from any external entry point in the analyzed
                            source, its contract is concrete, and the file has
                            no unparsed ``receive``/``fallback`` body that
                            could hide a caller.

Ambiguity is never guessed away: any case the extractor cannot resolve returns
``unknown`` and no verdict is ever drawn from an ``unknown``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from agentsafe.intel.extract import (
    ContractEntry,
    ContractIntel,
    FunctionIntel,
    extract_contract_intel,
)
from agentsafe.intel.graph import call_graph, classify_proxy_pattern

__all__ = [
    "Reachability",
    "FunctionLocation",
    "ReachabilityModel",
    "build_reachability",
    "auth_guard",
]

# Tri-state: never collapse "unknown" into either verdict.
Reachability = str  # "reachable" | "not_reachable" | "unknown"

# Authorization modifiers. Curated and exact (lowercased): a modifier whose
# name is not an authorization gate must never be read as one. ``onlyProxy``,
# ``nonReentrant`` and ``onlyInitializing`` are deliberately absent: they are
# structural guards, not caller-authorization.
_AUTH_MODIFIERS: frozenset[str] = frozenset(
    {
        "onlyowner",
        "onlyadmin",
        "onlyrole",
        "onlygovernance",
        "onlygovernor",
        "onlyminter",
        "onlyoperator",
        "onlymanager",
        "onlyguardian",
        "onlycontroller",
        "onlyexecutor",
        "onlyauthorized",
        "onlyauthorised",
        "auth",
        "authorized",
        "authorised",
        "restricted",
        "requiresauth",
        "onlymaintainer",
        "onlydeployer",
    }
)

# Body-level authorization evidence: explicit role/owner comparisons. A
# `require(msg.sender == ...)` is an authorization gate regardless of naming.
_AUTH_BODY_RE = re.compile(
    r"hasrole\s*\(|_checkrole\s*\(|_checkowner\s*\(|_checkadmin\s*\(|"
    r"require\s*\(\s*msg\.sender\s*==|"
    r"if\s*\(\s*msg\.sender\s*!=\s*[A-Za-z_][\w\.]*\s*\)\s*(?:\{[^}]*)?revert",
    re.IGNORECASE,
)

_UNPARSED_ENTRY_RE = re.compile(r"\b(?:receive|fallback)\s*\(", re.IGNORECASE)
_EXPLICIT_INTERNAL_RE = re.compile(r"\b(?:internal|private)\b")
_EXPLICIT_EXTERNAL_RE = re.compile(r"\b(?:public|external)\b")
_PART_SUFFIX_RE = re.compile(r"#part\d+$")

# Transparent-proxy admin gate: the proxy admin is checked before the admin
# functions (upgrade/changeAdmin) are served. Its presence is evidence the
# upgrade path is authorization-gated by design, not a missing-control defect.
_PROXY_ADMIN_CHECK_RE = re.compile(
    r"msg\.sender\s*==\s*[^;\n]*_proxyAdmin|_proxyAdmin\s*\(\s*\)\s*==\s*msg\.sender|"
    r"onlyProxyAdmin\b",
    re.IGNORECASE,
)
_PROXY_ADMIN_MARKER = ("_proxyAdmin", "ProxyAdmin", "getProxyAdmin", "getAdmin")
_UPGRADE_AUTHZ_FN = "_authorizeUpgrade"


def auth_guard(fi: FunctionIntel) -> str | None:
    """Return the authorization gate protecting a function, or None.

    A modifier named in the curated set wins; otherwise an explicit
    role/owner comparison in the body is reported. Never inferred from the
    function's name (a name is not a control)."""
    for m in fi.modifiers or ():
        if m.strip().lower() in _AUTH_MODIFIERS:
            return f"modifier {m}"
    match = _AUTH_BODY_RE.search(fi.body or "")
    if match:
        return match.group(0).strip()
    return None


@dataclass
class FunctionLocation:
    """One extracted function bound to the file it lives in."""

    path: str
    contract: str
    fn: FunctionIntel
    header: str

    @property
    def key(self) -> str:
        return f"{self.contract}.{self.fn.name}"

    def contains(self, line: int | None) -> bool:
        if line is None:
            return False
        start = self.fn.line_start or 0
        end = self.fn.line_end or start
        return start <= line <= end


@dataclass
class ReachabilityModel:
    """Per-audit reachability index. Construct via :func:`build_reachability`."""

    reachable: set[str] = field(default_factory=set)
    attacker_reachable: set[str] = field(default_factory=set)
    guarded: dict[str, str] = field(default_factory=dict)
    adj: dict[str, list[str]] = field(default_factory=dict)
    contract_meta: dict[str, ContractEntry] = field(default_factory=dict)
    by_path: dict[str, list[FunctionLocation]] = field(default_factory=dict)
    file_sources: dict[str, str] = field(default_factory=dict)
    proxy_kind: dict[str, str] = field(default_factory=dict)
    entry_keys: set[str] = field(default_factory=set)

    # -- location resolution ------------------------------------------------
    def function_at(
        self, file_path: str | None, line: int | None, fn_name: str | None = None
    ) -> FunctionLocation | None:
        """The function whose declaration most recently precedes (file, line),
        preferring an explicit name match.

        Extracted line *ranges* can overlap by one line (a body's closing brace
        may share the next declaration's line), so selection is by nearest
        preceding declaration, not by range containment. Falls back to the sole
        file only when the source set is a single file; returns None otherwise."""
        if line is None:
            return None
        path = _PART_SUFFIX_RE.sub("", file_path or "")
        candidates = self.by_path.get(path)
        if candidates is None:
            if len(self.by_path) == 1:
                candidates = next(iter(self.by_path.values()))
            else:
                return None
        before = [loc for loc in candidates if (loc.fn.line_start or 0) <= line]
        if not before:
            return None
        if fn_name:
            named = [loc for loc in before if loc.fn.name == fn_name]
            if named:
                before = named
        return max(before, key=lambda loc: loc.fn.line_start or 0)

    def is_view(self, loc: FunctionLocation) -> bool:
        return (loc.fn.mutability or "") in ("view", "pure")

    def guard_of(self, key: str) -> str | None:
        return self.guarded.get(key)

    def _reaches(self, src: str, dst: str) -> bool:
        """Whether ``src`` can call ``dst`` through the internal call graph."""
        seen = {src}
        stack = [src]
        while stack:
            cur = stack.pop()
            for nxt in self.adj.get(cur, []):
                if nxt == dst:
                    return True
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        return False

    def gating_guards(self, key: str) -> list[str]:
        """Authorization gates that necessarily stand between an external
        caller and ``key``: a guarded function that can call ``key`` (or
        ``key`` itself when it carries the guard). Reported as
        ``"<fn> (<guard>)"`` evidence strings; empty when none apply."""
        out: list[str] = []
        if key in self.guarded:
            out.append(f"{key} ({self.guarded[key]})")
        for g, guard in sorted(self.guarded.items()):
            if g == key:
                continue
            if self._reaches(g, key):
                out.append(f"{g} ({guard})")
        return out

    # -- proxy posture ------------------------------------------------------
    def is_proxy(self) -> bool:
        return any(k in ("uups", "transparent", "beacon") for k in self.proxy_kind.values())

    def upgrade_authorization_evidence(self) -> str | None:
        """Evidence that UPGRADE/admin authorization is enforced by design, or
        None. Two recognized mechanisms only (never a guess):

        - a guarded ``_authorizeUpgrade`` override (UUPS pattern);
        - a transparent-proxy admin gate (``msg.sender == _proxyAdmin``) or a
          ProxyAdmin reference with an explicit admin check.
        """
        for key, guard in sorted(self.guarded.items()):
            if key.split(".")[-1] == _UPGRADE_AUTHZ_FN:
                return f"{key} ({guard})"
        blob = " ".join(self.file_sources.values())
        if any(m in blob for m in _PROXY_ADMIN_MARKER) and _PROXY_ADMIN_CHECK_RE.search(blob):
            return "transparent-proxy admin gate (msg.sender == _proxyAdmin)"
        return None

    # -- reachability verdicts ---------------------------------------------
    def reachability(self, loc: FunctionLocation) -> Reachability:
        """Tri-state reachability for a resolved location. Conservative: a
        confident ``not_reachable`` requires every condition to hold, else
        ``unknown``."""
        key = loc.key
        if key in self.reachable:
            return "reachable"
        # Not reached: only call it unreachable when we are sure a caller is
        # not hiding somewhere we could not parse.
        if loc.fn.visibility not in ("internal", "private"):
            return "unknown"
        if _EXPLICIT_EXTERNAL_RE.search(loc.header) or not _EXPLICIT_INTERNAL_RE.search(
            loc.header
        ):
            # Visibility we cannot confirm as internal/private => do not judge.
            return "unknown"
        meta = self.contract_meta.get(loc.contract)
        if meta is None or meta.kind != "contract" or meta.is_abstract:
            return "unknown"
        if _UNPARSED_ENTRY_RE.search(self.file_sources.get(loc.path, "")):
            return "unknown"  # a receive()/fallback() body could call it
        return "not_reachable"

    def attacker_can_reach(self, loc: FunctionLocation) -> bool | None:
        """True when an unprivileged external path to the function exists;
        False when every external path is authorization-gated; None when the
        function is not externally reachable at all (see reachability())."""
        key = loc.key
        if key not in self.reachable:
            return None
        return key in self.attacker_reachable

    def key_attacker_reachable(self, key: str) -> Reachability:
        """Tri-state attacker reachability for a raw function key (the form
        attack paths carry, e.g. ``Contract.fn``)."""
        if key in self.attacker_reachable:
            return "yes"
        if key in self.reachable:
            return "no"
        return "unknown"


def _header_text(content: str, line_start: int) -> str:
    """Reconstruct a function header (signature + modifiers) from the source,
    stopping at the opening brace or statement terminator. Keeps visibility
    tokens that may sit on their own line."""
    lines = content.splitlines()
    if line_start < 1 or line_start > len(lines):
        return ""
    buf: list[str] = []
    for i in range(line_start - 1, min(line_start - 1 + 8, len(lines))):
        seg = lines[i]
        buf.append(seg)
        if "{" in seg or ";" in seg:
            break
    return " ".join(buf)


def build_reachability(
    segments: dict[str, str] | None,
    intel: ContractIntel | None = None,
) -> ReachabilityModel | None:
    """Build the reachability model over a source set.

    Returns None when there is no usable structure (no segments, pseudo-source,
    or nothing parseable) — callers must then draw no reachability verdicts."""
    if not segments:
        return None
    intel_all = intel if intel is not None and intel.contracts else extract_contract_intel(segments)
    if intel_all is None or not intel_all.contracts:
        return None

    adj = call_graph(intel_all)
    entries = {
        f"{f.contract}.{f.name}" for f in intel_all.external_entry_points()
    }
    if not entries:
        return None

    # Authorization gates, indexed by function key.
    guarded: dict[str, str] = {}
    for c in intel_all.contracts:
        for f in c.functions:
            g = auth_guard(f)
            if g:
                guarded[f"{c.name}.{f.name}"] = g

    # Any-path reachability (fixpoint over the call graph).
    reachable: set[str] = set(entries)
    stack = list(entries)
    while stack:
        cur = stack.pop()
        for nxt in adj.get(cur, []):
            if nxt not in reachable:
                reachable.add(nxt)
                stack.append(nxt)

    # Attacker reachability: BFS that cannot ENTER an authorization-guarded
    # function (an unprivileged caller is stopped by it, and cannot use it to
    # reach what it calls). If the set is empty after this, every external path
    # to a non-guarded function passes a gate.
    attacker: set[str] = set()
    stack = []
    for e in entries:
        if e in guarded:
            continue
        attacker.add(e)
        stack.append(e)
    while stack:
        cur = stack.pop()
        for nxt in adj.get(cur, []):
            if nxt in guarded or nxt in attacker:
                continue
            attacker.add(nxt)
            stack.append(nxt)

    # Per-file function map: file+line -> function (the whole-set intel does
    # not carry a per-file binding, so extract per file for location only).
    by_path: dict[str, list[FunctionLocation]] = {}
    for path, content in segments.items():
        if not content:
            continue
        per = extract_contract_intel({path: content})
        locs: list[FunctionLocation] = []
        for c in per.contracts:
            for f in c.functions:
                locs.append(
                    FunctionLocation(
                        path=path, contract=c.name, fn=f,
                        header=_header_text(content, f.line_start),
                    )
                )
        if locs:
            by_path[path] = locs

    contract_meta = {c.name: c for c in intel_all.contracts}
    proxy_kind = {p.contract: p.kind for p in classify_proxy_pattern(intel_all)}

    return ReachabilityModel(
        reachable=reachable,
        attacker_reachable=attacker,
        guarded=guarded,
        adj=adj,
        contract_meta=contract_meta,
        by_path=by_path,
        file_sources={p: (c or "") for p, c in segments.items()},
        proxy_kind=proxy_kind,
        entry_keys=entries,
    )
