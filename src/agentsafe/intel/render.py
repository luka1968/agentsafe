"""Render ContractIntel + knowledge-base records as bounded prompt sections.

Everything rendered here is UNTRUSTED CONTEXT for the LLM: the renderer must
never drop the untrusted markers (injection containment), and every section is
hard-capped by character budget so it can never crowd out the actual contract
code inside `MAX_SEGMENT_CHARS`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from .extract import ContractIntel

INTEL_BUDGET_CHARS = 2400
KB_BUDGET_CHARS = 1600
KB_SNIPPET_CHARS = 420

# Which intel facets matter per agent focus (mission: cross-function
# interactions, accounting, authorization, multi-step paths).
_FOCUS_FACETS = {
    "access_control": ("priv", "entry", "mods"),
    "fund_flow": ("transfers", "state", "entry", "mods"),
    "business_logic": ("state", "calls", "arith", "entry"),
    "validation": ("priv", "state", "transfers"),
}


def _cap(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _facet_for(focus: str, facets: tuple[str, ...]) -> tuple[str, ...]:
    key = next((k for k in _FOCUS_FACETS if k.split("_")[0] in focus.lower()), "access_control")
    return _FOCUS_FACETS.get(key, ("priv", "entry", "mods"))


def render_intel_brief(intel: "ContractIntel | None", focus: str,
                       file_hint: str | None = None) -> str:
    """Compact, focus-aware intel brief. Deterministic, capped, honest about
    gaps (unresolved externals + extraction warnings are always shown)."""
    if intel is None or not intel.contracts:
        return "(no deterministic intel available for this audit)"
    facets = _facet_for(focus, ())
    out: list[str] = []

    # -- contracts + inheritance -----------------------------------------
    lines = []
    for c in intel.contracts[:12]:
        bases = f" is {', '.join(c.bases)}" if c.bases else ""
        lines.append(f"{c.kind} {c.name}{bases} ({len(c.functions)} fns, "
                     f"{sum(1 for s in c.state_vars if not s.startswith('modifier:'))} vars)")
    out.append("CONTRACTS: " + "; ".join(lines))

    # -- privileged + initializers (access_control facet) ------------------
    if "priv" in facets:
        if intel.privileged_functions:
            out.append("PRIVILEGED FNS: " + "; ".join(intel.privileged_functions[:14]))
        if intel.initializer_functions:
            out.append("INITIALIZERS: " + "; ".join(intel.initializer_functions[:8]))

    # -- external entry points ---------------------------------------------
    if "entry" in facets:
        eps = intel.external_entry_points()[:14]
        if eps:
            out.append("ENTRY POINTS (public/external state-changing): " +
                      "; ".join(f"{f.contract}.{f.name}({f.params})" for f in eps))

    # -- state read/write map (cross-function interactions) -----------------
    if "state" in facets:
        seen_vars: list[str] = []
        for c in intel.contracts:
            for sv in c.state_vars:
                if sv.startswith("modifier:"):
                    continue
                w = intel.writers_of_state(sv)
                r = intel.readers_of_state(sv)
                if w or r:
                    seen_vars.append(f"{sv}: W[{','.join(w[:5])}] R[{','.join(r[:5])}]")
        if seen_vars:
            out.append("STATE ACCESS MAP: " + "; ".join(seen_vars[:12]))

    # -- internal call edges ---------------------------------------------------
    if "calls" in facets:
        edges = []
        for c in intel.contracts:
            for f in c.functions:
                if f.internal_calls:
                    edges.append(f"{f.name} -> {','.join(sorted(f.internal_calls)[:4])}")
        if edges:
            out.append("INTERNAL CALL EDGES: " + "; ".join(edges[:12]))

    # -- transfers (fund_flow facet) ------------------------------------------
    if "transfers" in facets:
        sites = []
        for c in intel.contracts:
            for f in c.functions:
                tags = []
                if f.ether_calls:
                    tags.append(f"eth x{f.ether_calls}")
                if f.delegatecalls:
                    tags.append(f"delegatecall x{f.delegatecalls}")
                if f.token_calls:
                    tags.append(",".join(sorted(set(f.token_calls))[:3]))
                if tags:
                    sites.append(f"{c.name}.{f.name} [{', '.join(tags)}]"
                                 + (f" L{f.line_start}" if f.line_start else ""))
        if sites:
            out.append("TRANSFER SITES: " + "; ".join(sites[:12]))

    # -- modifiers (authorization evidence) -------------------------------------
    if "mods" in facets:
        mods = []
        for c in intel.contracts:
            mn = [n.split(":", 1)[1] for n in c.state_vars if n.startswith("modifier:")]
            if mn:
                mods.append(f"{c.name}: {','.join(mn[:6])}")
        if mods:
            out.append("MODIFIERS: " + "; ".join(mods[:8]))

    # -- arithmetic / accounting ------------------------------------------------
    if "arith" in facets:
        arith = []
        for c in intel.contracts:
            for f in c.functions:
                if f.arithmetic:
                    ops = ",".join(sorted(f.arithmetic))
                    tag = " unchecked!" if f.unchecked else ""
                    arith.append(f"{f.name}({ops}{tag})")
        if arith:
            out.append("ARITHMETIC: " + "; ".join(arith[:10]))

    # -- proxy patterns + honesty section (always) --------------------------------
    if intel.proxy_hints:
        out.append("PROXY/UPGRADE HINTS: " + "; ".join(sorted(set(intel.proxy_hints))[:6]))
    if intel.slither_detectors:
        dets = [f"[{d.get('impact')}] {d.get('check')}: {d.get('description', '')[:80]}"
                for d in intel.slither_detectors[:6]]
        out.append("SLITHER DETECTORS (context, may be FP): " + " | ".join(dets))
    if intel.unresolved_externals:
        out.append("UNRESOLVED (bodies not in source; do NOT assume behavior): "
                   + "; ".join(sorted(intel.unresolved_externals)[:8]))
    if intel.extraction_warnings:
        out.append("INTEL WARNINGS: " + "; ".join(intel.extraction_warnings[:4]))

    # -- structural graphs (G+ Stage 4, when available) -----------------------
    cg = getattr(intel, "call_graph", None)
    sdg = getattr(intel, "state_deps", None)
    sinks = getattr(intel, "sinks", None)
    pats = getattr(intel, "proxy_patterns", None)
    if cg:
        edges = [f"{a}->{b}" for a, bs in list(cg.items())[:14]
                 for b in bs[:3]]
        if edges:
            out.append("CALL GRAPH: " + "; ".join(edges[:12]))
    if sdg:
        deps = [f"{v} W[{','.join(d['writers'][:3])}] R[{','.join(d['readers'][:3])}]"
                for v, d in list(sdg.items())[:10]]
        if deps:
            out.append("STATE DEPS: " + "; ".join(deps[:8]))
    if sinks:
        sks = [f"{s['fn']} [{','.join(s['ops'][:4])}]".replace(
            " ", "_") for s in sinks[:12]]
        if sks:
            out.append("SINKS: " + "; ".join(sks[:10]))
    if pats:
        pp = [f"{p.contract}={p.kind}" + (f"[gap]" if p.storage_gap_present else "")
              + (f"[init:{','.join(p.initializer_chain)}]" if p.initializer_chain else "")
              for p in pats[:6]]
        out.append("PROXY PATTERNS: " + "; ".join(pp))

    return _cap("\n".join(out), INTEL_BUDGET_CHARS)


def render_kb_snippets(records: list[dict[str, Any]]) -> str:
    """Render top KB records as untrusted historical-pattern excerpts.
    Each snippet forces the applicability question the agent must answer."""
    if not records:
        return "(no relevant knowledge-base records)"
    parts: list[str] = []
    for i, r in enumerate(records, 1):
        body = (
            f"[{r.get('id')}] {r.get('category')} / {r.get('protocol_type', 'generic')} — "
            f"mechanism: {r.get('mechanism')}\n"
            f"root cause: {r.get('root_cause')}\n"
            f"preconditions: {'; '.join(r.get('preconditions', []))}\n"
            f"impact: {r.get('impact')}\n"
            f"remediation: {r.get('remediation')}\n"
            f"source: {r.get('source')} ({r.get('url')})"
        )
        parts.append(f"--- KB-{i} ---\n{_cap(body, KB_SNIPPET_CHARS)}\n"
                     f"You MUST explicitly decide whether this mechanism "
                     f"applies to the code below and cite evidence; if it "
                     f"does not apply, do not report it.")
    return _cap("\n".join(parts), KB_BUDGET_CHARS)
