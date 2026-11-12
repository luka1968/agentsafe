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
        attack = r.get("attack_scenario")
        attack_line = f"attack scenario: {attack}\n" if attack else ""
        vcode = r.get("vulnerable_code")
        ccode = r.get("corrected_code")
        code_lines = ""
        if vcode or ccode:
            code_lines = (
                f"vulnerable code: {vcode}\n"
                + (f"corrected code: {ccode}\n" if ccode else "")
            )
        # Category B (attack-path) block: entry point, call sequence, state
        # variables and cross-contract dependencies guide multi-call discovery.
        path_lines = ""
        entry = r.get("attack_entry")
        seq = r.get("call_sequence") or []
        svars = r.get("state_vars") or []
        ccd = r.get("cross_contract_deps") or []
        if entry or seq:
            parts_ = [f"attack entry: {entry}" if entry else None,
                      f"call sequence: {' -> '.join(seq)}" if seq else None,
                      f"state vars: {', '.join(svars)}" if svars else None,
                      f"cross-contract deps: {'; '.join(ccd)}" if ccd else None]
            non_null = [p for p in parts_ if p]
            if non_null:
                path_lines = "\n".join(non_null) + "\n"
        # Category C (accounting) block: the invariant that must hold, the
        # actual deviation, and the evidence — key for financial bug discovery.
        acct_lines = ""
        invariant = r.get("invariant")
        ib = r.get("incorrect_behavior")
        ve = r.get("verification_evidence")
        if invariant or ib or ve:
            parts_ = [f"expected invariant: {invariant}" if invariant else None,
                      f"incorrect behavior: {ib}" if ib else None,
                      f"verification evidence: {ve}" if ve else None]
            non_null = [p for p in parts_ if p]
            if non_null:
                acct_lines = "\n".join(non_null) + "\n"
        # Category D (oracle) block: oracle type/source + freshness +
        # validation requirements, so price findings are grounded.
        oracle_lines = ""
        ot = r.get("oracle_type")
        ps = r.get("price_source")
        fr = r.get("freshness_requirements")
        pv = r.get("price_validation")
        if ot or ps or fr or pv:
            parts_ = [f"oracle type: {ot}" if ot else None,
                      f"price source: {ps}" if ps else None,
                      f"freshness required: {fr}" if fr else None,
                      f"price validation: {pv}" if pv else None]
            non_null = [p for p in parts_ if p]
            if non_null:
                oracle_lines = "\n".join(non_null) + "\n"
        # Category E (secure-code / FP) block: the safe pattern, why it is
        # safe, its limitations, and the evidence required to override the
        # safe default — reduces false positives on external/low-level calls.
        secure_lines = ""
        sp = r.get("security_pattern")
        ws = r.get("why_safe")
        kl = r.get("known_limitations")
        fpp = r.get("fp_patterns")
        er = r.get("evidence_required")
        if sp or ws or fpp or er:
            parts_ = [f"security pattern: {sp}" if sp else None,
                      f"why safe: {ws}" if ws else None,
                      f"known limitations: {kl}" if kl else None,
                      f"false-positive shapes: {fpp}" if fpp else None,
                      f"evidence required to report: {er}" if er else None]
            non_null = [p for p in parts_ if p]
            if non_null:
                secure_lines = "\n".join(non_null) + "\n"
        # Category F (verification / PoC) block: how to PROVE or REFUTE a
        # candidate finding, and — for reproduced PoC records — the harness
        # metadata (repo, contracts, toolchain, recorded result).
        verify_lines = ""
        vm = r.get("verification_method")
        poc = r.get("poc_code")
        csg = r.get("confirmation_signals")
        rfs = r.get("refutation_signals")
        tr = r.get("test_result")
        ac2 = r.get("attacker_contract")
        solc = r.get("solc_version")
        fv = r.get("foundry_version")
        pocr = r.get("poc_reference")
        if vm or poc or csg or rfs:
            parts_ = [f"verify via: {vm}" if vm else None,
                      f"PoC: {poc}" if poc else None,
                      f"confirms if: {csg}" if csg else None,
                      f"refutes if: {rfs}" if rfs else None]
            non_null = [p for p in parts_ if p]
            if non_null:
                verify_lines = "\n".join(non_null) + "\n"
        poc_meta = ""
        if tr or ac2 or pocr:
            parts_ = [f"vulnerable contract: {r.get('affected_contract')}"
                      if r.get("affected_contract") else None,
                      f"attacker contract: {ac2}" if ac2 else None,
                      f"PoC repo: {pocr}" if pocr else None,
                      f"test result: {tr}" if tr else None,
                      f"toolchain: solc {solc} / {fv}" if solc or fv else None]
            non_null = [p for p in parts_ if p]
            if non_null:
                poc_meta = "\n".join(non_null) + "\n"
        body = (
            f"[{r.get('id')}] {r.get('category')} / {r.get('protocol_type', 'generic')} — "
            f"mechanism: {r.get('mechanism')}\n"
            f"root cause: {r.get('root_cause')}\n"
            f"preconditions: {'; '.join(r.get('preconditions', []))}\n"
            f"{path_lines}"
            f"{acct_lines}"
            f"{oracle_lines}"
            f"{secure_lines}"
            f"{verify_lines}"
            f"{poc_meta}"
            f"{attack_line}"
            f"{code_lines}"
            f"impact: {r.get('impact')}\n"
            f"remediation: {r.get('remediation')}\n"
            f"source: {r.get('source')} ({r.get('url')})"
        )
        parts.append(f"--- KB-{i} ---\n{_cap(body, KB_SNIPPET_CHARS)}\n"
                     f"You MUST explicitly decide whether this mechanism "
                     f"applies to the code below and cite evidence; if it "
                     f"does not apply, do not report it. This record is "
                     f"SUPPORTING EVIDENCE, never automatic proof of a "
                     f"vulnerability. Before reporting, you MUST: "
                     f"(1) compare the target code against the mechanism and "
                     f"identify which preconditions MATCH and which DO NOT; "
                     f"(2) analyze the actual code path in the contract, not "
                     f"the pattern in the record; (3) check whether the "
                     f"alleged impact is actually reachable in THIS code; "
                     f"(4) consider the secure-implementation counterexample "
                     f"and why the code does or does not deviate from it; "
                     f"(5) cite source-level evidence (function, line, code "
                     f"snippet) for every claim; (6) assign confidence "
                     f"proportional to the evidence, not to the record's "
                     f"existence. Do NOT report a vulnerability solely "
                     f"because a similar knowledge-base record exists; if "
                     f"the preconditions do not hold in this code, do not "
                     f"report it.")
    return _cap("\n".join(parts), KB_BUDGET_CHARS)
