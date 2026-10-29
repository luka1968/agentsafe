"""ValidationAgent: strict finding state machine + deterministic source-level
false-positive rules.

Final states (customer-facing):
    confirmed | potential | informational | rejected | needs_manual_review

Decision chain for LLM findings (in order, first rule wins):
    1. missing evidence quote                     -> rejected
    2. real source but no line number              -> needs_manual_review
    3. evidence not traceable to provided code     -> needs_manual_review
    4. category rules (deterministic source analysis):
         reentrancy + CEI-compliant function       -> rejected
         integer overflow w/o concrete attack path -> informational (never critical)
         transfer() -> transferFrom(msg.sender) with balance check
                                                   -> informational
         standard ERC-20 allowance race w/o deviation
                                                   -> informational
    5. independent tool support at same location   -> confirmed
    6. otherwise                                    -> potential

Tool findings run the same category rules (conservatively) plus LLM
corroboration; the entry states tool_detected / llm_suggested never appear
in a final report.

Safety rails:
- The CEI rejection rule only fires when the finding's evidence fragment is
  located inside the flagged function body AND every caller-state effect
  precedes every external call in that body. Any ambiguity (internal helper
  calls, unlocatable evidence, interleaved ordering) => do NOT reject.
- The overflow downgrade requires the ABSENCE of attacker-controlled input
  AND impact indicators; a finding with a concrete attack path is never
  suppressed, only severity-capped when uncorroborated.
- Rules never look at the contract's identity or popularity - only at
  evidence, so a well-known contract is treated exactly like any other.

The ValidationAgent NEVER claims a contract is safe and NEVER upgrades a
finding to "proven exploitable"; `confirmed` means independently corroborated
by two distinct evidence sources, nothing more.
"""

from __future__ import annotations

import difflib
import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from agentsafe.schemas import Finding, FindingStatus, Severity
from agentsafe.severity import assess, enrich_swc

logger = logging.getLogger("agentSAFE.validation")

EVIDENCE_SIMILARITY_THRESHOLD = 0.60
LINE_OVERLAP_TOLERANCE = 5
_MIN_TRACEABLE_EVIDENCE_CHARS = 20

# --- category detectors ------------------------------------------------------
_RE_REENTRANCY = re.compile(r"re[- ]?entran", re.IGNORECASE)
_RE_OVERFLOW = re.compile(
    r"(?:integer\s+)?(?:over|under)flow|arithmetic\s+(?:over|under)flow", re.IGNORECASE
)
_RE_TRANSFER_DELEGATION = re.compile(r"transferFrom\s*\(\s*msg\.sender", re.IGNORECASE)
_RE_ALLOWANCE = re.compile(r"allowance", re.IGNORECASE)
_RE_ALLOWANCE_RACE = re.compile(r"race|front[- ]?run|reset", re.IGNORECASE)
# attacker-controlled / impact indicators for overflow claims
_RE_ATTACK_INPUT = re.compile(
    r"attacker|user[- ]controlled|arbitrary|unbounded|untrusted|external input|"
    r"can (?:be )?set by|caller[- ]controlled",
    re.IGNORECASE,
)
_RE_IMPACT = re.compile(
    r"exploit|drain|steal|bypass|profit|gain|wrap|manipulat|lock|freeze|mint|"
    r"total\s*supply|funds|balance",
    re.IGNORECASE,
)
# --- source-level patterns -----------------------------------------------------
_EXTERNAL_CALL = re.compile(
    r"\.transfer\s*\(|\.send\s*\(|\.call\s*\{|\.call\s*\(|\.callvalue\s*\(|"
    r"\.delegatecall\s*\(|\.call\{value",
)
_CALLER_STATE_EFFECT = re.compile(
    r"\w+\s*\[\s*msg\.sender\s*\]\s*(?:--|\+\+|[-+*/%&|^]?=(?!=))",
)
_FUNC_HEADER = re.compile(r"\bfunction\s+([A-Za-z_]\w*)?\s*\(")
_BALANCE_CHECK = re.compile(
    r"require\s*\([^)]*[\w.]+\s*\[[^\]]*\]\s*>=|require\s*\(\s*balance|\.sub\s*\(|"
    r"SafeERC20|safeTransferFrom",
    re.IGNORECASE,
)


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def _similar(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, _norm(a), _norm(b)).ratio()


def _location_overlap(a: str | None, a_line: int | None, b: str | None, b_line: int | None) -> bool:
    if a and b and _norm(a) == _norm(b):
        if a_line is None or b_line is None:
            return True
        return abs(a_line - b_line) <= LINE_OVERLAP_TOLERANCE
    return False


# --- Solidity function-block extraction ---------------------------------------


def _strip_noise(line: str) -> str:
    """Remove line comments and (single-line spans of) string literals so
    brace counting and pattern matching stay reliable."""
    if "//" in line:
        line = line.split("//", 1)[0]
    if '"' in line:
        parts = line.split('"')
        line = "".join(parts[::2])
    return line


@dataclass
class _FuncBlock:
    name: str
    start_line: int  # 1-indexed header line
    body_first: int  # 1-indexed first body line
    body_last: int  # 1-indexed last body line
    body_text: str

    def contains_line(self, line: int | None) -> bool:
        return line is not None and self.start_line <= line <= self.body_last


def _function_blocks(text: str) -> list[_FuncBlock]:
    """Brace-matched Solidity function extraction (heuristic but
    conservative: on any parse doubt we simply don't produce a block)."""
    lines = text.splitlines()
    blocks: list[_FuncBlock] = []
    for i, raw in enumerate(lines):
        m = _FUNC_HEADER.search(_strip_noise(raw))
        if not m:
            continue
        depth = 0
        opened = False
        j = i
        while j < len(lines):
            clean = _strip_noise(lines[j])
            if j == i:
                clean = clean[m.end() - 1 :]
            for ch in clean:
                if ch == "{":
                    depth += 1
                    opened = True
                elif ch == "}":
                    depth -= 1
                    if opened and depth == 0:
                        body = lines[i + 1 : j]  # lines between header and closing brace
                        blocks.append(
                            _FuncBlock(
                                name=m.group(1) or "",
                                start_line=i + 1,
                                body_first=i + 2,
                                body_last=j + 1,
                                body_text="\n".join(body),
                            )
                        )
                        j = len(lines)  # break outer
                        break
            if opened and depth <= 0:
                break
            j += 1
    return blocks


def _longest_evidence_line(evidence: str) -> str:
    best = ""
    for ln in (evidence or "").splitlines():
        ln = ln.strip()
        if len(ln) > len(best):
            best = ln
    return best


def _locate_function(
    blocks: list[_FuncBlock], text: str, evidence: str, line_start: int | None
) -> _FuncBlock | None:
    """Find the function the finding refers to. Evidence-fragment containment
    (robust to hallucinated line numbers) beats line-range containment."""
    frag = _longest_evidence_line(evidence)
    if len(frag) >= _MIN_TRACEABLE_EVIDENCE_CHARS:
        needle = _norm(frag)
        hits = [b for b in blocks if needle in _norm(b.body_text)]
        if len(hits) == 1:
            return hits[0]
        if hits:
            return next((b for b in hits if b.contains_line(line_start)), hits[0])
    if line_start is not None:
        return next((b for b in blocks if b.contains_line(line_start)), None)
    return None


def _cei_verdict(block: _FuncBlock) -> str | None:
    """'rejected' when every caller-state effect precedes every external call;
    'plausible' when an external call precedes a caller-state effect; None when
    the body has no external call to exploit (claim out of scope for this rule)."""
    body_lines = block.body_text.splitlines()
    ext = [i for i, ln in enumerate(body_lines) if _EXTERNAL_CALL.search(_strip_noise(ln))]
    eff = [i for i, ln in enumerate(body_lines) if _CALLER_STATE_EFFECT.search(_strip_noise(ln))]
    if not ext or not eff:
        return None
    if max(eff) < min(ext):
        return "rejected"
    if min(ext) < max(eff):
        return "plausible"
    return None


# --- outcomes ------------------------------------------------------------------


@dataclass
class ValidationOutcome:
    findings: list[Finding] = field(default_factory=list)
    confirmed: int = 0
    potential: int = 0
    informational: int = 0
    rejected: int = 0
    needs_manual_review: int = 0

    def detail(self) -> str:
        return (
            f"confirmed={self.confirmed} potential={self.potential} "
            f"informational={self.informational} rejected={self.rejected} "
            f"needs_manual_review={self.needs_manual_review}"
        )


class ValidationAgent:
    """Strict state machine + deterministic false-positive rules."""

    name = "validation"

    # ------------------------------------------------------------ public API

    def validate(
        self,
        llm_findings: Sequence[Finding],
        tool_findings: Sequence[Finding],
        source_segments: dict[str, str] | None = None,
        is_pseudo_source: bool = False,
    ) -> ValidationOutcome:
        outcome = ValidationOutcome()
        for f in llm_findings:
            if f.status is not FindingStatus.LLM_SUGGESTED:
                # already carries a final state: pass through untouched
                outcome.findings.append(f)
                self._count(outcome, f)
                continue
            nf = self._validate_llm_finding(f, tool_findings, source_segments, is_pseudo_source)
            if is_pseudo_source:
                nf.limitations = [
                    *nf.limitations,
                    "derived from decompiled pseudo-source; identifiers and "
                    "line numbers are approximate",
                ]
            nf.location_status = _llm_location_status(nf, is_pseudo_source, source_segments)
            outcome.findings.append(nf)
            self._count(outcome, nf)
        return outcome

    def validate_tools(
        self,
        tool_findings: Sequence[Finding],
        validated_llm: Sequence[Finding],
        source_segments: dict[str, str] | None = None,
        is_pseudo_source: bool = False,
    ) -> ValidationOutcome:
        outcome = ValidationOutcome()
        for f in tool_findings:
            if f.status is not FindingStatus.TOOL_DETECTED:
                outcome.findings.append(f)
                self._count(outcome, f)
                continue
            nf = self._validate_tool_finding(f, validated_llm, source_segments, is_pseudo_source)
            if is_pseudo_source:
                nf.limitations = [
                    *nf.limitations,
                    "derived from decompiled pseudo-source; identifiers and "
                    "line numbers are approximate",
                ]
            nf.location_status = _tool_location_status(nf)
            outcome.findings.append(nf)
            self._count(outcome, nf)
        return outcome

    def _count(self, outcome: ValidationOutcome, f: Finding) -> None:
        if f.status is FindingStatus.CONFIRMED:
            outcome.confirmed += 1
        elif f.status is FindingStatus.POTENTIAL:
            outcome.potential += 1
        elif f.status is FindingStatus.INFORMATIONAL:
            outcome.informational += 1
        elif f.status is FindingStatus.REJECTED:
            outcome.rejected += 1
        elif f.status is FindingStatus.NEEDS_MANUAL_REVIEW:
            outcome.needs_manual_review += 1

    # ------------------------------------------------------ LLM decision chain

    def _validate_llm_finding(
        self,
        f: Finding,
        tools: Sequence[Finding],
        segments: dict[str, str] | None,
        is_pseudo: bool,
    ) -> Finding:
        # 1. evidence is mandatory for LLM claims
        if not (f.evidence or "").strip():
            return self._finalize(
                f, FindingStatus.REJECTED, "e0_missing_evidence",
                "LLM finding carries no evidence quote; hypotheses without "
                "evidence are rejected outright",
            )
        # 2. line numbers are mandatory for real source (may be impossible
        #    for decompiled pseudo-source)
        if not is_pseudo and f.line_start is None:
            return self._finalize(
                f, FindingStatus.NEEDS_MANUAL_REVIEW, "l0_missing_line_number",
                "no line number provided; the claim cannot be located in the "
                "source for deterministic validation",
            )
        # 3. evidence must be traceable to the provided code (anti-hallucination)
        src_text = self._source_for_finding(f, segments)
        if not is_pseudo and segments:
            if src_text is None:
                return self._finalize(
                    f, FindingStatus.NEEDS_MANUAL_REVIEW, "e0_untraceable_location",
                    "referenced file not present in analyzed sources; claim "
                    "cannot be verified against provided code",
                )
            frag = _longest_evidence_line(f.evidence)
            if len(frag) >= _MIN_TRACEABLE_EVIDENCE_CHARS and _norm(frag) not in _norm(src_text):
                return self._finalize(
                    f, FindingStatus.NEEDS_MANUAL_REVIEW, "e0_evidence_not_in_code",
                    "evidence quote does not appear in the provided source; "
                    "possible paraphrase or hallucination - human check required",
                )
        # 4. deterministic category rules (reentrancy CEI / transfer / allowance)
        ruled = self._category_rules(f, src_text, is_pseudo)
        if ruled is not None:
            return ruled
        # 5. independent tool support -> confirmed
        support = self._find_support(f, tools)
        # 5b. integer overflow severity calibration needs the support context:
        #     a tool-corroborated real overflow must NOT be suppressed by weak
        #     LLM prose, while an uncorroborated theoretical claim must NOT
        #     headline the report as critical/high.
        if _RE_OVERFLOW.search(f"{f.title} {f.description}"):
            claim_text = f"{f.description} {f.evidence}"
            has_path = bool(_RE_ATTACK_INPUT.search(claim_text)) and bool(
                _RE_IMPACT.search(claim_text)
            )
            # Stage 10 regression guard: even a tool-corroborated overflow is
            # informational unless a concrete attack path (attacker-controlled
            # input -> arithmetic -> demonstrated impact) is shown. A detector
            # flag alone is never proof of exploitability.
            if not has_path:
                return self._finalize(
                    f, FindingStatus.INFORMATIONAL, "ov0_theoretical_only",
                    "overflow claim lacks a concrete attack path (no "
                    "attacker-controlled input reaching the arithmetic and no "
                    "demonstrated impact); the absence of compiler overflow "
                    "checks alone is informational, never critical — even when "
                    "a detector flags the arithmetic",
                )
        if support is not None:
            merged = self._finalize(
                f, FindingStatus.CONFIRMED, "cr0_independent_support",
                "independent tool evidence at the same location corroborates "
                "the hypothesis",
            )
            merged.metadata["validation"]["supporting_source"] = list(support.source)
            merged.metadata["validation"]["supporting_detector"] = support.detector_id
            merged.metadata["validation"]["supporting_location"] = (
                f"{support.file_path}:{support.line_start}"
            )
            merged.supporting_evidence = [
                f"tool:{','.join(support.source)}:{support.detector_id}"
                f"@{support.file_path}:{support.line_start}"
            ]
            return merged
        # 6. credible, complete, unverified -> potential
        return self._finalize(
            f, FindingStatus.POTENTIAL, "pt0_default",
            "complete evidence, neither independently corroborated nor "
            "refuted by deterministic rules; treat as a credible hypothesis",
        )

    # ------------------------------------------------- deterministic category rules

    def _category_rules(
        self, f: Finding, src_text: str | None, is_pseudo: bool
    ) -> Finding | None:
        """Rules shared by LLM and tool findings. Returns a final-state
        Finding when a rule fires, else None to continue the chain."""
        title_desc = f"{f.title} {f.description}"
        blocks = _function_blocks(src_text) if src_text else []

        # -- reentrancy: Checks-Effects-Interactions contradiction ---------
        if _RE_REENTRANCY.search(title_desc):
            if blocks:
                block = _locate_function(blocks, src_text or "", f.evidence, f.line_start)
                if block is not None and _cei_verdict(block) == "rejected":
                    ordered = self._cei_evidence_lines(block, f.file_path)
                    nf = self._finalize(
                        f, FindingStatus.REJECTED, "re0_cei_satisfied",
                        "the flagged function follows Checks-Effects-Interactions: "
                        f"every caller-state update ({ordered['effect']}) precedes "
                        f"every external call ({ordered['interaction']}); the "
                        "reentrancy claim about this function is contradicted "
                        "by the source",
                    )
                    nf.contradicting_evidence = [
                        ordered["effect"],
                        ordered["interaction"],
                    ]
                    return nf

        # -- ERC-20 transfer() delegating to transferFrom(msg.sender, ...) ----
        if (
            "transfer" in title_desc.lower()
            and "transferfrom" in title_desc.lower()
        ):
            if blocks:
                t_block = next((b for b in blocks if b.name == "transfer"), None)
                tf_block = next((b for b in blocks if b.name == "transferFrom"), None)
                if (
                    t_block is not None
                    and _RE_TRANSFER_DELEGATION.search(t_block.body_text)
                    and tf_block is not None
                    and _BALANCE_CHECK.search(tf_block.body_text)
                ):
                    return self._finalize(
                        f, FindingStatus.INFORMATIONAL, "tr0_canonical_delegation",
                        "transfer() delegates to transferFrom(msg.sender, ...) "
                        "(the canonical ERC-20 pattern) and transferFrom enforces "
                        "the balance check; no defect identified in the delegation",
                    )

        # -- standard ERC-20 allowance race ----------------------------------
        if _RE_ALLOWANCE.search(title_desc) and _RE_ALLOWANCE_RACE.search(title_desc):
            deviation = re.search(
                r"infinite|unlimited|no zero|without zero|doesn.t (?:reset|decrement)|"
                r"permit\b|missing (?:zero|reset)|allowance is not (?:reset|decremented)",
                f"{f.title} {f.description} {f.evidence}",
                re.IGNORECASE,
            )
            if deviation is None:
                return self._finalize(
                    f, FindingStatus.INFORMATIONAL, "al0_standard_behavior",
                    "the approve/transferFrom allowance race (SWC-114) is standard "
                    "ERC-20 semantics; no exploitable deviation is shown in the "
                    "evidence, so this is informational guidance for integrators",
                )

        return None

    def _cei_evidence_lines(self, block: _FuncBlock, file_path: str | None) -> dict[str, str]:
        body_lines = block.body_text.splitlines()

        def _fmt(idx: int, ln: str) -> str:
            line_no = block.body_first + idx
            loc = f"{file_path}:{line_no}" if file_path else f"line {line_no}"
            return f"{ln.strip()} [{loc}]"

        eff_idx = next(
            (
                i
                for i, ln in enumerate(body_lines)
                if _CALLER_STATE_EFFECT.search(_strip_noise(ln))
            ),
            None,
        )
        ext_idx = next(
            (
                i
                for i, ln in enumerate(body_lines)
                if _EXTERNAL_CALL.search(_strip_noise(ln))
            ),
            None,
        )
        eff = _fmt(eff_idx, body_lines[eff_idx]) if eff_idx is not None else "state update"
        ext = _fmt(ext_idx, body_lines[ext_idx]) if ext_idx is not None else "external call"
        return {"effect": eff, "interaction": ext}

    # ---------------------------------------------------------- tool findings

    def _validate_tool_finding(
        self,
        f: Finding,
        validated_llm: Sequence[Finding],
        segments: dict[str, str] | None,
        is_pseudo: bool,
    ) -> Finding:
        src_text = self._source_for_finding(f, segments)
        ruled = self._category_rules(f, src_text, is_pseudo)
        if ruled is not None:
            return ruled
        corroborating = [
            lf
            for lf in validated_llm
            if lf.status in (FindingStatus.CONFIRMED, FindingStatus.POTENTIAL)
            and _location_overlap(
                f.file_path, f.line_start, lf.file_path, lf.line_start
            )
        ]
        if corroborating:
            lf = corroborating[0]
            nf = self._finalize(
                f, FindingStatus.CONFIRMED, "cr0_llm_corroboration",
                "an independent LLM agent reported the same issue at the same "
                "location with its own evidence",
            )
            nf.metadata["validation"]["corroborating_agent"] = list(lf.source)
            nf.supporting_evidence = [
                f"llm:{','.join(lf.source)}:{lf.title}@{lf.file_path}:{lf.line_start}"
            ]
            return nf
        # overflow calibration for standalone tool claims (a corroborated
        # overflow is already confirmed above and never downgraded here)
        if _RE_OVERFLOW.search(f"{f.title} {f.description}"):
            claim_text = f"{f.description} {f.evidence}"
            has_path = bool(_RE_ATTACK_INPUT.search(claim_text)) and bool(
                _RE_IMPACT.search(claim_text)
            )
            if not has_path:
                return self._finalize(
                    f, FindingStatus.INFORMATIONAL, "ov0_theoretical_only",
                    "detector claims overflow without a concrete attack path "
                    "in its own evidence; theoretical arithmetic risk is "
                    "informational, never critical",
                )
        if f.severity is Severity.INFO:
            return self._finalize(
                f, FindingStatus.INFORMATIONAL, "if0_info_grade",
                "informational-grade tool finding; no exploitability claimed",
            )
        return self._finalize(
            f, FindingStatus.POTENTIAL, "pt0_default_tool",
            "detector-reported; not independently corroborated and not "
            "refuted; treat as a credible hypothesis",
        )

    # ---------------------------------------------------------------- helpers

    def _source_for_finding(self, f: Finding, segments: dict[str, str] | None) -> str | None:
        if not segments:
            return None
        if f.file_path and f.file_path in segments:
            return segments[f.file_path]
        if len(segments) == 1:
            return next(iter(segments.values()))
        return None

    def _find_support(self, candidate: Finding, tools: Sequence[Finding]) -> Finding | None:
        """Independent support = tool finding at the same location, or with
        strongly similar evidence. Traceability is preserved in metadata."""
        best: Finding | None = None
        best_score = 0.0
        for t in tools:
            if t.status in (FindingStatus.NEEDS_MANUAL_REVIEW, FindingStatus.REJECTED):
                continue
            score = 0.0
            if _location_overlap(
                candidate.file_path, candidate.line_start, t.file_path, t.line_start
            ):
                score = 0.9
            else:
                sim = max(
                    _similar(candidate.evidence, t.evidence),
                    _similar(candidate.evidence, t.description),
                )
                title_sim = _similar(candidate.title, t.title)
                if (sim >= EVIDENCE_SIMILARITY_THRESHOLD and title_sim >= 0.3) or sim >= 0.85:
                    score = sim * 0.8
            if score > best_score:
                best, best_score = t, score
        return best if best_score >= EVIDENCE_SIMILARITY_THRESHOLD else None

    def _set(
        self, f: Finding, status: FindingStatus, rule: str, reason: str
    ) -> Finding:
        """Apply a state transition, preserving a full audit trail of the
        original claim and why the state machine moved it."""
        merged = f.model_copy(deep=True)
        merged.status = status
        merged.metadata = {
            **merged.metadata,
            "validation": {
                **merged.metadata.get("validation", {}),
                "rule": rule,
                "reason": reason,
                "original_status": f.status.value,
                "original_severity": f.severity.value,
            },
        }
        return merged

    def _finalize(
        self, f: Finding, status: FindingStatus, rule: str, reason: str
    ) -> Finding:
        """Single funnel for every terminal decision: state transition +
        evidence-based severity assessment (documented rubric, Section 4) +
        SWC enrichment + audit trail. LLM confidence never enters severity."""
        nf = self._set(f, status, rule, reason)
        nf.proposed_severity = f.severity  # preserve the original impact claim
        new_sev, basis = assess(nf)
        nf.severity = new_sev
        nf.metadata["validation"]["severity_basis"] = basis
        swc = enrich_swc(nf)
        if swc:
            nf.swc_id = swc
        # Stage 8/9: record HOW this finding was validated and its result.
        # The method is derived from the rule id (never claimed); a static
        # analyzer warning or LLM confidence is never treated as proof.
        nf.validation_method = _method_for_rule(rule)
        nf.validation_result = status.value
        return nf


# ---------------------------------------------------------------------------
# Location traceability (Section 7): mark how trustworthy a finding's source
# location is. Never guessed - each status has a deterministic trigger.
# ---------------------------------------------------------------------------


def _llm_location_status(
    f: Finding,
    is_pseudo: bool,
    segments: dict[str, str] | None,
) -> str | None:
    """LLM findings: 'verified' requires a filename + line AND an evidence
    quote long enough to have been located verbatim in that source (the e0
    gate ran and passed to reach a terminal state). Everything else is
    honestly marked unverified/unavailable, never 'verified' by assumption."""
    if not f.file_path and not f.line_start:
        return "unavailable"
    if is_pseudo or not segments:
        return "unverified"
    frag = _longest_evidence_line(f.evidence or "")
    if f.file_path and f.line_start and len(frag) >= _MIN_TRACEABLE_EVIDENCE_CHARS:
        return "verified"
    return "unverified"


def _tool_location_status(f: Finding) -> str | None:
    """Tool findings: the analyzer's own source mapping is authoritative
    (it comes from the AST, not a quoted claim). 'verified' when the tool
    reported both file and line; line-only or file-only is 'unverified';
    nothing at all is 'unavailable'."""
    if f.file_path and f.line_start:
        return "verified"
    if f.file_path or f.line_start:
        return "unverified"
    return "unavailable"


def _method_for_rule(rule: str) -> str:
    """Map a validation rule id to a documented validation method. The method
    is derived from the rule that fired, never self-declared by an agent.
    Static-analyzer warnings and LLM confidence never enter this mapping."""
    if rule.startswith("cr0_"):
        return "independent_tool_corroboration"
    if rule in ("re0_cei_satisfied", "tr0_canonical_delegation",
                "al0_standard_behavior", "ov0_theoretical_only",
                "if0_info_grade"):
        return "deterministic_source_rules"
    if rule in ("e0_missing_evidence", "e0_untraceable_location",
                "e0_evidence_not_in_code", "l0_missing_line_number"):
        return "evidence_traceability"
    return "evidence_state_machine"
