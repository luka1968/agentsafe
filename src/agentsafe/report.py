"""Report building: merge, dedupe, summarize. Zero findings NEVER equals safe.

Dedup rules (Prompt 7 + P4):
- detector-keyed findings merge by (detector_id, file, line) even with
  different titles;
- CROSS-ENGINE findings that describe the same root cause (same weakness class
  + overlapping location, or an identical SWC class that is unique per engine
  for bytecode findings without a source mapping) merge into ONE finding whose
  `source` lists every engine and whose metadata keeps every detector id;
- LLM findings merge into tool findings when location overlaps or evidence is
  strongly similar (cross-support is preserved, not discarded);
- every merge keeps ALL original sources in `source` and records merged_from.
"""

from __future__ import annotations

import difflib
import hashlib
import logging
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, Literal

from agentsafe import CHAIN_ID, REPORT_DISCLAIMER
from agentsafe.schemas import (
    AuditReport,
    Finding,
    FindingStatus,
    LLMUsage,
    ReportSummary,
    Severity,
    ToolExecution,
)

logger = logging.getLogger("agentSAFE.report")


def _derived_report_id(address: str) -> str:
    """Stable report id for audits run without a service task id (worker
    mode). Never used for auth - purely a human-facing label."""
    basis = f"{address}|{datetime.now(UTC).isoformat()}"
    return "AS-" + hashlib.sha1(basis.encode()).hexdigest()[:12]

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}
_STATUS_ORDER = {
    FindingStatus.CONFIRMED: 0,
    FindingStatus.HIGH_CONFIDENCE: 1,
    FindingStatus.POTENTIAL: 2,
    FindingStatus.NEEDS_MANUAL_REVIEW: 3,
    FindingStatus.UNVERIFIED: 4,
    FindingStatus.INFORMATIONAL: 5,
    FindingStatus.REJECTED: 6,
}
_EVIDENCE_SIMILARITY = 0.60
_LINE_TOLERANCE = 5

# Cross-engine root-cause classes. Two engines naming the same weakness with
# different identifiers (slither "reentrancy-eth" vs mythril "SWC-107") must
# merge into one vulnerability, not two. Only well-known equivalences are
# listed: an unknown detector is never collapsed.
_DETECTOR_CLASS: dict[str, str] = {
    "reentrancy-eth": "reentrancy",
    "reentrancy-no-eth": "reentrancy",
    "reentrancy-benign": "reentrancy",
    "reentrancy-event": "reentrancy",
    "reentrancy-unlimited-gas": "reentrancy",
    "integer-overflow": "arithmetic",
    "integer-underflow": "arithmetic",
    "unchecked-lowlevel": "unchecked-call",
    "unchecked-transfer": "unchecked-call",
    "unchecked-send": "unchecked-call",
    "controlled-delegatecall": "delegatecall",
    "delegatecall-to-user-supplied-address": "delegatecall",
    "arbitrary-send-eth": "arbitrary-send",
    "arbitrary-send-erc20": "arbitrary-send",
    "suicidal": "suicidal",
    "weak-prng": "prng",
    "tx-origin": "tx-origin",
    "incorrect-equality": "equality",
}
_SWC_CLASS: dict[str, str] = {
    "SWC-101": "arithmetic",
    "SWC-104": "unchecked-call",
    "SWC-105": "arbitrary-send",
    "SWC-106": "suicidal",
    "SWC-107": "reentrancy",
    "SWC-112": "delegatecall",
    "SWC-115": "equality",
    "SWC-120": "prng",
}
_CATEGORY_CLASS: dict[str, str] = {
    "reentrancy": "reentrancy",
    "arithmetic": "arithmetic",
    "unhandled_exception": "unchecked-call",
    "arbitrary_send": "arbitrary-send",
}


def root_cause_class(f: Finding) -> str | None:
    """Canonical weakness class used for CROSS-ENGINE dedup only.

    Resolution order: the detector id's documented equivalence, then its SWC
    id, then the finding category. Returns None when the class is unknown -
    unknown findings are never merged on class alone."""
    det = (f.detector_id or "").strip().lower()
    det = re.sub(r"^\[[^\]]*\]\s*", "", det)          # "[slither] reentrancy-eth"
    det = re.sub(r"^(?:mythril|aderyn|slither)[-_:]", "", det)
    det = det.replace("_", "-")
    if det in _DETECTOR_CLASS:
        return _DETECTOR_CLASS[det]
    if f.swc_id:
        cls = _SWC_CLASS.get(f.swc_id.strip().upper())
        if cls:
            return cls
    cat = f.category.value if f.category else ""
    return _CATEGORY_CLASS.get(cat)


def _same_location(a: Finding, b: Finding) -> bool:
    fa, fb = (a.file_path or "").lower(), (b.file_path or "").lower()
    if not fa or not fb or fa != fb:
        return False
    if a.line_start is None or b.line_start is None:
        return True
    return abs(a.line_start - b.line_start) <= _LINE_TOLERANCE


def _is_located(f: Finding) -> bool:
    return bool(f.file_path) and f.line_start is not None


def _merge_cross_engine(findings: Sequence[Finding]) -> list[Finding]:
    """Collapse findings from DIFFERENT engines that describe the same root
    cause, so one weakness never appears twice under two detector names.

    Located findings need the same file and overlapping lines. Bytecode
    findings (mythril) carry no source mapping, so they collapse only on an
    identical root-cause class that is UNIQUE per engine in this audit - a
    conservative rule that can never merge two distinct reentrancies."""
    per_class_engine: dict[tuple[str, str], int] = {}
    for f in findings:
        cls = root_cause_class(f)
        if cls:
            for src in f.source:
                per_class_engine[(cls, src)] = per_class_engine.get((cls, src), 0) + 1

    kept: list[Finding] = []
    for f in findings:
        cls = root_cause_class(f)
        host: Finding | None = None
        if cls:
            for k in kept:
                if root_cause_class(k) != cls:
                    continue
                if set(k.source) & set(f.source):
                    continue  # same engine: handled by the detector-key merge
                if _same_location(k, f):
                    host = k
                    break
                # Mixed located/unlocated (mythril has no source mapping):
                # merge only when that class is unique per engine in this
                # audit, so two distinct weaknesses of the same class can
                # never collapse together.
                if _is_located(k) != _is_located(f) and all(
                    per_class_engine.get((cls, s), 0) == 1
                    for s in (*k.source, *f.source)
                ):
                    host = k
                    break
            if host is None and cls and not _is_located(f):
                candidates = [
                    k
                    for k in kept
                    if root_cause_class(k) == cls
                    and not (set(k.source) & set(f.source))
                    and not _is_located(k)
                    and all(
                        per_class_engine.get((cls, s), 0) == 1
                        for s in (*k.source, *f.source)
                    )
                ]
                if len(candidates) == 1:
                    host = candidates[0]
        if host is None:
            kept.append(f)
            continue
        # Prefer the located record's source mapping on the survivor: source
        # mappings are data, not opinion - keep the most precise one.
        if not _is_located(host) and _is_located(f):
            host.file_path = f.file_path
            host.line_start = f.line_start
            host.line_end = f.line_end
        _absorb_into(host, f)  # in place: `host` is the object held in `kept`
    return kept


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def _similar(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, _norm(a)[:2000], _norm(b)[:2000]).ratio()


def _loc(f: Finding) -> tuple[str | None, int | None]:
    return ((f.file_path or "").lower() or None), f.line_start


def merge_findings(
    tool_findings: Sequence[Finding], llm_findings: Sequence[Finding]
) -> list[Finding]:
    """Deterministic, testable merge of VALIDATED findings.

    Inputs are expected to already carry final states (confirmed/potential/
    informational/rejected/needs_manual_review) from the ValidationAgent.
    Tool findings merge by detector key; LLM findings either merge into
    overlapping tool findings (upgrading the host to confirmed when the LLM
    hypothesis was corroborated) or survive standalone."""
    # 1) detector merge among tool findings
    merged_tool: dict[tuple, Finding] = {}
    for f in tool_findings:
        key = f.merge_key()
        if key in merged_tool:
            merged_tool[key] = _absorb(merged_tool[key], f)
        else:
            merged_tool[key] = f

    tool_list = list(merged_tool.values())
    # 1b) cross-engine root-cause merge: slither "reentrancy-eth" and mythril
    #     "SWC-107" on the same function are ONE vulnerability, not two.
    tool_list = _merge_cross_engine(tool_list)

    # 2) LLM findings: attach to overlapping tool findings, or keep standalone
    standalone: list[Finding] = []
    for f in llm_findings:
        host = _find_host(f, tool_list)
        if host is not None:
            _absorb_into(host, f, cross=True)
        else:
            standalone.append(f)

    # 3) LLM-vs-LLM duplicates by normalized title+location (highest-ranked
    #    status survives as primary). Agents phrase the same bug differently,
    #    so match on file + nearby line + title/evidence similarity, not on an
    #    exact title string (which is why simple key dedup let the same
    #    reentrancy survive once per agent).
    deduped: list[Finding] = []
    for f in standalone:
        host = _find_llm_host(f, deduped)
        if host is not None:
            idx = deduped.index(host)
            deduped[idx] = _absorb(host, f)
        else:
            deduped.append(f)

    out = tool_list + deduped
    # presentation order: confirmed issues first, hypotheses next, guidance,
    # and REJECTED findings always last (audit trail, not headline risk)
    out.sort(
        key=lambda f: (
            _STATUS_ORDER.get(f.status, 99),
            _SEVERITY_ORDER[f.severity],
            f.title,
        )
    )
    return out


def _absorb(primary: Finding, duplicate: Finding) -> Finding:
    """Return primary carrying duplicate's sources/evidence (never loses info)."""
    merged = primary.model_copy(deep=True)
    _absorb_into(merged, duplicate)
    return merged


def _absorb_into(host: Finding, dup: Finding, *, cross: bool = False) -> None:
    for s in dup.source:
        if s not in host.source:
            host.source.append(s)
    host.metadata.setdefault("merged_from", [])
    host.metadata["merged_from"].append(
        {
            "source": dup.source,
            "title": dup.title,
            "status": dup.status.value,
            "detector_id": dup.detector_id,
        }
    )
    if _norm(dup.evidence) and _norm(dup.evidence) not in _norm(host.evidence):
        host.evidence = (host.evidence + "\n--- additional evidence ---\n" + dup.evidence)[:4000]
    for ref in dup.supporting_evidence:
        if ref not in host.supporting_evidence:
            host.supporting_evidence.append(ref)
    for ref in dup.contradicting_evidence:
        if ref not in host.contradicting_evidence:
            host.contradicting_evidence.append(ref)
    for ref in dup.knowledge_references:
        if ref not in host.knowledge_references:
            host.knowledge_references.append(ref)
    if dup.confidence is not None:
        host.confidence = max(host.confidence or 0.0, dup.confidence)
    if dup.status is FindingStatus.REJECTED:
        return  # a rejected hypothesis never raises severity nor upgrades state
    if cross and dup.status is FindingStatus.CONFIRMED:
        # independent corroboration: the tool-detected host is now confirmed
        host.status = FindingStatus.CONFIRMED
        host.metadata.setdefault("validation", {})
        host.metadata["validation"]["rule"] = "cr0_llm_corroboration"
        host.metadata["validation"]["reason"] = (
            "an independent LLM agent reported the same issue at the same "
            "location with its own evidence"
        )
    if (
        cross
        and dup.severity in _SEVERITY_ORDER
        and _SEVERITY_ORDER[dup.severity] < _SEVERITY_ORDER[host.severity]
    ):
        host.severity = dup.severity  # cross-support may raise severity


def _find_host(candidate: Finding, tools: Sequence[Finding]) -> Finding | None:
    best: Finding | None = None
    best_score = 0.0
    for t in tools:
        score = 0.0
        (cf, cl), (tf, tl) = _loc(candidate), _loc(t)
        if cf and tf and cf == tf:
            if cl is None or tl is None or abs(cl - tl) <= _LINE_TOLERANCE:
                score = 0.9
        if score == 0.0:
            ev = _similar(candidate.evidence, t.evidence)
            ti = _similar(candidate.title, t.title)
            if ev >= _EVIDENCE_SIMILARITY and ti >= 0.4:
                score = ev * 0.85
        if score > best_score:
            best, best_score = t, score
    return best if best_score >= _EVIDENCE_SIMILARITY else None


def _find_llm_host(candidate: Finding, hosts: Sequence[Finding]) -> Finding | None:
    """LLM-vs-LLM merge target. Different agents report the same bug with
    different wording, so group by file + nearby line + strong title AND
    evidence similarity. A same-file, same-lane hit needs no exact title; a
    title-similar hit needs evidence overlap so distinct bugs never fuse."""
    best: Finding | None = None
    best_score = 0.0
    for t in hosts:
        # findings in different validation states are different conclusions;
        # a confirmed and a potential version of the same location must both
        # surface (the report needs both the claim and its assessment).
        if t.status is not candidate.status:
            continue
        score = 0.0
        (cf, cl), (tf, tl) = _loc(candidate), _loc(t)
        same_lane = False
        if cf and tf and cf == tf and cl is not None and tl is not None:
            if abs(cl - tl) <= _LINE_TOLERANCE:
                same_lane = True
        ev = _similar(candidate.evidence, t.evidence)
        ti = _similar(candidate.title, t.title)
        # Merge only when BOTH the lane overlaps AND the findings are about
        # the same bug (semantic similarity). Never fuse distinct bugs that
        # merely sit on nearby lines of the same file.
        if same_lane and (ti >= 0.55 or ev >= _EVIDENCE_SIMILARITY):
            score = 0.95
        elif same_lane:
            score = 0.80 * max(ti, ev)  # same region but weak semantics: low
        if score > best_score:
            best, best_score = t, score
    # require strong evidence of a duplicate, never a fuzzy word-match alone
    return best if best_score >= 0.85 else None


def summarize(
    findings: Sequence[Finding], tools_executed: Sequence[str], tools_failed: Sequence[str]
) -> ReportSummary:
    by_sev: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for f in findings:
        by_status[f.status.value] = by_status.get(f.status.value, 0) + 1
        # rejected findings are kept for auditability but excluded from the
        # severity headline: they are contradicted claims, not risks.
        if f.status is not FindingStatus.REJECTED:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
    return ReportSummary(
        total_findings=len(findings),
        by_severity=by_sev,
        by_status=by_status,
        tools_executed=list(tools_executed),
        tools_failed=list(tools_failed),
    )


def build_report(
    *,
    address: str,
    task_id: str | None,
    is_verified_source: bool,
    tool_findings: Sequence[Finding],
    llm_findings: Sequence[Finding],
    tools_executed: Sequence[str],
    tools_failed: Sequence[str],
    tool_versions: dict[str, str],
    llm_usage: LLMUsage,
    limitations: Sequence[str],
    errors: Sequence[str],
    execution_time_seconds: float,
    tool_executions: Sequence[ToolExecution] = (),
    static_analysis_status: Literal["full", "partial", "unavailable", "skipped"] = "skipped",
    audit_state: Literal["complete", "partial", "failed"] = "complete",
    compiler_version: str = "",
    analyzed_files: Sequence[str] = (),
    invariant_checks: Sequence[dict[str, Any]] = (),
    attack_paths: Sequence[dict[str, Any]] = (),
    targeted_test_results: Sequence[dict[str, Any]] = (),
    adversarial_review: dict[str, Any] | None = None,
    coverage: dict[str, Any] | None = None,
    deployment: dict[str, Any] | None = None,
) -> AuditReport:
    findings = merge_findings(tool_findings, llm_findings)
    report = AuditReport(
        address=address,
        chain=CHAIN_ID,
        task_id=task_id,
        report_id=task_id or _derived_report_id(address),
        timestamp=datetime.now(UTC),
        is_verified_source=is_verified_source,
        compiler_version=compiler_version,
        analyzed_files=list(analyzed_files),
        summary=summarize(findings, tools_executed, tools_failed),
        findings=findings,
        tool_executions=list(tool_executions),
        tools_used=sorted(set(tools_executed) | set(tools_failed)),
        tool_versions=dict(tool_versions),
        llm_usage=llm_usage,
        limitations=list(limitations),
        errors=list(errors),
        execution_time_seconds=round(execution_time_seconds, 2),
        disclaimer=REPORT_DISCLAIMER,
        invariant_checks=list(invariant_checks),
        attack_paths=list(attack_paths),
        targeted_test_results=list(targeted_test_results),
        adversarial_review=dict(adversarial_review or {}),
        coverage=dict(coverage or {}),
        deployment=dict(deployment or {}),
    )
    report.summary.static_analysis_status = static_analysis_status
    # Never label a degraded audit complete: even if a caller forgets to pass
    # the explicit state, any failed engine, failed stage or unavailable
    # static analysis demotes the report to partial.
    if audit_state == "complete" and (
        static_analysis_status in ("partial", "unavailable")
        or tools_failed
        or errors
    ):
        audit_state = "partial"
    report.summary.audit_state = audit_state
    return report
