"""Report building: merge, dedupe, summarize. Zero findings NEVER equals safe.

Dedup rules (Prompt 7):
- detector-keyed findings merge by (detector_id, file, line) even with
  different titles;
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
from typing import Literal

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
    FindingStatus.POTENTIAL: 1,
    FindingStatus.NEEDS_MANUAL_REVIEW: 2,
    FindingStatus.INFORMATIONAL: 3,
    FindingStatus.REJECTED: 4,
}
_EVIDENCE_SIMILARITY = 0.60
_LINE_TOLERANCE = 5


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

    # 2) LLM findings: attach to overlapping tool findings, or keep standalone
    standalone: list[Finding] = []
    for f in llm_findings:
        host = _find_host(f, tool_list)
        if host is not None:
            _absorb_into(host, f, cross=True)
        else:
            standalone.append(f)

    # 3) LLM-vs-LLM duplicates by normalized title+location (highest-ranked
    #    status survives as primary)
    deduped: dict[tuple, Finding] = {}
    for f in standalone:
        llm_key = ("llm", *_loc(f), _norm(f.title)[:120])
        if llm_key in deduped:
            pair = sorted((deduped[llm_key], f), key=lambda x: _STATUS_ORDER.get(x.status, 99))
            deduped[llm_key] = _absorb(pair[0], pair[1])
        else:
            deduped[llm_key] = f

    out = tool_list + list(deduped.values())
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
    compiler_version: str = "",
    analyzed_files: Sequence[str] = (),
    invariant_checks: Sequence[dict[str, Any]] = (),
    attack_paths: Sequence[dict[str, Any]] = (),
    targeted_test_results: Sequence[dict[str, Any]] = (),
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
    )
    report.summary.static_analysis_status = static_analysis_status
    return report
