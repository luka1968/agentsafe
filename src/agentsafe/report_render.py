"""Customer-facing report rendering (Section 8).

Single source of truth: machine JSON, HTML and PDF are all rendered from the
SAME validated AuditReport model. Findings are never recomputed, re-counted
or re-interpreted per format, so the three views cannot disagree.

Honesty rules enforced here (spec Section 8):
- NEVER "Security Audit Passed" / "Contract Safe", regardless of findings.
- The supported positive statement is exactly "No confirmed vulnerabilities
  identified within the completed analysis scope", and only when the
  analysis actually supports it (verified source + static tools ran + LLM
  analysis ran).
- Confirmed and unconfirmed findings are never merged into one severity
  count: confirmed / potential / informational are reported separately.
- No credentials, tokens, infrastructure internals or environment details
  are ever rendered: this module reads ONLY the sanitized AuditReport.
- Every page states that AI-assisted screening is not a formal audit.
"""

from __future__ import annotations

import html
import io
from datetime import UTC, datetime

from agentsafe import REPORT_DISCLAIMER
from agentsafe.schemas import AuditReport, Finding, FindingStatus


class ReportRenderError(RuntimeError):
    """Raised when the requested rendering format is unavailable (e.g. the
    optional PDF dependency is not installed). Never affects audit execution."""


_STATUS_LABELS = {
    "confirmed": "Confirmed",
    "potential": "Potential",
    "informational": "Informational",
    "needs_manual_review": "Needs manual review",
    "rejected": "Rejected (excluded)",
}

_SEVERITY_CLASS = {
    "critical": "sev-critical",
    "high": "sev-high",
    "medium": "sev-medium",
    "low": "sev-low",
    "info": "sev-info",
}

_NO_CONFIRMED_PHRASE = (
    "No confirmed vulnerabilities identified within the completed analysis scope"
)


def overall_status(report: AuditReport) -> dict[str, str]:
    """Overall assessment wording, derived only from validated report data."""
    counts = report.summary.by_status
    if counts.get("confirmed", 0) > 0:
        return {"label": "Confirmed vulnerabilities identified", "tone": "critical"}
    if counts.get("potential", 0) > 0 or counts.get("needs_manual_review", 0) > 0:
        return {
            "label": "Potential issues identified - manual review required",
            "tone": "warning",
        }
    analysis_supported = (
        report.is_verified_source
        and report.summary.static_analysis_status in ("full", "partial")
        and (report.llm_usage.total_calls or 0) > 0
    )
    if analysis_supported:
        return {"label": _NO_CONFIRMED_PHRASE, "tone": "clear"}
    return {"label": "Analysis incomplete - see limitations", "tone": "warning"}


def _esc(text: object) -> str:
    return html.escape(str(text), quote=True)


def _location(f: Finding) -> str:
    """Human-readable location string. When the location could not be
    verified it says so explicitly instead of silently asserting precision."""
    if f.file_path and f.line_start:
        rng = f"-{f.line_end}" if f.line_end and f.line_end > f.line_start else ""
        loc = f"{f.file_path}:{f.line_start}{rng}"
        if f.location_status == "unverified":
            loc += " (unverified)"
        return loc
    return "location unavailable"


def _swc_link(f: Finding) -> str | None:
    if not f.swc_id or not f.swc_id.upper().startswith("SWC-"):
        return None
    num = f.swc_id.split("-", 1)[1]
    return f"https://swcregistry.io/docs/SWC-{num}"


def _fmt_ts(ts: datetime) -> str:
    return ts.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


_CSS = """
:root{--ink:#111827;--muted:#6b7280;--line:#e5e7eb;--bg:#f8fafc;--card:#fff;
--critical:#b91c1c;--high:#c2410c;--medium:#a16207;--low:#1d4ed8;--info:#475569;
--clear:#15803d}
*{box-sizing:border-box}body{font:15px/1.55 -apple-system,'Segoe UI',Roboto,Arial,
sans-serif;color:var(--ink);background:var(--bg);margin:0}
.page{max-width:960px;margin:0 auto;padding:32px 24px}
.cover{background:linear-gradient(160deg,#0f172a,#1e3a8a);color:#fff;border-radius:14px;
padding:48px 40px;margin-bottom:28px}
.cover h1{margin:8px 0 4px;font-size:30px;letter-spacing:.3px}
.cover .tag{opacity:.75;font-size:14px}
.cover table{margin-top:26px;border-collapse:collapse;width:100%}
.cover td{padding:7px 0;vertical-align:top}
.cover td.k{opacity:.65;width:190px;font-size:13px;text-transform:uppercase;letter-spacing:.8px}
.badge{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12.5px;font-weight:600}
.tone-critical{background:#fef2f2;color:var(--critical);border:1px solid #fecaca}
.tone-warning{background:#fffbeb;color:var(--medium);border:1px solid #fde68a}
.tone-clear{background:#f0fdf4;color:var(--clear);border:1px solid #bbf7d0}
.sev-critical{background:#fef2f2;color:var(--critical)}
.sev-high{background:#fff7ed;color:var(--high)}
.sev-medium{background:#fefce8;color:var(--medium)}
.sev-low{background:#eff6ff;color:var(--low)}
.sev-info{background:#f1f5f9;color:var(--info)}
h2{font-size:19px;margin:34px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:16px 20px;margin:10px 0}
.stats{display:flex;flex-wrap:wrap;gap:12px;margin:12px 0}
.stat{flex:1 1 130px;background:var(--card);border:1px solid var(--line);
border-radius:10px;padding:14px}
.stat .n{font-size:26px;font-weight:700}.stat .l{color:var(--muted);font-size:12.5px}
table.data{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);
font-size:14px}table.data th{background:#f1f5f9;text-align:left;padding:9px 12px;font-size:12.5px;
text-transform:uppercase;letter-spacing:.5px;color:var(--muted)}
table.data td{padding:9px 12px;border-top:1px solid var(--line)}
pre.code{background:#0f172a;color:#e2e8f0;padding:14px;border-radius:8px;overflow-x:auto;
font:12.5px/1.5 ui-monospace,Consolas,monospace;white-space:pre-wrap}
ul{margin:6px 0;padding-left:22px}li{margin:3px 0}
.finding{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:18px 22px;margin:16px 0}
.finding h3{margin:0 0 6px;font-size:16.5px}
.f-meta{color:var(--muted);font-size:13px;margin-bottom:10px}
.dl div{margin:7px 0}.dl b{display:inline-block;min-width:150px;vertical-align:top}
footer{margin-top:40px;padding:18px;border-top:1px solid var(--line);
color:var(--muted);font-size:13px}
.brand{display:flex;align-items:center;gap:10px}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:13px}
"""

_BRAND_SVG = (
    '<svg width="30" height="30" viewBox="0 0 24 24" fill="none" aria-hidden="true">'
    '<path d="M12 2L4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z" '
    'fill="#60a5fa" fill-opacity=".25" stroke="#60a5fa" stroke-width="1.6"/>'
    '<path d="M8.5 12l2.4 2.4L15.7 9.6" stroke="#93c5fd" stroke-width="1.8" '
    'stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>'
)


def render_html(report: AuditReport) -> str:
    """Render the customer-facing HTML assessment report from validated data."""
    s = report.summary
    status = overall_status(report)
    counts = s.by_status
    confirmed = counts.get("confirmed", 0)
    potential = counts.get("potential", 0)
    info = counts.get("informational", 0)
    manual = counts.get("needs_manual_review", 0)
    rejected = counts.get("rejected", 0)

    parts: list[str] = []
    parts.append(
        '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>agentSAFE - Security Assessment {_esc(report.address)}</title>\n"
        f"<style>{_CSS}</style>\n</head>\n<body>\n<div class=\"page\">"
    )

    # ---- cover page ----
    parts.append(
        f'<header class="cover"><div class="brand">{_BRAND_SVG}'
        '<span style="font-size:18px;font-weight:700;letter-spacing:.5px">agent'
        '<span style="color:#93c5fd">SAFE</span></span></div>'
        "<h1>Smart Contract Security Assessment</h1>"
        '<div class="tag">AI-assisted risk screening with deterministic '
        "evidence validation - not a formal human audit</div>"
        "<table>"
        f"<tr><td class='k'>Contract address</td><td class='mono'>{_esc(report.address)}</td></tr>"
        f"<tr><td class='k'>Blockchain network</td><td>{_esc(report.chain.replace('-', ' ').title())}</td></tr>"  # noqa: E501
        f"<tr><td class='k'>Assessment date</td><td>{_esc(_fmt_ts(report.timestamp))}</td></tr>"
        f"<tr><td class='k'>Report ID</td><td class='mono'>{_esc(report.report_id or report.task_id or 'n/a')}</td></tr>"  # noqa: E501
        "<tr><td class='k'>Assessment status</td><td>"
        f"<span class='badge tone-{_esc(status['tone'])}'>{_esc(status['label'])}</span>"
        "</td></tr></table></header>"
    )

    # ---- executive summary ----
    parts.append("<h2>1. Executive summary</h2>")
    parts.append(
        f"<p><span class='badge tone-{_esc(status['tone'])}'>{_esc(status['label'])}</span></p>"
    )
    parts.append(
        '<div class="stats">'
        f'<div class="stat"><div class="n" style="color:var(--critical)">{confirmed}</div>'
        '<div class="l">Confirmed vulnerabilities</div></div>'
        f'<div class="stat"><div class="n" style="color:var(--high)">{potential}</div>'
        '<div class="l">Potential findings</div></div>'
        f'<div class="stat"><div class="n" style="color:var(--low)">{info}</div>'
        '<div class="l">Informational findings</div></div>'
        f'<div class="stat"><div class="n" style="color:var(--muted)">{manual}</div>'
        '<div class="l">Needs manual review</div></div>'
        "</div>"
    )
    parts.append(
        f"<p class='f-meta'>Rejected/duplicate findings retained for audit "
        f"traceability: {rejected} (excluded from all counts above). "
        "Severity counts never mix confirmed and unconfirmed findings.</p>"
    )
    if s.tools_failed:
        parts.append(
            "<div class='card'><b>Tool failures</b><ul>"
            + "".join(f"<li>{_esc(t)}</li>" for t in s.tools_failed)
            + "</ul>Failed tools contribute nothing to these counts; their "
            "missing output is not evidence of safety.</div>"
        )
    if report.limitations:
        parts.append(
            "<div class='card'><b>Important limitations</b><ul>"
            + "".join(f"<li>{_esc(lim)}</li>" for lim in report.limitations)
            + "</ul></div>"
        )

    # ---- scope and methodology ----
    files = report.analyzed_files or []
    parts.append("<h2>2. Scope and methodology</h2><div class='card'><dl class='dl'>")
    parts.append(
        "<div><b>Verified source</b> "
        f"{_esc('Yes' if report.is_verified_source else 'No - closed-source bytecode path')}</div>"
    )
    if files:
        parts.append(
            "<div><b>Analyzed files</b><ul>"
            + "".join(f"<li class='mono'>{_esc(p)}</li>" for p in files)
            + "</ul></div>"
        )
    else:
        parts.append("<div><b>Analyzed files</b> not recorded</div>")
    parts.append(
        f"<div><b>Compiler version</b> {_esc(report.compiler_version or 'not recorded')}</div>"
    )
    parts.append(
        f"<div><b>Tools executed</b> {_esc(', '.join(s.tools_executed) or 'none')}</div>"
    )
    parts.append(
        f"<div><b>Tools failed</b> {_esc(', '.join(s.tools_failed) or 'none')}</div>"
    )
    parts.append(
        f"<div><b>Static analysis</b> {_esc(s.static_analysis_status)}</div>"
    )
    usage = report.llm_usage
    parts.append(
        f"<div><b>LLM analysis</b> {_esc(usage.total_calls or 0)} call(s), "
        f"{_esc(usage.failed_calls or 0)} failed; providers: "
        f"{_esc(', '.join(usage.providers_used) or 'n/a')}</div>"
    )
    parts.append(
        "<div><b>Coverage</b> every finding passed deterministic validation "
        "gates; untraceable claims are downgraded for manual review, never "
        "presented as fact.</div></dl></div>"
    )

    # ---- findings overview ----
    parts.append("<h2>3. Findings overview</h2>")
    if report.findings:
        rows = []
        for f in report.findings:
            rows.append(
                "<tr>"
                f"<td class='mono'>{_esc(f.finding_id)}</td>"
                f"<td>{_esc(f.title)}</td>"
                "<td><span class='badge "
                f"{_SEVERITY_CLASS.get(f.severity.value, 'sev-info')}'>"
                f"{_esc(f.severity.value)}</span></td>"
                f"<td>{_esc(_STATUS_LABELS.get(f.status.value, f.status.value))}</td>"
                f"<td class='mono'>{_esc(_location(f))}</td>"
                "</tr>"
            )
        parts.append(
            "<table class='data'><tr><th>Finding ID</th><th>Title</th>"
            "<th>Severity</th><th>Validation status</th>"
            "<th>Affected location</th></tr>" + "".join(rows) + "</table>"
        )
    else:
        parts.append(
            "<div class='card'>No candidate findings were produced by the "
            "completed analysis scope. This is not a security guarantee.</div>"
        )

    # ---- detailed findings ----
    parts.append("<h2>4. Detailed findings</h2>")
    actionable = [f for f in report.findings if f.status is not FindingStatus.REJECTED]
    if not actionable:
        parts.append(
            "<div class='card'>No actionable findings. Rejected candidates are "
            "listed in the appendix with the deterministic rule that refuted them.</div>"
        )
    for f in actionable:
        v = f.metadata.get("validation", {}) if isinstance(f.metadata, dict) else {}
        refs = []
        swc_link = _swc_link(f)
        if swc_link:
            refs.append(f"<a href='{_esc(swc_link)}'>{_esc(f.swc_id)} (SWC registry)</a>")
        if "slither" in f.source:
            refs.append(
                "<a href='https://github.com/crytic/slither/wiki/Detector-Documentation'>"
                "Slither detector documentation</a>"
            )
        prop_note = ""
        if f.proposed_severity is not None and f.proposed_severity is not f.severity:
            prop_note = (
                f" Original claim was {_esc(f.proposed_severity.value)}, "
                "preserved per the severity rubric."
            )
        parts.append(
            f"<div class='finding'><h3>{_esc(f.title)}</h3>"
            f"<div class='f-meta mono'>{_esc(f.finding_id)} · "
            "<span class='badge "
            f"{_SEVERITY_CLASS.get(f.severity.value, 'sev-info')}'>"
            f"{_esc(f.severity.value)}</span> · "
            f"{_esc(_STATUS_LABELS.get(f.status.value, f.status.value))} · "
            f"{_esc(_location(f))}</div>"
            + (
                f"<div><b>Category</b> {_esc(f.category.value)}</div>"
                if f.category is not None else ""
            )
            + (
                "<div><b>Affected functions</b> "
                + ", ".join(f"<span class='mono'>{_esc(x)}</span>" for x in f.affected_functions)
                + "</div>"
                if f.affected_functions else ""
            )
            + (
                f"<div><b>Validation</b> method: {_esc(f.validation_method or 'n/a')} · "
                f"result: {_esc(f.validation_result or f.status.value)}</div>"
            )
            + "<div class='dl'>"
            f"<div><b>Description</b> {_esc(f.description)}</div>"
            + (f"<div><b>Affected code</b></div><pre class='code'>{_esc(f.evidence)}</pre>" if f.evidence else "")  # noqa: E501
            + (
                "<div><b>Corroborating evidence</b><ul>"
                + "".join(f"<li class='mono'>{_esc(r)}</li>" for r in f.supporting_evidence)
                + "</ul></div>"
                if f.supporting_evidence
                else ""
            )
            + (
                "<div><b>Contradicting evidence</b><ul>"
                + "".join(f"<li class='mono'>{_esc(r)}</li>" for r in f.contradicting_evidence)
                + "</ul></div>"
                if f.contradicting_evidence
                else ""
            )
            + (
                "<div><b>Knowledge references (context only, not proof)</b><ul>"
                + "".join(f"<li class='mono'>{_esc(r)}</li>" for r in f.knowledge_references)
                + "</ul></div>"
                if f.knowledge_references
                else ""
            )
            + (
                "<div><b>Knowledge references (context only, not proof)</b><ul>"
                + "".join(
                    "<li>"
                    f"<b>{_esc(kr.title or kr.knowledge_id or 'reference')}</b> "
                    f"<span class='mono'>(source: {_esc(kr.source_name or 'n/a')})</span> "
                    f"<span class='mono'>({_esc(kr.knowledge_id or 'no-id')})</span> "
                    f"<span class='mono'>{_esc(kr.relevance_reason or '')}</span>"
                    "</li>"
                    for kr in f.knowledge_reference_details
                )
                + "</ul></div>"
                if f.knowledge_reference_details
                else ""
            )
            + (f"<div><b>Preconditions</b> {_esc(f.preconditions)}</div>" if f.preconditions else "")  # noqa: E501
            + (f"<div><b>Attack scenario</b> {_esc(f.attack_scenario)}</div>" if f.attack_scenario else "")  # noqa: E501
            + (f"<div><b>Impact</b> {_esc(f.impact)}</div>" if f.impact else "")
            + (
                "<div><b>Severity rationale</b> assessed from exploit prerequisites "
                f"({_esc(v.get('severity_basis', 'documented rubric'))}).{_esc(prop_note) if prop_note else ''}</div>"  # noqa: E501
            )
            + (f"<div><b>Recommended fix</b> {_esc(f.recommendation)}</div>" if f.recommendation else "")  # noqa: E501
            + (f"<div><b>References</b> {' · '.join(refs)}</div>" if refs else "")
            + "</div></div>"
        )

    # ---- appendix ----
    parts.append("<h2>5. Appendix</h2>")
    parts.append("<div class='card'><b>Tool versions</b><ul>")
    if report.tool_versions:
        parts.append(
            "".join(
                f"<li class='mono'>{_esc(k)}: {_esc(v)}</li>"
                for k, v in sorted(report.tool_versions.items())
            )
        )
    else:
        parts.append("<li>not recorded</li>")
    parts.append("</ul></div>")
    if report.tool_executions:
        rows = "".join(
            f"<tr><td class='mono'>{_esc(t.tool)}</td><td>{_esc(t.kind)}</td>"
            f"<td>{_esc('yes' if t.executed else 'no')}</td>"
            f"<td>{_esc(t.failure_category or '-')}</td>"
            f"<td>{_esc(t.duration_seconds if t.duration_seconds is not None else '-')}</td>"
            f"<td>{_esc(t.exit_code if t.exit_code is not None else '-')}</td></tr>"
            for t in report.tool_executions
        )
        parts.append(
            "<table class='data'><tr><th>Tool</th><th>Kind</th><th>Executed</th>"
            "<th>Failure category</th><th>Duration (s)</th><th>Exit code</th></tr>"
            + rows
            + "</table>"
        )
    parts.append(
        "<div class='card'><b>Execution metadata</b>"
        f"<div>Report ID: <span class='mono'>{_esc(report.report_id or 'n/a')}</span></div>"
        f"<div>Task ID: <span class='mono'>{_esc(report.task_id or 'n/a')}</span></div>"
        f"<div>Assessment date: {_esc(_fmt_ts(report.timestamp))}</div>"
        "<div>Total execution time: "
        f"{_esc(report.execution_time_seconds if report.execution_time_seconds is not None else 'n/a')}s</div>"  # noqa: E501
        "<div>Analysis pipeline: static + bytecode analysis, bounded multi-agent "
        "LLM screening, deterministic cross-validation, evidence-based severity "
        "assessment (documented rubric)</div></div>"
    )
    if report.errors:
        parts.append(
            "<div class='card'><b>Errors recorded during analysis</b><ul>"
            + "".join(f"<li>{_esc(e)}</li>" for e in report.errors)
            + "</ul></div>"
        )
    rejected_findings = [f for f in report.findings if f.status is FindingStatus.REJECTED]
    if rejected_findings:
        parts.append(
            "<div class='card'><b>Rejected findings (excluded from counts, "
            "retained for auditability)</b><ul>"
            + "".join(
                f"<li><span class='mono'>{_esc(f.finding_id)}</span> {_esc(f.title)} "
                "— refuted by "
                f"{_esc((f.metadata.get('validation', {}) or {}).get('rule', 'deterministic validation'))}</li>"  # noqa: E501
                for f in rejected_findings
            )
            + "</ul></div>"
        )
    parts.append(
        "<div class='card'><b>Known limitations</b><ul>"
        "<li>Automated AI-assisted screening is NOT equivalent to a formal "
        "human security audit.</li>"
        "<li>Unvalidated claims are capped at medium severity; their original "
        "claims are preserved in proposed_severity for review.</li>"
        "<li>Closed-source bytecode analysis is inherently limited; decompiled "
        "pseudo-source line numbers are approximate.</li>"
        "<li>Economic and novel attack vectors outside the analyzed patterns "
        "may exist.</li>"
        "</ul></div>"
    )
    parts.append(f"<footer>{_esc(REPORT_DISCLAIMER)}</footer>")
    parts.append("</div></body></html>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# PDF export (Section 8): OPTIONAL dependency, never required by the core
# audit execution. reportlab is imported lazily inside render_pdf only.
# ---------------------------------------------------------------------------


def render_markdown(report: AuditReport) -> str:
    """Markdown rendering from the SAME validated report data as HTML/PDF.
    All formats agree on findings, severity, validation status, and
    limitations by construction — they share one AuditReport instance."""
    parts: list[str] = []
    parts.append(f"# agentSAFE Audit Report — {_esc(report.address)}")
    parts.append("")
    parts.append(f"- Report ID: `{_esc(report.report_id or 'n/a')}`")
    parts.append(f"- Task ID: `{_esc(report.task_id or 'n/a')}`")
    parts.append(f"- Assessment date: {_esc(_fmt_ts(report.timestamp))}")
    parts.append(f"- Verified source: {'yes' if report.is_verified_source else 'no'}")
    parts.append(f"- Execution time: {_esc(report.execution_time_seconds if report.execution_time_seconds is not None else 'n/a')}s")
    parts.append("")

    # summary
    parts.append("## Summary")
    parts.append("")
    parts.append(f"Total findings: {report.summary.total_findings}")
    sev = report.summary.by_severity or {}
    st = report.summary.by_status or {}
    if sev:
        parts.append(f"By severity: {', '.join(f'{k}={v}' for k, v in sorted(sev.items()))}")
    if st:
        parts.append(f"By status: {', '.join(f'{k}={v}' for k, v in sorted(st.items()))}")
    parts.append(f"Tools executed: {', '.join(report.summary.tools_executed) or 'none'}")
    parts.append(f"Static analysis status: {report.summary.static_analysis_status}")
    parts.append("")

    # findings
    parts.append("## Findings")
    parts.append("")
    actionable = [f for f in report.findings if f.status is not FindingStatus.REJECTED]
    if not actionable:
        parts.append(
            "No actionable findings. Rejected candidates are listed in the "
            "appendix with the deterministic rule that refuted them.")
    for f in actionable:
        v = f.metadata.get("validation", {}) if isinstance(f.metadata, dict) else {}
        parts.append(f"### {f.finding_id}: {_esc(f.title)}")
        parts.append("")
        parts.append(f"- **Severity**: `{_esc(f.severity.value)}`")
        parts.append(f"- **Status**: `{_esc(_STATUS_LABELS.get(f.status.value, f.status.value))}`")
        loc = _location(f)
        if loc:
            parts.append(f"- **Location**: `{_esc(loc)}`")
        if f.category is not None:
            parts.append(f"- **Category**: `{_esc(f.category.value)}`")
        parts.append(f"- **Validation method**: `{_esc(f.validation_method or 'not recorded')}`")
        parts.append(f"- **Validation result**: `{_esc(f.validation_result or f.status.value)}`")
        parts.append("")
        parts.append(f"**Description:** {_esc(f.description)}")
        if f.affected_functions:
            parts.append("")
            parts.append(f"**Affected functions:** {', '.join(f'`{_esc(x)}`' for x in f.affected_functions)}")
        if f.preconditions:
            parts.append("")
            parts.append(f"**Preconditions:** {_esc(f.preconditions)}")
        if f.attack_scenario:
            parts.append("")
            parts.append(f"**Attack scenario:** {_esc(f.attack_scenario)}")
        if f.evidence:
            parts.append("")
            parts.append("**Affected code:**")
            parts.append("")
            parts.append("```solidity")
            parts.append(_esc(f.evidence))
            parts.append("```")
        if f.supporting_evidence:
            parts.append("")
            parts.append("**Corroborating evidence:**")
            parts.append("".join(f"- `{_esc(r)}`\n" for r in f.supporting_evidence))
        if f.contradicting_evidence:
            parts.append("")
            parts.append("**Contradicting evidence:**")
            parts.append("".join(f"- `{_esc(r)}`\n" for r in f.contradicting_evidence))
        if f.knowledge_reference_details:
            parts.append("")
            parts.append("**Knowledge references (context only, not proof):**")
            for kr in f.knowledge_reference_details:
                parts.append(
                    f"- {_esc(kr.title or kr.knowledge_id or 'reference')} "
                    f"(source: {_esc(kr.source_name or 'n/a')}, "
                    f"{_esc(kr.relevance_reason or 'relevance not stated')})")
        elif f.knowledge_references:
            parts.append("")
            parts.append("**Knowledge references (context only, not proof):**")
            parts.append("".join(f"- `{_esc(r)}`\n" for r in f.knowledge_references))
        if f.impact:
            parts.append("")
            parts.append(f"**Impact:** {_esc(f.impact)}")
        if f.recommendation:
            parts.append("")
            parts.append(f"**Recommended fix:** {_esc(f.recommendation)}")
        if f.limitations:
            parts.append("")
            parts.append("**Limitations:**")
            parts.append("".join(f"- {_esc(x)}\n" for x in f.limitations))
        parts.append("")
        parts.append("---")
        parts.append("")

    # rejected appendix
    rejected = [f for f in report.findings if f.status is FindingStatus.REJECTED]
    if rejected:
        parts.append("## Appendix: Rejected findings (auditability)")
        parts.append("")
        for f in rejected:
            rule = (f.metadata.get("validation", {}) or {}).get("rule", "deterministic validation")
            parts.append(f"- `{_esc(f.finding_id)}` {_esc(f.title)} — refuted by `{_esc(rule)}`")
        parts.append("")

    # limitations
    parts.append("## Known limitations")
    parts.append("")
    for lim in report.limitations:
        parts.append(f"- {_esc(lim)}")
    parts.append("")
    parts.append(f"> {_esc(report.disclaimer)}")
    parts.append("")
    return "\n".join(parts)


def render_pdf(report: AuditReport) -> bytes:
    """Render the customer-facing PDF from the same validated report data.
    Requires the optional ``reportlab`` package; raises ReportRenderError
    when unavailable - audit execution never depends on this."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise ReportRenderError(
            "PDF export requires the optional 'reportlab' package "
            "(pip install reportlab)"
        ) from exc

    s = report.summary
    status = overall_status(report)
    counts = s.by_status
    styles = getSampleStyleSheet()
    title_st = ParagraphStyle(
        "t", parent=styles["Title"], fontSize=24, textColor=colors.HexColor("#0f172a")
    )
    h2 = ParagraphStyle(
        "h2", parent=styles["Heading2"], textColor=colors.HexColor("#0f172a"), spaceBefore=14
    )
    h3 = ParagraphStyle("h3", parent=styles["Heading3"], spaceBefore=10)
    body = styles["BodyText"]
    small = ParagraphStyle("sm", parent=body, fontSize=9, textColor=colors.HexColor("#475569"))
    mono = ParagraphStyle("mono", parent=body, fontName="Courier", fontSize=8.5)
    tone_color = {
        "critical": colors.HexColor("#b91c1c"),
        "warning": colors.HexColor("#a16207"),
        "clear": colors.HexColor("#15803d"),
    }[status["tone"]]

    def _p(text: str, style=body) -> Paragraph:
        return Paragraph(_esc(text), style)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        title=f"agentSAFE Security Assessment {report.address}",
        author="agentSAFE",
        subject="Smart Contract Security Assessment",
    )
    story: list = []

    # cover page
    story.append(Spacer(1, 45 * mm))
    story.append(Paragraph("agentSAFE", title_st))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Smart Contract Security Assessment", styles["Heading2"]))
    story.append(Spacer(1, 3 * mm))
    story.append(
        Paragraph(
            "AI-assisted risk screening with deterministic evidence validation"
            " - not a formal human audit",
            ParagraphStyle("tag", parent=small, alignment=TA_CENTER),
        )
    )
    story.append(Spacer(1, 12 * mm))
    cover_tbl = Table(
        [
            ["Contract address", _esc(report.address)],
            ["Blockchain network", _esc(report.chain.replace("-", " ").title())],
            ["Assessment date", _esc(_fmt_ts(report.timestamp))],
            ["Report ID", _esc(report.report_id or report.task_id or "n/a")],
            ["Assessment status", _esc(status["label"])],
        ],
        colWidths=[52 * mm, 105 * mm],
    )
    cover_tbl.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#6b7280")),
                ("TEXTCOLOR", (1, 4), (1, 4), tone_color),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(cover_tbl)
    story.append(PageBreak())

    # executive summary
    story.append(Paragraph("1. Executive summary", h2))
    story.append(
        Paragraph(_esc(status["label"]), ParagraphStyle("st2", parent=body, textColor=tone_color))
    )
    story.append(
        _p(
            f"Confirmed vulnerabilities: {counts.get('confirmed', 0)} | "
            f"Potential findings: {counts.get('potential', 0)} | "
            f"Informational: {counts.get('informational', 0)} | "
            f"Needs manual review: {counts.get('needs_manual_review', 0)} | "
            f"Rejected (excluded from counts): {counts.get('rejected', 0)}"
        )
    )
    if s.tools_failed:
        story.append(
            _p("Tool failures: " + ", ".join(s.tools_failed), small)
        )
        story.append(
            _p(
                "Failed tools contribute nothing to these counts; their missing "
                "output is not evidence of safety.",
                small,
            )
        )
    for lim in report.limitations:
        story.append(_p(f"Limitation: {lim}", small))

    # scope & methodology
    story.append(Paragraph("2. Scope and methodology", h2))
    story.append(_p(f"Verified source: {'Yes' if report.is_verified_source else 'No'}"))
    story.append(_p(f"Compiler version: {report.compiler_version or 'not recorded'}"))
    story.append(_p(f"Tools executed: {', '.join(s.tools_executed) or 'none'}"))
    story.append(_p(f"Tools failed: {', '.join(s.tools_failed) or 'none'}"))
    story.append(_p(f"Static analysis status: {s.static_analysis_status}"))
    story.append(
        _p(
            f"LLM analysis: {report.llm_usage.total_calls or 0} call(s), "
            f"{report.llm_usage.failed_calls or 0} failed"
        )
    )
    for p in report.analyzed_files or []:
        story.append(_p(f"Analyzed file: {p}", small))

    # findings overview
    story.append(Paragraph("3. Findings overview", h2))
    if report.findings:
        rows = [["Finding ID", "Title", "Severity", "Status", "Location"]]
        for f in report.findings:
            rows.append(
                [
                    _esc(f.finding_id),
                    _esc(f.title[:70]),
                    _esc(f.severity.value),
                    _esc(_STATUS_LABELS.get(f.status.value, f.status.value)),
                    _esc(_location(f))[:55],
                ]
            )
        tbl = Table(rows, colWidths=[25 * mm, 55 * mm, 16 * mm, 32 * mm, 42 * mm], repeatRows=1)
        tbl.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(tbl)
    else:
        story.append(
            _p(
                "No candidate findings were produced by the completed analysis "
                "scope. This is not a security guarantee."
            )
        )

    # detailed findings
    story.append(Paragraph("4. Detailed findings", h2))
    actionable = [f for f in report.findings if f.status is not FindingStatus.REJECTED]
    if not actionable:
        story.append(
            _p(
                "No actionable findings. Rejected candidates are listed in the "
                "appendix with the deterministic rule that refuted them."
            )
        )
    for f in actionable:
        v = f.metadata.get("validation", {}) if isinstance(f.metadata, dict) else {}
        story.append(Paragraph(_esc(f"{f.title}  [{f.severity.value}]"), h3))
        story.append(_p(f"{f.finding_id} - {f.status.value} - {_location(f)}", small))
        story.append(_p(f"Description: {f.description}"))
        if f.evidence:
            story.append(_p("Affected code:", small))
            story.append(Paragraph(_esc(f.evidence), mono))
        if f.preconditions:
            story.append(_p(f"Preconditions: {f.preconditions}"))
        if f.attack_scenario:
            story.append(_p(f"Attack scenario: {f.attack_scenario}"))
        if f.impact:
            story.append(_p(f"Impact: {f.impact}"))
        rationale = (
            "Severity rationale: assessed from exploit prerequisites "
            f"({_esc(v.get('severity_basis', 'documented rubric'))})."
        )
        if f.proposed_severity is not None and f.proposed_severity is not f.severity:
            rationale += (
                f" Original claim {f.proposed_severity.value} preserved per the rubric."
            )
        story.append(_p(rationale, small))
        if f.recommendation:
            story.append(_p(f"Recommended fix: {f.recommendation}"))
        if f.swc_id:
            story.append(_p(f"Reference: {f.swc_id} (SWC registry, swcregistry.io)", small))
        story.append(Spacer(1, 4 * mm))

    # appendix
    story.append(Paragraph("5. Appendix", h2))
    for k, val in sorted((report.tool_versions or {}).items()):
        story.append(_p(f"{k}: {val}", small))
    story.append(
        _p(
            f"Report ID: {report.report_id or 'n/a'} | "
            f"Task ID: {report.task_id or 'n/a'} | "
            f"Execution time: "
            f"{report.execution_time_seconds if report.execution_time_seconds is not None else 'n/a'}s",  # noqa: E501
            small,
        )
    )
    for e in report.errors:
        story.append(_p(f"Error: {e}", small))
    for rej in [f for f in report.findings if f.status is FindingStatus.REJECTED]:
        v = rej.metadata.get("validation", {}) if isinstance(rej.metadata, dict) else {}
        story.append(
            _p(
                f"Rejected: {rej.finding_id} \"{rej.title}\" - refuted by "
                f"{v.get('rule', 'deterministic validation')}",
                small,
            )
        )
    story.append(Spacer(1, 3 * mm))
    story.append(
        _p(
            "Known limitations: automated AI-assisted screening is NOT a formal "
            "human security audit; unvalidated claims are capped at medium "
            "severity; closed-source bytecode analysis and decompiled "
            "pseudo-source are inherently approximate; economic and novel "
            "attack vectors outside the analyzed patterns may exist.",
            small,
        )
    )
    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph(_esc(REPORT_DISCLAIMER), small))

    doc.build(story)
    return buf.getvalue()
