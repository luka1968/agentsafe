"""Section 13 — report integrity and customer trust.

The final report must make the audit's ACTUAL quality transparent: what was
received vs analyzed, coverage, engine/agent execution, what was skipped, and
the difference between what was verified and what is merely suspected.

This module builds one consolidated, deterministic panel from data the pipeline
already produced. It never claims full coverage when analysis was partial, never
claims all tests passed when some were not executed, and never claims a
vulnerability was reproduced when only an LLM proposed it.
"""

from __future__ import annotations

from typing import Any

__all__ = ["build_integrity"]

_EXECUTED_RESULTS = frozenset({"passed", "failed", "error"})
_REPRODUCED_POC = frozenset({"successful_exploitation"})


def _md(f: Any, *path: str) -> Any:
    cur = getattr(f, "metadata", None) or {}
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def build_integrity(
    report: Any,
    *,
    scheduler_meta: dict[str, Any] | None = None,
    tools_attempted: Any = (),
    received_files: Any = (),
) -> dict[str, Any]:
    summary = report.summary
    coverage = getattr(report, "coverage", {}) or {}
    findings = list(getattr(report, "findings", []) or [])

    per_agent = list((scheduler_meta or {}).get("per_agent", []) or [])
    specialists = [
        {
            "agent": a.get("agent"),
            "ran": bool(a.get("ran", True)),
            "findings": int(a.get("findings", 0) or 0),
            "llm_calls": int(a.get("llm_calls", 0) or 0),
            "skipped": a.get("skipped"),
            "errors": list(a.get("errors", []) or []),
        }
        for a in per_agent
    ]
    failed_agents = [s["agent"] for s in specialists if s["errors"]]
    skipped_agents = [s["agent"] for s in specialists if s["skipped"]]

    tests = list(getattr(report, "targeted_test_results", []) or [])
    executed_tests = [
        t for t in tests if str(t.get("result")) in _EXECUTED_RESULTS
    ]
    if not tests:
        dynamic_status = "not_run"
    elif not executed_tests:
        dynamic_status = "not_executed"
    else:
        dynamic_status = "executed"
    all_passed: Any
    if not executed_tests:
        all_passed = "none_executed"
    else:
        all_passed = all(
            str(t.get("result")) == "passed" for t in executed_tests
        )

    poc_attempted = poc_executed = poc_env = poc_reproduced = 0
    for f in findings:
        poc = _md(f, "poc") or {}
        if isinstance(poc, dict) and poc.get("status"):
            poc_attempted += 1
            if poc.get("status") in _REPRODUCED_POC:
                poc_reproduced += 1
            if poc.get("status") == "environment_limitation":
                poc_env += 1
            if poc.get("executed"):
                poc_executed += 1

    # A vulnerability is "reproduced" ONLY by an executed test / PoC that
    # demonstrated impact — never by an LLM hypothesis.
    reproduced_findings = sum(
        1 for f in findings
        if (_md(f, "poc") or {}).get("status") in _REPRODUCED_POC
    ) + sum(1 for t in tests if t.get("reproduced") is True)

    analyzed = list(getattr(report, "analyzed_files", []) or [])
    full_coverage = bool(coverage.get("is_complete", False)) and (
        summary.audit_state == "complete"
    )

    return {
        "audit_state": summary.audit_state,
        "verified_vs_suspected": {
            "confirmed": summary.by_status.get("confirmed", 0),
            "high_confidence": summary.by_status.get("high_confidence", 0),
            "potential_suspected": summary.by_status.get("potential", 0),
            "informational": summary.by_status.get("informational", 0),
            "rejected": summary.by_status.get("rejected", 0),
            "unverified": summary.by_status.get("unverified", 0),
            "needs_manual_review": summary.by_status.get("needs_manual_review", 0),
        },
        "source_files_received": list(received_files),
        "source_files_analyzed": analyzed,
        "functions_total": int(coverage.get("total_functions", 0) or 0),
        "functions_covered": (
            int(coverage.get("total_functions", 0) or 0)
            - int(coverage.get("uncovered_functions_count", 0) or 0)
        ),
        "segments_total": int(coverage.get("total_segments", 0) or 0),
        "segments_analyzed": int(coverage.get("analyzed_segments", 0) or 0),
        "coverage_complete": bool(coverage.get("is_complete", False)),
        "specialists": specialists,
        "failed_agents": failed_agents,
        "skipped_analysis": skipped_agents,
        "static_engines": {
            "status": summary.static_analysis_status,
            "attempted": sorted(set(tools_attempted)),
            "executed": list(getattr(report, "tools_used", []) or []),
            "failed": list(getattr(summary, "tools_failed", []) or []),
        },
        "dynamic_verification": dynamic_status,
        "dynamic_tests": {
            "total": len(tests),
            "executed": len(executed_tests),
            "all_executed_passed": all_passed,
        },
        "poc": {
            "attempted": poc_attempted,
            "executed": poc_executed,
            "environment_limited": poc_env,
            "reproduced": poc_reproduced,
        },
        "reproduced_findings": reproduced_findings,
        "important_limitations": list(getattr(report, "limitations", []) or []),
        "claims": {
            "full_coverage": full_coverage,
            "all_tests_passed": all_passed,
            "reproduced": reproduced_findings,
        },
    }
