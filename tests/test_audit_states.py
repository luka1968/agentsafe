"""Priority 1: explicit audit states and fault-isolated report generation.

These tests pin the commercial-reliability contract:

- every report carries an explicit ``summary.audit_state`` of
  complete / partial / failed - a degraded audit is NEVER labelled complete;
- a partial report names the engines/agents that did not complete, in the
  rendered HTML and Markdown as well as the JSON;
- a single optional engine timing out, the specialist scheduler crashing,
  or the validation layer crashing does not abort the audit: the report is
  still produced, marked partial, and says what is missing;
- report assembly is retried, and rendering is a pure function of the
  persisted report (retyable without re-running analysis).

Cross-engine / payment invariants (no duplicate charge) are already pinned
by tests/test_payments.py (replay rejection) and tests/test_creem.py
(idempotent webhook + no-op re-dispatch).
"""

from __future__ import annotations

import json

import pytest
import respx

from agentsafe.agents.validation import ValidationAgent
from agentsafe.analyzers.bytecode import (
    BytecodeAnalysis,
    BytecodeAnalyzer,
    BytecodeClass,
    BytecodeClassification,
    BytecodeToolRun,
)
from agentsafe.orchestrator import AuditOrchestrator, OrchestratorError
from agentsafe.report import build_report
from agentsafe.report_render import render_html, render_markdown
from agentsafe.rpc import EthRpcClient
from agentsafe.schemas import AuditReport, FindingStatus, LLMUsage
from tests.test_orchestrator import (
    ADDR,
    CODE,
    SLITHER_FINDING,
    FakeBytecodeAnalyzer,
    FakeExplorer,
    FakeSourceAnalyzer,
    _orchestrator,
    _router,
    _stub_rpc,
)

BENIGN = "no extra limitations"


async def _ns(_):
    return None


def _report_kwargs(**over):
    base = dict(
        address=ADDR,
        task_id="task-states",
        is_verified_source=True,
        tool_findings=[],
        llm_findings=[],
        tools_executed=["slither", "mythril", "heimdall"],
        tools_failed=[],
        tool_versions={},
        llm_usage=LLMUsage(),
        limitations=[],
        errors=[],
        execution_time_seconds=1.0,
        static_analysis_status="full",
    )
    base.update(over)
    return base


# --------------------------------------------------------------- unit: state
class TestAuditStateDerivation:
    def test_clean_report_is_complete(self):
        r = build_report(**_report_kwargs())
        assert r.summary.audit_state == "complete"

    def test_failed_engine_demotes_to_partial(self):
        r = build_report(**_report_kwargs(tools_failed=["mythril"]))
        assert r.summary.audit_state == "partial"

    def test_stage_error_demotes_to_partial(self):
        r = build_report(**_report_kwargs(errors=["heimdall: timeout"]))
        assert r.summary.audit_state == "partial"

    def test_partial_static_analysis_demotes_to_partial(self):
        r = build_report(**_report_kwargs(static_analysis_status="partial"))
        assert r.summary.audit_state == "partial"

    def test_unavailable_static_analysis_demotes_to_partial(self):
        r = build_report(**_report_kwargs(static_analysis_status="unavailable"))
        assert r.summary.audit_state == "partial"

    def test_closed_source_skipped_alone_is_not_degradation(self):
        # No verified source is a designed path, not a failure: the bytecode
        # engines ran, so the report is complete (not partial).
        r = build_report(
            **_report_kwargs(is_verified_source=False, static_analysis_status="skipped")
        )
        assert r.summary.audit_state == "complete"

    def test_explicit_state_is_preserved(self):
        r = build_report(**_report_kwargs(audit_state="failed"))
        assert r.summary.audit_state == "failed"
        r2 = build_report(**_report_kwargs(audit_state="partial"))
        assert r2.summary.audit_state == "partial"


# ------------------------------------------------------------- unit: render
class TestPartialReportRendering:
    def _partial(self) -> AuditReport:
        return build_report(
            **_report_kwargs(
                tools_failed=["mythril"],
                static_analysis_status="partial",
                limitations=[
                    "incomplete detection: 2 agent(s) (access_control, fund_flow) "
                    "failed (LLM/provider/analysis errors) and produced no "
                    "findings; result is NOT a clean bill of health for those "
                    "dimensions"
                ],
            )
        )

    def test_html_partial_banner_names_missing_components(self):
        html = render_html(self._partial())
        assert "PARTIAL ASSESSMENT" in html
        assert "analysis incomplete" in html
        assert "mythril" in html  # unavailable engine is named
        assert "static analysis: partial" in html
        assert "access_control" in html  # failed agent is named

    def test_html_complete_report_has_no_partial_banner(self):
        html = render_html(build_report(**_report_kwargs()))
        assert "PARTIAL ASSESSMENT" not in html
        assert "Analysis coverage" in html
        assert ">complete<" in html

    def test_markdown_partial_banner(self):
        md = render_markdown(self._partial())
        assert "Audit state: partial" in md
        assert "PARTIAL ASSESSMENT" in md
        assert "mythril" in md

    def test_markdown_complete_state_line(self):
        md = render_markdown(build_report(**_report_kwargs()))
        assert "Audit state: complete" in md
        assert "PARTIAL ASSESSMENT" not in md

    def test_report_json_roundtrip_keeps_state_and_renders(self):
        """Retrieval/report regeneration is retryable: the persisted
        report.json is enough to re-render, with no analysis re-run."""
        original = self._partial()
        payload = original.model_dump(mode="json")
        revived = AuditReport.model_validate(json.loads(json.dumps(payload)))
        assert revived.summary.audit_state == "partial"
        assert render_html(revived) == render_html(original)
        assert render_markdown(revived) == render_markdown(original)


# ------------------------------------------------- orchestrator integration
class _BoomScheduler:
    async def run(self, budget, material, validation=None):
        raise RuntimeError("classifier exploded")


class _BoomValidation(ValidationAgent):
    def validate(self, *args, **kwargs):
        raise RuntimeError("validator exploded")

    def validate_tools(self, *args, **kwargs):
        raise RuntimeError("validator exploded")


@respx.mock
async def test_clean_run_is_complete():
    _stub_rpc(CODE)
    orch = _orchestrator(
        FakeExplorer(verified=True),
        FakeSourceAnalyzer([SLITHER_FINDING]),
        FakeBytecodeAnalyzer(findings=[]),
        router=None,
    )
    report = await orch.run(ADDR, task_id="task-clean")
    assert report.summary.audit_state == "complete"
    assert report.summary.static_analysis_status == "full"


@respx.mock
async def test_one_engine_times_out_others_succeed_report_is_partial():
    """P5 #1: one engine times out while the others succeed - the audit must
    still produce a report, clearly marked partial, naming the failed engine."""

    class TimeoutMythril(BytecodeAnalyzer):
        async def analyze(self, bytecode):
            return BytecodeAnalysis(
                classification=BytecodeClassification(
                    BytecodeClass.NORMAL, len(bytecode) // 2 - 1
                ),
                runs=[
                    BytecodeToolRun(
                        tool="mythril",
                        executed=False,
                        findings=[],
                        error="timed out after 300s",
                        failure_category="timeout",
                    ),
                    BytecodeToolRun(
                        tool="heimdall",
                        executed=True,
                        findings=[],
                        pseudo_sources={"decompiled.sol": "pseudo"},
                    ),
                ],
            )

    _stub_rpc(CODE)
    orch = _orchestrator(
        FakeExplorer(verified=True),
        FakeSourceAnalyzer([SLITHER_FINDING]),
        TimeoutMythril(),
        router=None,
    )
    report = await orch.run(ADDR, task_id="task-timeout")
    assert report.summary.audit_state == "partial"
    assert "mythril" in report.summary.tools_failed
    assert "heimdall" in report.summary.tools_executed
    # the successful engines' findings still made it into the report
    assert any(f.detector_id == "reentrancy-eth" for f in report.findings)
    html = render_html(report)
    assert "PARTIAL ASSESSMENT" in html and "mythril" in html


@respx.mock
async def test_scheduler_crash_does_not_abort_audit():
    _stub_rpc(CODE)
    orch = AuditOrchestrator(
        rpc=EthRpcClient("https://rpc.test", sleeper=_ns),
        explorer=FakeExplorer(verified=True),
        source_analyzer=FakeSourceAnalyzer([SLITHER_FINDING]),
        bytecode_analyzer=FakeBytecodeAnalyzer(findings=[]),
        router=_router(),
        agents=[],
        validation_agent=ValidationAgent(),
        scheduler=_BoomScheduler(),
        total_timeout_seconds=900.0,
        llm_max_calls=5,
        llm_deadline_seconds=60.0,
    )
    report = await orch.run(ADDR, task_id="task-sched")
    # specialization is optional depth: the report still exists...
    assert report.summary.audit_state == "partial"
    assert any("specialist scheduler" in e for e in report.errors)
    assert any("incomplete detection" in lim for lim in report.limitations)
    # ...and the deterministic tool findings survive untouched.
    assert any(f.detector_id == "reentrancy-eth" for f in report.findings)


@respx.mock
async def test_validation_crash_keeps_findings_but_marks_them_unvalidated():
    _stub_rpc(CODE)
    orch = AuditOrchestrator(
        rpc=EthRpcClient("https://rpc.test", sleeper=_ns),
        explorer=FakeExplorer(verified=True),
        source_analyzer=FakeSourceAnalyzer([SLITHER_FINDING]),
        bytecode_analyzer=FakeBytecodeAnalyzer(findings=[]),
        router=None,
        agents=[],
        validation_agent=_BoomValidation(),
        total_timeout_seconds=900.0,
        llm_max_calls=5,
        llm_deadline_seconds=60.0,
    )
    report = await orch.run(ADDR, task_id="task-val")
    assert report.summary.audit_state == "partial"
    assert any("cross validation" in e for e in report.errors)
    assert any("validation layer failed" in lim for lim in report.limitations)
    # findings are preserved with their PRE-validation status (not dropped,
    # and not silently upgraded to "confirmed" without evidence checking)
    sl = next(f for f in report.findings if f.detector_id == "reentrancy-eth")
    assert sl.status is not FindingStatus.CONFIRMED


@respx.mock
async def test_report_generation_is_retried_then_succeeds(monkeypatch):
    """P5 #5: a transient report-build failure is retried, audit not lost."""
    import agentsafe.report as report_mod

    real = report_mod.build_report
    calls = {"n": 0}

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError("transient model validation hiccup")
        return real(*args, **kwargs)

    monkeypatch.setattr(report_mod, "build_report", flaky)
    _stub_rpc(CODE)
    orch = _orchestrator(
        FakeExplorer(verified=True),
        FakeSourceAnalyzer([SLITHER_FINDING]),
        FakeBytecodeAnalyzer(findings=[]),
        router=None,
    )
    report = await orch.run(ADDR, task_id="task-retry")
    assert calls["n"] == 2  # failed once, retried, succeeded
    assert report.task_id == "task-retry"


@respx.mock
async def test_report_generation_persistent_failure_is_explicit(monkeypatch):
    import agentsafe.report as report_mod

    def always_fail(*args, **kwargs):
        raise ValueError("broken report model")

    monkeypatch.setattr(report_mod, "build_report", always_fail)
    _stub_rpc(CODE)
    orch = _orchestrator(
        FakeExplorer(verified=True),
        FakeSourceAnalyzer([SLITHER_FINDING]),
        FakeBytecodeAnalyzer(findings=[]),
        router=None,
    )
    stages: list = []
    with pytest.raises(OrchestratorError) as ei:
        await orch.run(
            ADDR, task_id="task-fail", progress=lambda st: stages.append(
                (st.name, st.state.value, st.error_code))
        )
    assert ei.value.error_code == "report_generation_failed"
    assert any(
        name == "merge_report" and state == "failed"
        for name, state, _code in stages
    )


def test_clip_report_preserves_audit_state():
    """The API/MCP payload path validates against AuditReport: the explicit
    state must survive serialization for the customer-facing JSON."""
    from agentsafe.server import _clip_report

    payload = build_report(
        **_report_kwargs(tools_failed=["mythril"])
    ).model_dump(mode="json")
    clipped = _clip_report(payload)
    assert clipped["summary"]["audit_state"] == "partial"


def test_duplicate_task_submission_reuses_task_id_not_new_charge():
    """Payment/idempotency invariants for duplicate submissions are owned by
    the payment layer (replay rejection + idempotent re-dispatch), pinned by
    tests/test_payments.py::test_replayed_payment_is_rejected and
    tests/test_creem.py::test_webhook_replay_is_idempotent. This test only
    documents the report-side invariant: one task -> one report id."""
    r1 = build_report(**_report_kwargs(task_id="task-dup"))
    r2 = build_report(**_report_kwargs(task_id="task-dup"))
    assert r1.task_id == r2.task_id == "task-dup"
    assert r1.report_id == r2.report_id == "task-dup"
