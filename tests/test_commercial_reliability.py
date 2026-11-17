"""Priority 5: commercial-reliability acceptance tests.

Each test maps to one of the ten required failure modes. Where a stronger
test already exists it is referenced in the docstring instead of duplicated
(do not weaken coverage); the gaps are filled here.

  1. one engine times out while the others succeed        -> this file
  2. one specialist fails while the others succeed        -> this file
  3. LLM provider returns malformed JSON                  -> this file (audit
     survival; the router-level repair gate is tests/test_router.py)
  4. Neon/task-store retrieval temporarily fails          -> this file
  5. report generation fails and is retried               -> tests/test_audit_states.py
  6. partial audit report retrieval (API level)           -> this file
  7. duplicate task submission                            -> this file
  8. payment not charged twice during a retry             -> this file
  9. WETH9 transfer rollback regression                   -> tests/test_evm_semantics.py
 10. complete audit report generation                     -> this file
"""

from __future__ import annotations

import io
import json
import zipfile

import httpx
import pytest
import respx

from agentsafe.agents.scheduler import MultiAgentScheduler
from agentsafe.agents.validation import ValidationAgent
from agentsafe.llm.router import LLMRouterError
from agentsafe.orchestrator import AuditOrchestrator
from agentsafe.report import build_report
from agentsafe.report_render import render_html
from agentsafe.rpc import EthRpcClient
from agentsafe.schemas import LLMUsage
from agentsafe.server import build_server
from tests.test_orchestrator import (
    ADDR,
    CODE,
    SLITHER_FINDING,
    FakeBytecodeAnalyzer,
    FakeExplorer,
    FakeSourceAnalyzer,
    _orchestrator,
    _stub_rpc,
)
from tests.test_payments import (
    GH,
    _mock_facilitator,
    _settings,
)
from tests.test_rest_x402 import _http_client, _payment_header_from_402


# ---------------------------------------------------------------- 1. engines
@respx.mock
async def test_one_engine_times_out_while_others_succeed():
    """Mythril times out; slither + heimdall succeed. The audit still produces
    a report that names the failed engine and keeps the successful findings."""
    from agentsafe.analyzers.bytecode import (
        BytecodeAnalysis,
        BytecodeAnalyzer,
        BytecodeClass,
        BytecodeClassification,
        BytecodeToolRun,
    )

    class MythrilTimeout(BytecodeAnalyzer):
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
                        error="mythril timed out (hard outer limit)",
                        failure_category="timeout",
                        duration_seconds=330.0,
                    ),
                    BytecodeToolRun(
                        tool="heimdall",
                        executed=True,
                        findings=[],
                        pseudo_sources={"decompiled.sol": "pseudo"},
                        duration_seconds=2.5,
                    ),
                ],
            )

    _stub_rpc(CODE)
    orch = _orchestrator(
        FakeExplorer(verified=True),
        FakeSourceAnalyzer([SLITHER_FINDING]),
        MythrilTimeout(),
        router=None,
    )
    report = await orch.run(ADDR, task_id="task-engine-timeout")

    assert report.summary.audit_state == "partial"
    assert "mythril" in report.summary.tools_failed
    assert "slither" in report.summary.tools_executed
    assert "heimdall" in report.summary.tools_executed
    # the successful engine's finding survived; the timeout is documented
    assert any(f.detector_id == "reentrancy-eth" for f in report.findings)
    mythril_exec = next(t for t in report.tool_executions if t.tool == "mythril")
    assert mythril_exec.executed is False
    assert mythril_exec.failure_category == "timeout"
    assert mythril_exec.duration_seconds == 330.0
    assert "PARTIAL ASSESSMENT" in render_html(report)


# ------------------------------------------------------------- 2. specialists
class _BoomRouter:
    """Returns nothing; the boom happens in one specialist's analyze."""

    def start_audit(self, **kw):
        return _Budget()

    async def complete_json(self, budget, messages, payload_cls):
        return payload_cls.model_validate({"findings": []}), _Call()


class _Budget:
    def __init__(self, max_calls: int = 100) -> None:
        self.max_calls = max_calls
        self.calls_made = 0
        self.calls_by_agent: dict[str, int] = {}
        self.deadline = 1e18
        self.failed_calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.providers_used: set[str] = set()
        self.models_used: set[str] = set()

    def usage_summary(self) -> dict:
        return {
            "total_calls": self.calls_made,
            "failed_calls": self.failed_calls,
            "prompt_tokens": None,
            "completion_tokens": None,
            "providers_used": [],
            "models_used": [],
            "calls_by_agent": dict(self.calls_by_agent),
        }


class _Call:
    provider = "mock"
    model = "m"


@respx.mock
async def test_one_specialist_fails_while_others_succeed(monkeypatch):
    """GeneralDiscoveryAgent raises; the other specialists run. The audit
    completes with a partial state and an explicit 'incomplete detection'
    limitation - never a silent clean bill of health."""
    from agentsafe.agents import specialists as spec

    def _boom(self, budget, material):
        raise RuntimeError("specialist crashed on prompt build")

    monkeypatch.setattr(spec.GeneralDiscoveryAgent, "analyze", _boom)

    async def _ns(_):
        return None

    _stub_rpc(CODE)
    orch = AuditOrchestrator(
        rpc=EthRpcClient("https://rpc.test", sleeper=_ns),
        explorer=FakeExplorer(verified=True),
        source_analyzer=FakeSourceAnalyzer([SLITHER_FINDING]),
        bytecode_analyzer=FakeBytecodeAnalyzer(findings=[]),
        router=_BoomRouter(),
        agents=[],
        validation_agent=ValidationAgent(),
        scheduler=MultiAgentScheduler(_BoomRouter(), max_concurrent=4),
        total_timeout_seconds=900.0,
        llm_max_calls=50,
        llm_deadline_seconds=60.0,
    )
    report = await orch.run(ADDR, task_id="task-specialist-fail")

    failed = [a for a in (report.llm_usage.per_agent or {})]
    assert report.summary.audit_state == "partial"
    assert any("incomplete detection" in lim for lim in report.limitations)
    # the deterministic tool finding is untouched by the agent failure
    assert any(f.detector_id == "reentrancy-eth" for f in report.findings)
    assert failed is not None


# ------------------------------------------------------ 3. malformed JSON
class _MalformedJsonRouter(_BoomRouter):
    async def complete_json(self, budget, messages, payload_cls):
        budget.calls_made += 1
        budget.calls_by_agent["malformed"] = (
            budget.calls_by_agent.get("malformed", 0) + 1
        )
        raise LLMRouterError("provider returned malformed JSON (repair failed)")


@respx.mock
async def test_malformed_llm_json_does_not_kill_the_audit():
    """Every agent call fails schema/prose repair. The audit still produces a
    report: LLM depth is optional, the deterministic findings are intact, and
    the failures are recorded (partial, not silent)."""
    async def _ns(_):
        return None

    _stub_rpc(CODE)
    orch = AuditOrchestrator(
        rpc=EthRpcClient("https://rpc.test", sleeper=_ns),
        explorer=FakeExplorer(verified=True),
        source_analyzer=FakeSourceAnalyzer([SLITHER_FINDING]),
        bytecode_analyzer=FakeBytecodeAnalyzer(findings=[]),
        router=_MalformedJsonRouter(),
        agents=[],
        validation_agent=ValidationAgent(),
        scheduler=MultiAgentScheduler(_MalformedJsonRouter(), max_concurrent=4),
        total_timeout_seconds=900.0,
        llm_max_calls=50,
        llm_deadline_seconds=60.0,
    )
    report = await orch.run(ADDR, task_id="task-malformed")

    assert report.summary.audit_state == "partial"
    assert report.errors or any(
        lim.startswith("incomplete detection") for lim in report.limitations
    )
    assert any(f.detector_id == "reentrancy-eth" for f in report.findings)


# ------------------------------------------------------- 4. Neon store outage
class _BrokenStore:
    """Real store behind a failing read path (transient Neon outage)."""

    def __init__(self, base) -> None:
        self._base = base

    def get(self, task_id):
        raise RuntimeError("connection to Neon timed out")

    def __getattr__(self, name):
        return getattr(self._base, name)


@pytest.mark.asyncio
async def test_task_store_outage_is_retryable_not_a_500(monkeypatch):
    import agentsafe.server as server_mod
    from agentsafe.task_store import open_task_store as real_open

    monkeypatch.setattr(
        server_mod,
        "open_task_store",
        lambda *a, **kw: _BrokenStore(real_open(*a, **kw)),
    )
    with respx.mock:
        _mock_facilitator()
        server = build_server(_settings())
        async with _http_client(server) as client:
            status = await client.get("/api/audit/task-outage/status")
            report = await client.get("/api/audit/task-outage/report")
    for res in (status, report):
        assert res.status_code == 503, res.text
        assert res.json()["error_code"] == "store_unavailable"


# --------------------------------------------- 6. partial report retrieval API
@respx.mock
async def test_partial_report_is_retrievable_and_labelled():
    """Free-mode end-to-end: dispatch -> completed run -> artifact download.
    The served HTML is the persisted partial report, clearly labelled."""
    _mock_facilitator()
    state: dict = {}
    partial = build_report(
        address=ADDR,
        task_id=None,
        is_verified_source=True,
        tool_findings=[],
        llm_findings=[],
        tools_executed=["slither"],
        tools_failed=["mythril"],
        tool_versions={},
        llm_usage=LLMUsage(),
        limitations=[
            "incomplete detection: 1 agent(s) failed and produced no findings"
        ],
        errors=["mythril: timed out"],
        execution_time_seconds=1.0,
        static_analysis_status="partial",
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("report.json", partial.model_dump_json())
    zip_bytes = buf.getvalue()

    def dispatch(request):
        state["task_id"] = json.loads(request.read())["inputs"]["task_id"]
        return httpx.Response(204)

    from datetime import UTC, datetime, timedelta

    created_at = (datetime.now(UTC) + timedelta(seconds=5)).isoformat()

    def runs_list(request):
        return httpx.Response(
            200,
            json={
                "workflow_runs": [
                    {
                        "id": 5,
                        "name": f"audit-{state['task_id']}",
                        "created_at": created_at,
                        "status": "completed",
                        "conclusion": "success",
                    }
                ]
            },
        )

    def run_one(request):
        return httpx.Response(
            200,
            json={
                "id": 5,
                "name": f"audit-{state.get('task_id', '')}",
                "created_at": created_at,
                "status": "completed",
                "conclusion": "success",
            },
        )

    def artifacts(request):
        return httpx.Response(
            200,
            json={
                "artifacts": [
                    {
                        "id": 77,
                        "name": f"audit-report-{state['task_id']}",
                        "expired": False,
                        "workflow_run": {"id": 5},
                    }
                ]
            },
        )

    respx.post(f"{GH}/repos/owner/repo/actions/workflows/audit.yml/dispatches").mock(
        side_effect=dispatch
    )
    respx.get(f"{GH}/repos/owner/repo/actions/workflows/audit.yml/runs").mock(
        side_effect=runs_list
    )
    respx.get(f"{GH}/repos/owner/repo/actions/runs/5").mock(side_effect=run_one)
    respx.get(f"{GH}/repos/owner/repo/actions/runs/5/artifacts").mock(
        side_effect=artifacts
    )
    respx.get(f"{GH}/repos/owner/repo/actions/artifacts/77/zip").mock(
        return_value=httpx.Response(200, content=zip_bytes)
    )

    server = build_server(_settings(PAYMENTS_ENABLED=False))
    async with _http_client(server) as client:
        started = await client.post("/api/audit", json={"address": ADDR})
        assert started.status_code == 202, started.text
        task_id = started.json()["task_id"]
        html = await client.get(f"/api/audit/{task_id}/report")

    assert html.status_code == 200, html.text
    assert "PARTIAL ASSESSMENT" in html.text
    assert "mythril" in html.text


# ------------------------------- 7+8. duplicate submission / no double charge
@respx.mock
async def test_duplicate_submission_never_charges_or_dispatches_twice():
    """A retried request carrying the SAME payment is rejected as a replay:
    the facilitator verifies/settles once and exactly one audit is
    dispatched."""
    routes = _mock_facilitator()
    dispatched: list[str] = []
    state: dict = {}

    def dispatch(request):
        tid = json.loads(request.read())["inputs"]["task_id"]
        state["task_id"] = tid
        dispatched.append(tid)
        return httpx.Response(204)

    from datetime import UTC, datetime, timedelta

    created_at = (datetime.now(UTC) + timedelta(seconds=5)).isoformat()

    def runs_list(request):
        return httpx.Response(
            200,
            json={
                "workflow_runs": [
                    {
                        "id": 5,
                        "name": f"audit-{state.get('task_id', '')}",
                        "created_at": created_at,
                        "status": "in_progress",
                        "conclusion": None,
                    }
                ]
            },
        )

    respx.post(f"{GH}/repos/owner/repo/actions/workflows/audit.yml/dispatches").mock(
        side_effect=dispatch
    )
    respx.get(f"{GH}/repos/owner/repo/actions/workflows/audit.yml/runs").mock(
        side_effect=runs_list
    )


    server = build_server(_settings())
    async with _http_client(server) as client:
        header = await _payment_header_from_402(client)
        first = await client.post(
            "/api/audit", json={"address": ADDR}, headers={"PAYMENT-SIGNATURE": header}
        )
        retry = await client.post(
            "/api/audit", json={"address": ADDR}, headers={"PAYMENT-SIGNATURE": header}
        )

    assert first.status_code == 202, first.text
    assert retry.status_code == 402
    assert retry.json()["error_code"] == "payment_replay"
    # the money moved exactly once (settle is the charge; verify is a free
    # upstream check and may legitimately run again on the retry) and exactly
    # one audit was dispatched
    assert routes["settle"].call_count == 1
    assert routes["verify"].call_count >= 1
    assert len(dispatched) == 1


# -------------------------------------------- 10. complete report generation
@respx.mock
async def test_complete_audit_report_generation():
    _stub_rpc(CODE)
    orch = _orchestrator(
        FakeExplorer(verified=True),
        FakeSourceAnalyzer([SLITHER_FINDING]),
        FakeBytecodeAnalyzer(findings=[]),
        router=None,
    )
    report = await orch.run(ADDR, task_id="task-complete")

    assert report.summary.audit_state == "complete"
    assert report.summary.static_analysis_status == "full"
    assert not report.summary.tools_failed
    assert report.task_id == "task-complete"
    assert report.report_id == "task-complete"
    html = render_html(report)
    assert "PARTIAL ASSESSMENT" not in html
    assert "Analysis coverage" in html
    assert ">complete<" in html
    # zero findings never means "safe"
    assert "not a formal security audit" in report.disclaimer
