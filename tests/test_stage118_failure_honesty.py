"""Stage 11.8 — failure honesty gate.

When any specialist agent fails (LLM/provider/analysis errors), the audit must
surface it as *incomplete detection*, never as a clean "no findings" result.
This prevents a failed agent from silently being indistinguishable from a
genuinely safe contract.
"""

from __future__ import annotations

import asyncio
import time

import httpx
import pytest
import respx

from agentsafe.agents.scheduler import AgentRunStats, SchedulerResult
from agentsafe.agents.classification import ClassifiedProfile
from agentsafe.config import LLMProviderConfig
from agentsafe.llm.router import LLMRouter
from tests.test_orchestrator import (
    ADDR,
    FakeBytecodeAnalyzer,
    FakeExplorer,
    FakeSourceAnalyzer,
    _stub_rpc,
)
from agentsafe.orchestrator import AuditOrchestrator
from agentsafe.agents.validation import ValidationAgent
from agentsafe.rpc import EthRpcClient


async def _ns(_):
    return None


def _router():
    prov = LLMProviderConfig(
        name="p", base_url="https://llm.test/v1", api_key="sk",
        model="m", rpm_limit=60)
    return LLMRouter(
        [prov], global_rpm=600, request_timeout_seconds=5,
        max_retries_per_call=0, http_client=httpx.AsyncClient(),
        sleeper=_ns, clock=lambda: time.monotonic())


class _FailScheduler:
    """Returns one agent that FAILED (errors present) + one that succeeded."""

    def __init__(self, failed_agents: list[str]) -> None:
        self._failed = failed_agents

    async def run(self, budget, material, *, validation=None):
        result = SchedulerResult(profile=ClassifiedProfile())
        result.routing_summary = "test routing"
        ok = [AgentRunStats(agent="access_control", depth="basic",
                            started=0.0, elapsed=0.1, findings_produced=0)]
        ok[0].findings_produced = 0
        for name in self._failed:
            st = AgentRunStats(agent=name, depth="basic", started=0.0,
                               elapsed=0.1)
            st.errors = [f"{name}: LLMRouterError: provider down"]
            result.per_agent.append(st)
        result.per_agent.insert(0, ok[0])
        return result


class _SilentScheduler:
    """All agents succeed -> no honesty-gate limitation."""

    async def run(self, budget, material, *, validation=None):
        result = SchedulerResult(profile=ClassifiedProfile())
        result.routing_summary = "ok"
        result.per_agent.append(
            AgentRunStats(agent="access_control", depth="basic", started=0.0,
                          elapsed=0.1, findings_produced=0))
        return result


def _orch(scheduler):
    return AuditOrchestrator(
        rpc=EthRpcClient("https://rpc.test", sleeper=_ns),
        explorer=FakeExplorer(verified=True),
        source_analyzer=FakeSourceAnalyzer(findings=[]),
        bytecode_analyzer=FakeBytecodeAnalyzer(findings=[]),
        router=_router(),
        agents=[],
        validation_agent=ValidationAgent(),
        total_timeout_seconds=300.0,
        llm_max_calls=5,
        llm_deadline_seconds=60.0,
        scheduler=scheduler,
    )


@pytest.mark.asyncio
@respx.mock
async def test_failed_agent_surfaces_incomplete_detection():
    _stub_rpc("0x60006000" + "00" * 60)
    orch = _orch(_FailScheduler(failed_agents=["fund_flow"]))
    report = await orch.run(ADDR)
    joined = "\n".join(report.limitations or [])
    assert "incomplete detection" in joined
    assert "fund_flow" in joined
    assert "NOT a clean bill of health" in joined


@pytest.mark.asyncio
@respx.mock
async def test_no_failure_no_gate():
    _stub_rpc("0x60006000" + "00" * 60)
    orch = _orch(_SilentScheduler())
    report = await orch.run(ADDR)
    joined = "\n".join(report.limitations or [])
    assert "incomplete detection" not in joined