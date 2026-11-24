"""Stage B — source-coverage accounting.

Every submitted file and segment must be accounted for, and a partial analysis
must never be presented as complete. These tests pin:

- segment inventory matches the agents' chunker (including split files);
- the union of what agents analyzed is what the coverage record reports;
- functions inside un-analyzed segments are named;
- when agents RAN but left segments unread, the report is marked PARTIAL and
  the unread segments are named in the limitations.
"""

from __future__ import annotations

import asyncio

import httpx
import respx

from agentsafe.agents.classification import ClassifiedProfile
from agentsafe.agents.scheduler import AgentRunStats, SchedulerResult
from agentsafe.agents.validation import ValidationAgent
from agentsafe.analyzers.bytecode import (
    BytecodeAnalysis,
    BytecodeAnalyzer,
    BytecodeClass,
    BytecodeClassification,
    BytecodeToolRun,
)
from agentsafe.analyzers.source import SourceAnalysis, ToolRun
from agentsafe.coverage import build_coverage
from agentsafe.explorer import EtherscanClient, SourceBundle, SourceFile
from agentsafe.intel.extract import extract_contract_intel
from agentsafe.orchestrator import AuditOrchestrator
from agentsafe.rpc import EthRpcClient

ADDR = "0x" + "ab" * 20
RPC = "https://rpc.test"
ETH = "https://api.etherscan.test/v2/api"
CODE = "0x6080604052" + "ff" * 200


async def _ns(_):
    return None


# ---------------------------------------------------------------------------
# unit: coverage record
# ---------------------------------------------------------------------------

class TestCoverageRecord:
    def test_single_small_file_is_complete(self):
        rep = build_coverage({"A.sol": "contract A {}"}, {"A.sol"})
        assert rep.total_segments == 1 and rep.analyzed_segments == 1
        assert rep.is_complete and rep.coverage_ratio == 1.0

    def test_missing_segment_is_incomplete(self):
        rep = build_coverage(
            {"A.sol": "contract A {}", "B.sol": "contract B {}"}, {"A.sol"}
        )
        assert rep.total_segments == 2 and rep.analyzed_segments == 1
        assert not rep.is_complete
        assert rep.unanalyzed_segments == ["B.sol"]
        assert rep.per_file["B.sol"]["analyzed"] == 0

    def test_oversized_file_splits_and_partial_read_is_incomplete(self):
        big = "// pad line\n" * 1500  # > 8000 chars -> multiple segments
        rep0 = build_coverage({"Big.sol": big}, set())
        labels = sorted(rep0.unanalyzed_segments)
        assert len(labels) >= 2  # the file really was split
        rep = build_coverage({"Big.sol": big}, {labels[0]})
        assert not rep.is_complete
        assert rep.analyzed_segments == 1

    def test_function_in_unanalyzed_segment_is_named(self):
        src = "contract A { uint256 x; function f() external { x = 1; } }"
        intel = extract_contract_intel({"A.sol": src})
        rep = build_coverage({"A.sol": src}, set(), intel=intel)
        assert rep.total_functions == 1
        assert rep.uncovered_functions and "A.f" in rep.uncovered_functions[0]
        covered = build_coverage({"A.sol": src}, {"A.sol"}, intel=intel)
        assert covered.uncovered_functions == []

    def test_empty_analysis_reports_zero_analyzed(self):
        rep = build_coverage({"A.sol": "contract A {}"}, set())
        assert rep.analyzed_segments == 0 and not rep.is_complete
        assert any("no agent analyzed" in n for n in rep.notes)


# ---------------------------------------------------------------------------
# orchestrator integration: agents ran, coverage partial -> report PARTIAL
# ---------------------------------------------------------------------------

class _FakeExplorer(EtherscanClient):
    def __init__(self, bundle):
        super().__init__("k", base_url=ETH, sleeper=_ns)
        self._bundle = bundle

    async def get_verified_source(self, address):
        return self._bundle


class _OkSource:
    tools_attempted = ("slither",)

    async def analyze(self, bundle):
        return SourceAnalysis(
            runs=[ToolRun(tool="slither", executed=True, findings=[])],
            partial_failure=False,
        )


class _OkBytecode(BytecodeAnalyzer):
    async def analyze(self, bytecode):
        return BytecodeAnalysis(
            classification=BytecodeClassification(BytecodeClass.NORMAL, 1),
            runs=[BytecodeToolRun(tool="mythril", executed=True, findings=[])],
        )


class _StubRouter:
    def start_audit(self, *, max_calls, deadline_seconds):
        import time

        from agentsafe.llm.router import AuditBudget

        return AuditBudget(
            max_calls=max_calls,
            deadline=time.monotonic() + deadline_seconds,
            clock=time.monotonic,
        )


class _CoverageScheduler:
    """Runs and reports exactly the analyzed labels it is given."""

    def __init__(self, analyzed):
        self._analyzed = list(analyzed)

    async def run(self, budget, material, validation=None):
        return SchedulerResult(
            profile=ClassifiedProfile(),
            per_agent=[AgentRunStats(agent="reentrancy", analyzed_labels=self._analyzed)],
        )


def _two_file_bundle() -> SourceBundle:
    return SourceBundle(
        is_verified=True,
        contract_name="A",
        compiler_version="",
        files=[
            SourceFile(path="A.sol", content="contract A { function f() external {} }"),
            SourceFile(path="B.sol", content="contract B { function g() external {} }"),
        ],
    )


def _run(analyzed) -> object:
    orch = AuditOrchestrator(
        rpc=EthRpcClient(RPC, sleeper=_ns),
        explorer=_FakeExplorer(_two_file_bundle()),
        source_analyzer=_OkSource(),
        bytecode_analyzer=_OkBytecode(),
        router=_StubRouter(),
        agents=[],
        validation_agent=ValidationAgent(),
        total_timeout_seconds=60.0,
        llm_max_calls=5,
        llm_deadline_seconds=30.0,
        scheduler=_CoverageScheduler(analyzed),
    )
    return orch


class TestOrchestratorCoverage:
    @respx.mock
    def test_partial_agent_coverage_demotes_report_to_partial(self):
        respx.post(RPC).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": CODE})
        )
        report = asyncio.run(_run(["A.sol"]).run(ADDR, task_id="task-cov"))
        assert report.summary.audit_state == "partial"
        assert report.coverage["is_complete"] is False
        assert report.coverage["analyzed_segments"] == 1
        assert "B.sol" in report.coverage["unanalyzed_segments"]
        assert any("source coverage incomplete" in lim for lim in report.limitations)

    @respx.mock
    def test_full_agent_coverage_stays_complete(self):
        respx.post(RPC).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": CODE})
        )
        report = asyncio.run(_run(["A.sol", "B.sol"]).run(ADDR, task_id="task-cov2"))
        assert report.summary.audit_state == "complete"
        assert report.coverage["is_complete"] is True
        assert report.coverage["unanalyzed_segments"] == []
