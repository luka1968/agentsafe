"""Section 13 — report integrity and customer trust.

Pins:
- the consolidated integrity panel records coverage, engine/agent execution,
  skipped analysis, dynamic/PoC status, and verified-vs-suspected counts;
- it NEVER claims full coverage when analysis was partial, NEVER claims all
  tests passed when some were not executed, and NEVER counts an LLM hypothesis
  as reproduced;
- confirmed findings receive specific, code-anchored remediation;
- the panel renders in HTML and Markdown.
"""

from __future__ import annotations

import asyncio

import httpx
import respx

from agentsafe.agents.integrity import build_integrity
from agentsafe.agents.remediation import apply_specific_remediation, specific_remediation
from agentsafe.agents.validation import ValidationAgent
from agentsafe.analyzers.bytecode import (
    BytecodeAnalysis,
    BytecodeAnalyzer,
    BytecodeClass,
    BytecodeClassification,
    BytecodeToolRun,
)
from agentsafe.analyzers.source import SourceAnalysis, ToolRun
from agentsafe.explorer import EtherscanClient, SourceBundle, SourceFile
from agentsafe.orchestrator import AuditOrchestrator
from agentsafe.report import build_report
from agentsafe.report_render import render_html, render_markdown
from agentsafe.rpc import EthRpcClient
from agentsafe.schemas import Finding, FindingCategory, FindingStatus, LLMUsage

ADDR = "0x" + "ab" * 20
RPC = "https://rpc.test"
ETH = "https://api.etherscan.test/v2/api"
CODE = "0x6080604052" + "ff" * 200

SRC = ("pragma solidity ^0.8.0;\n"
       "contract Token {\n"
       "    mapping(address => uint256) private b;\n"
       "    function transfer(address to, uint256 a) external {\n"
       "        b[msg.sender] -= a; b[to] += a;\n"
       "    }\n"
       "}")


def _finding(**kw) -> Finding:
    base = dict(
        title="State issue", severity="medium", status=FindingStatus.POTENTIAL,
        source=["general_discovery"], description="d", evidence="b[to] += a;",
        file_path="Token.sol", line_start=5,
    )
    base.update(kw)
    return Finding(**base)


def _report(findings=(), *, coverage=None, tests=None, limitations=None):
    return build_report(
        address=ADDR, task_id="t", is_verified_source=True,
        tool_findings=[], llm_findings=list(findings),
        tools_executed=["slither"], tools_failed=["mythril"], tool_versions={},
        static_analysis_status="partial", audit_state="partial",
        analyzed_files=["Token.sol"], llm_usage=LLMUsage(),
        limitations=list(limitations or []), errors=[],
        execution_time_seconds=1.0,
        targeted_test_results=list(tests or []),
        coverage=coverage or {},
    )


class TestIntegrityPanel:
    def test_panel_records_the_required_facts(self):
        cov = {"total_segments": 4, "analyzed_segments": 3, "is_complete": False,
               "total_functions": 2, "uncovered_functions_count": 1}
        sched = {"per_agent": [
            {"agent": "reentrancy", "ran": True, "findings": 1, "llm_calls": 2,
             "errors": []},
            {"agent": "oracle", "ran": False, "findings": 0, "skipped": "no oracle"},
        ]}
        rep = _report([_finding()], coverage=cov)
        it = build_integrity(
            rep, scheduler_meta=sched, tools_attempted=["slither", "mythril"],
            received_files=["Token.sol", "Lib.sol"],
        )
        assert it["audit_state"] == "partial"
        assert it["source_files_received"] == ["Token.sol", "Lib.sol"]
        assert it["segments_analyzed"] == 3 and it["segments_total"] == 4
        assert it["functions_covered"] == 1 and it["functions_total"] == 2
        assert it["coverage_complete"] is False
        assert it["failed_agents"] == [] and it["skipped_analysis"] == ["oracle"]
        assert it["static_engines"]["status"] == "partial"
        assert it["static_engines"]["failed"] == ["mythril"]

    def test_never_claims_tests_passed_when_none_executed(self):
        rep = _report([_finding()], tests=[
            {"test_id": "t1", "result": "not_executed"},
        ])
        it = build_integrity(rep)
        assert it["dynamic_verification"] == "not_executed"
        assert it["dynamic_tests"]["all_executed_passed"] == "none_executed"
        assert it["claims"]["all_tests_passed"] == "none_executed"
        assert it["reproduced_findings"] == 0

    def test_llm_hypothesis_is_never_reproduced(self):
        rep = _report([_finding(status=FindingStatus.POTENTIAL)])
        it = build_integrity(rep)
        assert it["reproduced_findings"] == 0
        assert it["claims"]["reproduced"] == 0
        assert it["verified_vs_suspected"]["potential_suspected"] == 1

    def test_reproduced_counts_only_executed_impact(self):
        f = _finding(status=FindingStatus.CONFIRMED,
                     metadata={"poc": {"status": "successful_exploitation",
                                       "executed": True}})
        rep = _report([f], tests=[
            {"test_id": "t1", "result": "passed", "reproduced": True},
        ])
        it = build_integrity(rep)
        assert it["reproduced_findings"] >= 1
        assert it["dynamic_verification"] == "executed"
        assert it["dynamic_tests"]["all_executed_passed"] is True

    def test_no_partial_coverage_claim(self):
        rep = _report([_finding()], coverage={"is_complete": False,
                                              "total_segments": 2,
                                              "analyzed_segments": 1})
        it = build_integrity(rep)
        assert it["claims"]["full_coverage"] is False


class TestIntegrityRendering:
    def test_panel_renders_in_html_and_markdown(self):
        rep = _report([_finding()], coverage={"is_complete": True,
                                              "total_segments": 1,
                                              "analyzed_segments": 1})
        rep.integrity = build_integrity(rep)
        html = render_html(rep)
        md = render_markdown(rep)
        assert "Audit integrity" in html and "Audit integrity" in md
        assert "Verified vs suspected" in html
        assert "Verified vs suspected" in md


class TestSpecificRemediation:
    def test_cei_remediation_is_code_anchored(self):
        f = _finding(
            status=FindingStatus.CONFIRMED, category=FindingCategory.REENTRANCY,
            title="Reentrancy in withdraw()", affected_functions=["Vault.withdraw"],
            evidence='(bool ok, ) = msg.sender.call{value: amt}("");',
            recommendation="consider adding a guard",
            metadata={"validation": {"rule": "re1_cei_violation_kb"}},
        )
        assert apply_specific_remediation(f) is True
        r = f.recommendation
        assert "checks-effects-interactions" in r and "Vault.withdraw" in r

    def test_specific_recommendation_is_kept(self):
        f = _finding(
            status=FindingStatus.CONFIRMED, category=FindingCategory.REENTRANCY,
            recommendation=(
                "In Vault.withdraw (Vault.sol:42), reorder so the balances mapping "
                "is decremented before the low-level call, or add nonReentrant."
            ),
        )
        assert apply_specific_remediation(f) is False

    def test_no_rule_means_no_invention(self):
        f = _finding(status=FindingStatus.CONFIRMED, recommendation="")
        assert specific_remediation(f) is None


# ---------------------------------------------------------------------------
# orchestrator integration
# ---------------------------------------------------------------------------

async def _ns(_):
    return None


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


class _OneFindingAgent:
    name = "general_discovery"

    def __init__(self, finding):
        self._f = finding

    async def analyze(self, budget, material):
        from agentsafe.agents.base import AgentResult

        return AgentResult(agent=self.name, findings=[self._f])


class TestOrchestratorIntegrity:
    @respx.mock
    def test_integrity_panel_attached_and_honest(self):
        respx.post(RPC).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": CODE})
        )
        bundle = SourceBundle(
            is_verified=True, contract_name="Token", compiler_version="v0.8.19",
            files=[SourceFile(path="Token.sol", content=SRC)],
        )
        orch = AuditOrchestrator(
            rpc=EthRpcClient(RPC, sleeper=_ns),
            explorer=_FakeExplorer(bundle),
            source_analyzer=_OkSource(),
            bytecode_analyzer=_OkBytecode(),
            router=_StubRouter(),
            agents=[_OneFindingAgent(_finding(status=FindingStatus.LLM_SUGGESTED))],
            validation_agent=ValidationAgent(),
            total_timeout_seconds=60.0,
            llm_max_calls=5,
            llm_deadline_seconds=30.0,
        )
        report = asyncio.run(orch.run(ADDR, task_id="task-int"))
        it = report.integrity
        assert it and it["audit_state"] in ("complete", "partial")
        assert it["source_files_received"] == ["Token.sol"]
        assert it["claims"]["reproduced"] == 0
        assert it["claims"]["all_tests_passed"] == "none_executed"
        # the panel is rendered
        assert "Audit integrity" in render_html(report)
