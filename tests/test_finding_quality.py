"""Section 12 — finding quality and severity.

Pins:
- the required evidence package is audited deterministically and gaps are
  recorded (never padded, never invented);
- a PoC status is guaranteed for every actionable finding;
- severity is kept separate from confidence and verification status: a HIGH
  severity POTENTIAL finding is NOT a confirmed HIGH.
"""

from __future__ import annotations

import asyncio

import httpx
import respx

from agentsafe.agents.quality import (
    REQUIRED_ELEMENTS,
    ensure_poc_record,
    finding_quality,
)
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
from agentsafe.rpc import EthRpcClient
from agentsafe.schemas import Finding, FindingCategory, FindingStatus, Severity
from agentsafe.severity import assess

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


def _complete_finding() -> Finding:
    return Finding(
        title="Unauthorized state write in transfer()",
        severity="high",
        status=FindingStatus.POTENTIAL,
        source=["general_discovery"],
        detector_id=None,
        swc_id="SWC-105",
        category=FindingCategory.ACCESS_CONTROL,
        description="transfer() mutates balances without an authorization check",
        evidence="b[msg.sender] -= a; b[to] += a;",
        recommendation="add an access control check",
        preconditions="any external account can call transfer()",
        attack_scenario="1) call transfer(to, a); 2) balances change without auth",
        impact="attacker moves balances without authorization",
        file_path="Token.sol",
        line_start=5,
        confidence=0.6,
        supporting_evidence=["kb:reentrancy-1"],
        contradicting_evidence=["no guard on the path"],
        state_dependencies=["b", "a"],
        validation_method="deterministic_rules",
        validation_result="potential",
        metadata={
            "attacker_model": {
                "caller": "external account (no special role)",
                "feasible": "yes",
                "sequence": ["1. read state b", "2. write state b"],
            },
            "poc": {"status": "environment_limitation"},
            "disposition": "existing_exposure",
            "reconciliation": {"resolved_by": "deterministic source analysis"},
        },
    )


class TestQualityAudit:
    def test_required_elements_count(self):
        assert len(REQUIRED_ELEMENTS) == 19

    def test_complete_package(self):
        q = finding_quality(_complete_finding())
        assert q["complete"] is True and q["missing"] == []
        assert q["present_count"] == q["required_count"] == 19

    def test_missing_impact_is_recorded(self):
        f = _complete_finding()
        f.impact = ""
        q = finding_quality(f)
        assert not q["complete"] and "impact" in q["missing"]

    def test_missing_metadata_elements_are_recorded(self):
        f = _complete_finding()
        f.metadata = {}
        f.contradicting_evidence = []
        q = finding_quality(f)
        for name in ("attacker_model", "exploitability", "poc_status",
                     "counterarguments"):
            assert name in q["missing"]

    def test_ensure_poc_record_defaults_without_fabricating(self):
        f = _complete_finding()
        f.metadata = {k: v for k, v in f.metadata.items() if k != "poc"}
        ensure_poc_record(f)
        assert f.metadata["poc"]["status"] == "not_attempted"
        assert f.metadata["poc"]["executed"] is False

    def test_ensure_poc_record_keeps_existing(self):
        f = _complete_finding()
        ensure_poc_record(f)
        assert f.metadata["poc"]["status"] == "environment_limitation"


class TestSeveritySeparation:
    def test_high_severity_potential_is_capped_and_not_confirmed(self):
        f = Finding(
            title="x", severity="high", status=FindingStatus.POTENTIAL,
            source=["s"], description="d", evidence="e = 1;", confidence=0.9,
        )
        sev, _basis = assess(f)
        assert sev is Severity.MEDIUM            # not inflated to the claim
        assert f.status is FindingStatus.POTENTIAL  # never silently confirmed
        assert f.confidence == 0.9               # confidence is independent
        assert sev.value != f.status.value       # severity != verification status


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


class TestOrchestratorQuality:
    @respx.mock
    def test_quality_recorded_and_poc_guaranteed(self):
        respx.post(RPC).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": CODE})
        )
        bundle = SourceBundle(
            is_verified=True, contract_name="Token", compiler_version="v0.8.19",
            files=[SourceFile(path="Token.sol", content=SRC)],
        )
        finding = Finding(
            title="Unchecked state update in transfer()",
            severity="high", status=FindingStatus.LLM_SUGGESTED,
            source=["general_discovery"],
            description="transfer() updates balances without validation",
            evidence="b[msg.sender] -= a; b[to] += a;",
            preconditions="any account can call transfer()",
            attack_scenario="1) call transfer(to, a)",
            impact="balances are modified",
            file_path="Token.sol", line_start=5,
            category=FindingCategory.UNKNOWN,
        )
        orch = AuditOrchestrator(
            rpc=EthRpcClient(RPC, sleeper=_ns),
            explorer=_FakeExplorer(bundle),
            source_analyzer=_OkSource(),
            bytecode_analyzer=_OkBytecode(),
            router=_StubRouter(),
            agents=[_OneFindingAgent(finding)],
            validation_agent=ValidationAgent(),
            total_timeout_seconds=60.0,
            llm_max_calls=5,
            llm_deadline_seconds=30.0,
        )
        report = asyncio.run(orch.run(ADDR, task_id="task-q"))
        f = report.findings[0]
        q = f.metadata.get("quality") or {}
        assert q.get("required_count") == 19
        assert "poc" in f.metadata  # PoC status guaranteed
        # an actionable finding missing elements is reported, not hidden
        assert any("finding quality" in lim for lim in report.limitations)
