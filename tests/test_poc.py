"""Section 8 — executable verification / PoC.

Pins the honesty contract in an environment with no EVM backend:

- Foundry is detected correctly (the npm ``forge`` shim is NOT Foundry);
- a PoC plan is built deterministically from the finding + attacker model;
- the five outcomes are distinguished and a pass WITHOUT a demonstrated impact
  is NOT proof;
- with no backend the outcome is ``environment_limitation``, no result is
  fabricated, and confidence is unchanged;
- high-impact / financially-significant findings are prioritised.
"""

from __future__ import annotations

import asyncio

import httpx
import respx

from agentsafe.agents.poc import (
    assess_poc,
    build_poc_plan,
    classify_poc_result,
    foundry_available,
    poc_priority,
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
from agentsafe.schemas import Finding, FindingCategory, FindingStatus

ADDR = "0x" + "ab" * 20
RPC = "https://rpc.test"
ETH = "https://api.etherscan.test/v2/api"
CODE = "0x6080604052" + "ff" * 200

WITHDRAW_SRC = "\n".join(
    [
        "pragma solidity ^0.8.0;",                                   # 1
        "contract V {",                                              # 2
        "    mapping(address => uint256) balances;",                 # 3
        "    function withdraw(uint256 amt) external {",             # 4
        '        (bool ok, ) = msg.sender.call{value: amt}("");',    # 5
        '        require(ok, "fail");',                              # 6
        "        balances[msg.sender] -= amt;",                      # 7
        "    }",                                                     # 8
        "}",                                                         # 9
    ]
)


def _line_of(src: str, needle: str) -> int:
    for i, ln in enumerate(src.splitlines(), start=1):
        if needle in ln:
            return i
    raise AssertionError(needle)


def _finding(**kw) -> Finding:
    base = dict(
        title="Reentrancy in withdraw()",
        severity="high",
        status=FindingStatus.POTENTIAL,
        source=["reentrancy"],
        description="the external call precedes the balance update",
        evidence='(bool ok, ) = msg.sender.call{value: amt}("");',
        file_path="V.sol",
        line_start=_line_of(WITHDRAW_SRC, "msg.sender.call"),
        preconditions="attacker is any external account with a balance",
        attack_scenario="1) deposit; 2) call withdraw re-entrantly",
        impact="attacker drains the contract's funds via reentrancy",
        category=FindingCategory.REENTRANCY,
    )
    base.update(kw)
    return Finding(**base)


# ---------------------------------------------------------------------------
# backend detection + prioritisation
# ---------------------------------------------------------------------------

class TestBackendAndPriority:
    def test_npm_forge_shim_is_not_foundry(self):
        # In this environment `forge` is an unrelated npm shim.
        assert foundry_available() is False

    def test_high_severity_and_financial_impact_are_high_priority(self):
        assert poc_priority(_finding(severity="critical")) == "high"
        assert poc_priority(_finding(severity="high")) == "high"
        assert poc_priority(
            _finding(severity="low", category=FindingCategory.ORACLE, impact="x")
        ) == "high"
        assert poc_priority(
            _finding(
                severity="low",
                category=FindingCategory.UNKNOWN,
                impact="drains user funds",
            )
        ) == "high"
        assert poc_priority(
            _finding(
                severity="low",
                category=FindingCategory.UNKNOWN,
                impact="minor gas",
            )
        ) == "normal"


# ---------------------------------------------------------------------------
# plan
# ---------------------------------------------------------------------------

class TestPlan:
    def test_plan_uses_attacker_model_and_impact(self):
        am = {
            "caller": "external account (no special role)",
            "permissions": [],
            "capital_required": ["ETH via msg.value"],
            "multi_transaction": "yes",
            "sequence": ["1. external call msg.sender.call", "2. write state balances"],
        }
        plan = build_poc_plan(_finding(), attacker_model=am, backend="none")
        assert "external account" in plan.attacker
        assert any("capital" in p for p in plan.preconditions)
        assert any("multiple transactions" in p for p in plan.preconditions)
        assert plan.sequence == am["sequence"]
        assert plan.impact_assertion  # from finding.impact
        assert plan.priority == "high"


# ---------------------------------------------------------------------------
# classification (the five outcomes)
# ---------------------------------------------------------------------------

class TestClassification:
    def test_successful_exploitation_requires_demonstrated_impact(self):
        r = classify_poc_result("passed", impact_demonstrated=True)
        assert r.status == "successful_exploitation"

    def test_pass_without_impact_is_not_proof(self):
        r = classify_poc_result("passed", impact_demonstrated=False)
        assert r.status == "inconclusive"
        assert "not proof" in r.reason

    def test_expected_revert_vs_failed_attack(self):
        assert classify_poc_result(
            "failed", impact_demonstrated=False, revert_expected=True
        ).status == "expected_revert"
        assert classify_poc_result(
            "failed", impact_demonstrated=False
        ).status == "failed_attack"

    def test_environment_limitation_when_no_backend(self):
        r = classify_poc_result("not_executed", impact_demonstrated=False,
                                backend_available=False)
        assert r.status == "environment_limitation" and r.executed is False

    def test_uninterpretable_run_is_inconclusive(self):
        assert classify_poc_result("error", impact_demonstrated=False).status == "inconclusive"


class TestAssessPoC:
    def test_no_impact_predicate_is_inconclusive(self):
        plan, res = assess_poc(_finding(impact=""), backend_available=True)
        assert res.status == "inconclusive" and not plan.impact_assertion

    def test_no_backend_is_environment_limitation(self):
        _plan, res = assess_poc(_finding(), backend_available=False)
        assert res.status == "environment_limitation"
        assert res.executed is False

    def test_backend_present_plans_execution(self):
        _plan, res = assess_poc(_finding(), backend_available=True)
        assert res.status == "inconclusive" and res.backend == "foundry"


# ---------------------------------------------------------------------------
# orchestrator integration: honest, no fabrication
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
    name = "reentrancy"

    def __init__(self, finding):
        self._f = finding

    async def analyze(self, budget, material):
        from agentsafe.agents.base import AgentResult

        return AgentResult(agent=self.name, findings=[self._f])


class TestOrchestratorPoCHonesty:
    @respx.mock
    def test_high_impact_finding_gets_environment_limitation_no_fabrication(self):
        respx.post(RPC).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": CODE})
        )
        bundle = SourceBundle(
            is_verified=True,
            contract_name="V",
            compiler_version="v0.8.19",
            files=[SourceFile(path="V.sol", content=WITHDRAW_SRC)],
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
        report = asyncio.run(orch.run(ADDR, task_id="task-poc"))
        f = report.findings[0]
        poc = f.metadata.get("poc") or {}
        assert poc.get("status") == "environment_limitation"
        assert poc.get("executed") is False
        assert poc.get("impact_assertion")
        # the PoC step never fabricates an exploit result or inflates confidence
        assert poc.get("status") != "successful_exploitation"
        assert any("PoC execution unavailable" in lim for lim in report.limitations)
