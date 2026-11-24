"""Section 11 — historical / deployed-contract context.

Pins:
- source kind (verified deployed source vs unverified bytecode);
- immutability (immutable vs upgradeable) from evidence, with the remediation
  applicability flag;
- compiler era (pre-0.8 is not auto-exploitable);
- code-quality / compiler-warning findings are NEVER actionable vulnerabilities;
- immutable-deployed recommendations are flagged as not applicable to bytecode;
- the orchestrator records the context and reclassifies such findings as
  informational.
"""

from __future__ import annotations

import asyncio

import httpx
import respx

from agentsafe.agents.deployment import (
    DISPOSITION_EXISTING_EXPOSURE,
    DISPOSITION_INFORMATIONAL,
    DISPOSITION_RECOMMENDATION,
    IMMUTABLE,
    SOURCE_DEPLOYED_UNVERIFIED,
    SOURCE_DEPLOYED_VERIFIED,
    UPGRADEABLE,
    build_deployment_context,
    finding_disposition,
    is_code_quality,
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
from agentsafe.intel.extract import extract_contract_intel
from agentsafe.orchestrator import AuditOrchestrator
from agentsafe.rpc import EthRpcClient
from agentsafe.schemas import Finding, FindingCategory, FindingStatus

ADDR = "0x" + "ab" * 20
RPC = "https://rpc.test"
ETH = "https://api.etherscan.test/v2/api"
CODE = "0x6080604052" + "ff" * 200

IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

REGULAR_SRC = ("pragma solidity ^0.8.0;\n"
               "contract Token {\n"
               "    mapping(address => uint256) private b;\n"
               "    function transfer(address to, uint256 a) external {\n"
               "        b[msg.sender] -= a; b[to] += a;\n"
               "    }\n"
               "}")
UPGRADEABLE_SRC = ("pragma solidity ^0.8.0;\n"
                   "contract U {\n"
                   f"    bytes32 private constant IMPLEMENTATION_SLOT = {IMPL};\n"
                   "    modifier initializer() { _; }\n"
                   "    function upgradeToAndCall(address impl) external { }\n"
                   "}")


def _finding(**kw) -> Finding:
    base = dict(
        title="State issue", severity="high", status=FindingStatus.POTENTIAL,
        source=["general_discovery"], description="a state value is affected",
        evidence="b[to] += a;", file_path="T.sol", line_start=5,
    )
    base.update(kw)
    return Finding(**base)


class TestDeploymentContext:
    def test_immutable_deployed_verified(self):
        intel = extract_contract_intel({"T.sol": REGULAR_SRC})
        ctx = build_deployment_context(
            address=ADDR, is_verified_source=True,
            compiler_version="v0.8.19", intel=intel, chain=8453,
        )
        assert ctx.source_kind == SOURCE_DEPLOYED_VERIFIED
        assert ctx.immutability == IMMUTABLE
        assert ctx.remediation_applicable_to_bytecode is False
        assert any("immutable deployed contract" in n for n in ctx.notes)
        assert ctx.solc_mm == "0.8" and ctx.pre_0_8 is False

    def test_upgradeable_verified_is_remediable(self):
        intel = extract_contract_intel({"U.sol": UPGRADEABLE_SRC})
        ctx = build_deployment_context(
            address=ADDR, is_verified_source=True,
            compiler_version="v0.8.19", intel=intel,
        )
        assert ctx.immutability == UPGRADEABLE
        assert ctx.remediation_applicable_to_bytecode is True

    def test_unverified_bytecode(self):
        ctx = build_deployment_context(
            address=ADDR, is_verified_source=False, compiler_version="",
        )
        assert ctx.source_kind == SOURCE_DEPLOYED_UNVERIFIED
        assert ctx.immutability == "unknown"
        assert ctx.remediation_applicable_to_bytecode is False

    def test_pre_0_8_flag(self):
        ctx = build_deployment_context(
            address=ADDR, is_verified_source=True, compiler_version="v0.7.6",
        )
        assert ctx.pre_0_8 is True
        assert any("pre-0.8" in n for n in ctx.notes)


class TestDisposition:
    def _ctx(self, src):
        return build_deployment_context(
            address=ADDR, is_verified_source=True, compiler_version="v0.8.19",
            intel=extract_contract_intel({"T.sol": src}),
        )

    def test_code_quality_is_never_actionable(self):
        cq = _finding(title="Naming convention: _variable should be mixedCase",
                      detector_id="naming-convention")
        assert is_code_quality(cq)
        assert finding_disposition(cq, self._ctx(REGULAR_SRC)) == DISPOSITION_INFORMATIONAL

    def test_compiler_warning_detector_is_quality(self):
        assert is_code_quality(_finding(title="x", detector_id="solc-version"))
        assert is_code_quality(_finding(title="Code quality: redundant cast"))

    def test_security_finding_is_not_quality(self):
        assert not is_code_quality(
            _finding(title="Reentrancy in withdraw", detector_id="reentrancy-eth")
        )

    def test_immutable_recommendation_not_applicable(self):
        rec = _finding(
            title="Consider adding a zero-address check in the constructor",
            description="recommend adding a check", category=FindingCategory.UNKNOWN,
        )
        assert finding_disposition(rec, self._ctx(REGULAR_SRC)) == DISPOSITION_RECOMMENDATION

    def test_immutable_security_finding_stays_exposure(self):
        sec = _finding(title="Reentrancy in withdraw",
                       category=FindingCategory.REENTRANCY)
        assert finding_disposition(sec, self._ctx(REGULAR_SRC)) == DISPOSITION_EXISTING_EXPOSURE

    def test_upgradeable_recommendation_is_remediable(self):
        rec = _finding(title="Consider adding a zero-address check",
                       category=FindingCategory.UNKNOWN)
        assert finding_disposition(rec, self._ctx(UPGRADEABLE_SRC)) == DISPOSITION_EXISTING_EXPOSURE


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


class TestOrchestratorDeploymentContext:
    @respx.mock
    def test_code_quality_finding_reclassified_and_context_recorded(self):
        respx.post(RPC).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": CODE})
        )
        bundle = SourceBundle(
            is_verified=True, contract_name="Token", compiler_version="v0.8.19",
            files=[SourceFile(path="T.sol", content=REGULAR_SRC)],
        )
        finding = _finding(
            status=FindingStatus.LLM_SUGGESTED,
            title="Naming convention: variable should be mixedCase",
            category=FindingCategory.UNKNOWN,
            severity="low",
            description="style issue: the state variable name violates convention",
            preconditions="n/a", attack_scenario="n/a", impact="n/a",
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
        report = asyncio.run(orch.run(ADDR, task_id="task-dep"))
        assert report.deployment.get("source_kind") == SOURCE_DEPLOYED_VERIFIED
        assert report.deployment.get("immutability") == IMMUTABLE
        f = report.findings[0]
        assert f.metadata.get("disposition") == DISPOSITION_INFORMATIONAL
        assert f.status is FindingStatus.INFORMATIONAL
        assert any("deployment context" in lim for lim in report.limitations)
