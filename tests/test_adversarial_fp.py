"""False-positive elimination + independent adversarial verification.

Every test encodes a documented production false positive (docs/baseline.md)
or a structural fact about the code, not an opinion:

- internal-only functions reported as externally reachable must not headline
  the report (reachability);
- "no access control" on a function whose external paths are all authorization
  gated is contradicted (authorization gates);
- a mutation/privileged-action claim pinned on a view/pure function is
  contradicted (read-only evidence);
- standard-semantics claims about vendored third-party library code are out of
  the audited surface (scope).

The engine can only DOWNGRADE. A finding it cannot assess is left untouched,
and a genuine open public entry point is never suppressed.
"""

from __future__ import annotations

import asyncio

import httpx
import respx

from agentsafe.agents.adversarial import AdversarialVerifier
from agentsafe.agents.reachability import build_reachability
from agentsafe.agents.validation import ValidationAgent
from agentsafe.analyzers.bytecode import (
    BytecodeAnalysis,
    BytecodeAnalyzer,
    BytecodeClass,
    BytecodeClassification,
    BytecodeToolRun,
)
from agentsafe.explorer import EtherscanClient, SourceBundle, SourceFile
from agentsafe.orchestrator import AuditOrchestrator
from agentsafe.rpc import EthRpcClient
from agentsafe.schemas import Finding, FindingCategory, FindingStatus, Severity

# ---------------------------------------------------------------------------
# sources with stable, hand-numbered lines
# ---------------------------------------------------------------------------

REACH_SRC = "\n".join(
    [
        "pragma solidity ^0.8.0;",                                    # 1
        "contract A {",                                              # 2
        "    uint256 private x;",                                    # 3
        "    function pub(uint256 v) external {",                    # 4
        "        _setX(v);",                                         # 5
        "    }",                                                     # 6
        "    function _setX(uint256 v) internal {",                  # 7
        "        x = v;",                                            # 8
        "    }",                                                     # 9
        "    function _orphan(uint256 v) internal {",                # 10
        "        x = v;",                                            # 11
        "    }",                                                     # 12
        "}",                                                         # 13
    ]
)

GUARD_SRC = "\n".join(
    [
        "pragma solidity ^0.8.0;",                                   # 1
        "contract B {",                                              # 2
        "    address private owner;",                                # 3
        "    uint256 private impl;",                                 # 4
        "    function upgradeToAndCall(uint256 v) external onlyOwner {",  # 5
        "        _setImpl(v);",                                      # 6
        "    }",                                                     # 7
        "    function _setImpl(uint256 v) internal {",               # 8
        "        impl = v;",                                         # 9
        "    }",                                                     # 10
        "}",                                                         # 11
    ]
)

VIEW_SRC = "\n".join(
    [
        "pragma solidity ^0.8.0;",                                   # 1
        "contract V {",                                              # 2
        "    uint256 private fee;",                                  # 3
        "    function getFee() external view returns (uint256) {",   # 4
        "        return fee;",                                       # 5
        "    }",                                                     # 6
        "}",                                                         # 7
    ]
)

RECEIVE_SRC = "\n".join(
    [
        "pragma solidity ^0.8.0;",                                   # 1
        "contract R {",                                              # 2
        "    uint256 private x;",                                    # 3
        "    function poke() external {",                            # 4
        "        x = 2;",                                            # 5
        "    }",                                                     # 6
        "    receive() external payable {",                          # 7
        "        _sink();",                                          # 8
        "    }",                                                     # 9
        "    function _sink() internal {",                           # 10
        "        x = 1;",                                            # 11
        "    }",                                                     # 12
        "}",                                                         # 13
    ]
)


def _line_of(src: str, needle: str) -> int:
    for i, ln in enumerate(src.splitlines(), start=1):
        if needle in ln:
            return i
    raise AssertionError(f"needle not found: {needle!r}")


def _finding(**kw) -> Finding:
    base = dict(
        title="Unsafe state write in _orphan()",
        severity="high",
        status=FindingStatus.POTENTIAL,
        source=["general_discovery"],
        description="an attacker triggers an unexpected state write",
        evidence="x = v;",
        preconditions="any external account can call the exposed path",
        attack_scenario="1) call the path; 2) x is written unexpectedly",
        impact="unexpected state mutation",
        file_path="A.sol",
        line_start=11,
    )
    base.update(kw)
    return Finding(**base)


# ---------------------------------------------------------------------------
# reachability model
# ---------------------------------------------------------------------------

class TestReachabilityModel:
    def test_internal_without_caller_is_not_reachable(self):
        m = build_reachability({"A.sol": REACH_SRC})
        assert m is not None
        loc = m.function_at("A.sol", _line_of(REACH_SRC, "_orphan"))
        assert loc is not None and loc.fn.name == "_orphan"
        assert m.reachability(loc) == "not_reachable"

    def test_internal_reached_from_public_entry_is_reachable(self):
        m = build_reachability({"A.sol": REACH_SRC})
        loc = m.function_at("A.sol", _line_of(REACH_SRC, "x = v;"))
        assert loc is not None and loc.fn.name == "_setX"
        assert m.reachability(loc) == "reachable"
        assert m.attacker_can_reach(loc) is True  # pub() is ungated

    def test_auth_guarded_entry_makes_callee_not_attacker_reachable(self):
        m = build_reachability({"B.sol": GUARD_SRC})
        loc = m.function_at("B.sol", _line_of(GUARD_SRC, "impl = v;"))
        assert loc is not None and loc.fn.name == "_setImpl"
        assert m.reachability(loc) == "reachable"          # reached via upgradeToAndCall
        assert m.attacker_can_reach(loc) is False          # but only through onlyOwner
        assert m.guard_of(loc.key) is None
        assert m.guarded.get("B.upgradeToAndCall") == "modifier onlyOwner"

    def test_receive_body_forces_unknown(self):
        """An unparsed receive()/fallback() could call the internal function,
        so reachability must stay 'unknown' (never a confident rejection)."""
        m = build_reachability({"R.sol": RECEIVE_SRC})
        loc = m.function_at("R.sol", _line_of(RECEIVE_SRC, "x = 1;"))
        assert loc is not None and loc.fn.name == "_sink"
        assert m.reachability(loc) == "unknown"

    def test_no_segments_returns_none(self):
        assert build_reachability(None) is None
        assert build_reachability({}) is None


# ---------------------------------------------------------------------------
# adversarial verifier rules
# ---------------------------------------------------------------------------

class TestInternalUnreachableRule:
    def test_orphan_internal_function_is_downgraded(self):
        v = AdversarialVerifier()
        f = _finding()
        res = v.review([], [f], {"A.sol": REACH_SRC}, False)
        assert res.challenged == 1 and res.downgraded == 1 and res.rejected == 0
        out = res.llm_findings[0]
        assert out.status is FindingStatus.INFORMATIONAL
        assert out.severity is Severity.INFO
        assert out.metadata["challenge"]["rule"] == "ra0_internal_unreachable"
        assert out.proposed_severity is Severity.HIGH  # original claim preserved
        assert out.validation_method == "adversarial_review"
        assert out.contradicting_evidence  # the internal/private header is quoted

    def test_externally_reachable_function_is_untouched(self):
        v = AdversarialVerifier()
        f = _finding(
            title="Unexpected state write in _setX()",
            evidence="x = v;",
            file_path="A.sol",
            line_start=_line_of(REACH_SRC, "x = v;"),
        )
        res = v.review([], [f], {"A.sol": REACH_SRC}, False)
        assert res.challenged == 0
        assert res.llm_findings[0].status is FindingStatus.POTENTIAL

    def test_pseudo_source_is_never_reachability_challenged(self):
        v = AdversarialVerifier()
        f = _finding(file_path="decompiled.sol")
        res = v.review([], [f], {"decompiled.sol": "pseudo"}, True)
        assert res.challenged == 0


class TestAuthorizationGateRule:
    def test_missing_access_control_on_gated_function_is_downgraded(self):
        v = AdversarialVerifier()
        f = _finding(
            title="Missing access control on _setImpl()",
            description="no authorization on the implementation setter",
            evidence="impl = v;",
            file_path="B.sol",
            line_start=_line_of(GUARD_SRC, "impl = v;"),
            category=FindingCategory.ACCESS_CONTROL,
        )
        res = v.review([], [f], {"B.sol": GUARD_SRC}, False)
        assert res.challenged == 1 and res.downgraded == 1
        out = res.llm_findings[0]
        assert out.status is FindingStatus.INFORMATIONAL
        assert out.metadata["challenge"]["rule"] == "ac0_authz_gated_path"
        assert "onlyOwner" in " ".join(out.contradicting_evidence)

    def test_open_function_missing_access_control_is_not_suppressed(self):
        """A genuinely unprotected external function must NOT be cleared - that
        would be a missed vulnerability."""
        src = "\n".join(
            [
                "pragma solidity ^0.8.0;",
                "contract O {",
                "    uint256 private fee;",
                "    function setFee(uint256 f) external {",
                "        fee = f;",
                "    }",
                "}",
            ]
        )
        v = AdversarialVerifier()
        f = _finding(
            title="Missing access control on setFee()",
            description="setFee() is callable by anyone",
            evidence="fee = f;",
            file_path="O.sol",
            line_start=_line_of(src, "fee = f;"),
            category=FindingCategory.ACCESS_CONTROL,
        )
        res = v.review([], [f], {"O.sol": src}, False)
        assert res.challenged == 0
        assert res.llm_findings[0].status is FindingStatus.POTENTIAL


class TestReadOnlyContradictionRule:
    def test_mutation_claim_on_view_function_is_refuted(self):
        v = AdversarialVerifier()
        f = _finding(
            title="getFee() allows an upgrade to change the fee",
            description="the implementation can be swapped to change fees",
            evidence="return fee;",
            file_path="V.sol",
            line_start=_line_of(VIEW_SRC, "return fee;"),
        )
        res = v.review([], [f], {"V.sol": VIEW_SRC}, False)
        assert res.challenged == 1 and res.rejected == 1
        out = res.llm_findings[0]
        assert out.status is FindingStatus.REJECTED
        assert out.metadata["challenge"]["rule"] == "ro0_readonly_contradiction"

    def test_mutation_claim_with_evidence_elsewhere_is_not_refuted(self):
        """Mis-located evidence must not be refuted on the view basis: the
        claim may be about a different (mutating) function."""
        v = AdversarialVerifier()
        f = _finding(
            title="getFee() allows an upgrade to change the fee",
            description="the implementation can be swapped to change fees",
            evidence="function _adminUpgrade() external { impl = 0; }",
            file_path="V.sol",
            line_start=_line_of(VIEW_SRC, "return fee;"),
        )
        res = v.review([], [f], {"V.sol": VIEW_SRC}, False)
        assert res.challenged == 0


class TestProxyByDesignRule:
    UUPS_GUARDED = "\n".join(
        [
            "pragma solidity ^0.8.0;",
            "contract ProxyA {",
            "    address private owner;",
            "    modifier initializer() { _; }",
            "    modifier onlyProxy() { _; }",
            "    function upgradeToAndCall(address impl) external onlyProxy {",
            "        _authorizeUpgrade(impl);",
            "    }",
            "    function _authorizeUpgrade(address impl) internal onlyOwner {",
            '        require(msg.sender == owner, "not owner");',
            "    }",
            "}",
        ]
    )
    UUPS_UNGUARDED = "\n".join(
        [
            "pragma solidity ^0.8.0;",
            "contract ProxyB {",
            "    modifier initializer() { _; }",
            "    function upgradeToAndCall(address impl) external {",
            "        _authorizeUpgrade(impl);",
            "    }",
            "    function _authorizeUpgrade(address impl) internal {",
            "    }",
            "}",
        ]
    )

    def test_guarded_uups_upgrade_claim_is_informational(self):
        v = AdversarialVerifier()
        f = _finding(
            title="Missing access control on upgradeToAndCall()",
            description="upgradeToAndCall can be called without authorization",
            evidence="function upgradeToAndCall(address impl) external onlyProxy {",
            file_path="P.sol",
            line_start=_line_of(self.UUPS_GUARDED, "upgradeToAndCall(address impl) external"),
            category=FindingCategory.ACCESS_CONTROL,
        )
        res = v.review([], [f], {"P.sol": self.UUPS_GUARDED}, False)
        assert res.challenged == 1 and res.downgraded == 1
        out = res.llm_findings[0]
        assert out.status is FindingStatus.INFORMATIONAL
        assert out.metadata["challenge"]["rule"] == "pxy0_proxy_admin_by_design"
        assert "authorizeUpgrade" in " ".join(out.contradicting_evidence)

    def test_unguarded_uups_upgrade_is_not_suppressed(self):
        """A proxy whose _authorizeUpgrade carries NO authorization must keep
        the missing-access-control finding - suppressing it would be a missed
        vulnerability."""
        v = AdversarialVerifier()
        f = _finding(
            title="Missing access control on upgradeToAndCall()",
            description="upgradeToAndCall can be called without authorization",
            evidence="function upgradeToAndCall(address impl) external {",
            file_path="P.sol",
            line_start=_line_of(self.UUPS_UNGUARDED, "upgradeToAndCall(address impl) external"),
            category=FindingCategory.ACCESS_CONTROL,
        )
        res = v.review([], [f], {"P.sol": self.UUPS_UNGUARDED}, False)
        assert res.challenged == 0
        assert res.llm_findings[0].status is FindingStatus.POTENTIAL


class TestVendoredScopeRule:
    def test_standard_semantics_in_vendored_library_is_informational(self):
        v = AdversarialVerifier()
        f = _finding(
            title="Standard ERC20 approve/transferFrom allowance race",
            description="standard ERC20 allowance semantics allow a front-run reset",
            evidence="allowance[msg.sender][spender] = value;",
            file_path="@openzeppelin/contracts/token/ERC20/ERC20.sol",
            line_start=120,
            category=FindingCategory.TOKEN,
        )
        res = v.review([], [f], None, False)
        assert res.challenged == 1 and res.downgraded == 1
        out = res.llm_findings[0]
        assert out.status is FindingStatus.INFORMATIONAL
        assert out.metadata["challenge"]["rule"] == "vnd0_vendored_standard"


class TestDeclarationOnlyEvidenceRule:
    def test_interface_signature_evidence_is_unverified(self):
        v = AdversarialVerifier()
        f = _finding(
            title="Unprotected transfer in the IERC20 interface",
            description="the interface exposes transfer without a guard",
            evidence="function transfer(address to, uint256 amount) external returns (bool);",
            file_path="IERC20.sol",
            line_start=10,
            category=FindingCategory.TOKEN,
        )
        src = (
            "interface IERC20 { function transfer(address to, uint256 amount) "
            "external returns (bool); }"
        )
        res = v.review([], [f], {"IERC20.sol": src}, False)
        assert res.challenged == 1 and res.unverified == 1
        out = res.llm_findings[0]
        assert out.status is FindingStatus.UNVERIFIED
        assert out.metadata["challenge"]["rule"] == "iface0_declaration_only_evidence"
        assert res.summary()["unverified"] == 1

    def test_full_function_evidence_is_not_declaration_only(self):
        v = AdversarialVerifier()
        f = _finding(
            title="Reentrancy via external call before state update",
            description="the external call precedes the balance update",
            evidence=(
                'function withdraw() external { (bool ok, ) = msg.sender.call{value: 1}("");'
                " balances[msg.sender] = 0; }"
            ),
            file_path="W.sol",
            line_start=3,
        )
        res = v.review([], [f], None, False)
        assert res.challenged == 0
        assert "iface0_declaration_only_evidence" not in res.by_rule


class TestDowngradeOnlyInvariant:
    def test_engine_never_upgrades_a_claim(self):
        v = AdversarialVerifier()
        findings = [
            _finding(),  # will be downgraded
            _finding(
                title="Open function missing access control",
                evidence="x = v;",
                file_path="A.sol",
                line_start=_line_of(REACH_SRC, "x = v;"),
                category=FindingCategory.ACCESS_CONTROL,
            ),
        ]
        res = v.review([], findings, {"A.sol": REACH_SRC}, False)
        for orig, out in zip(findings, res.llm_findings, strict=True):
            assert (
                out.severity.value == orig.severity.value
                or Severity(out.severity.value) is Severity.INFO
            )
            assert out.status is not FindingStatus.CONFIRMED


# ---------------------------------------------------------------------------
# orchestrator integration: the stage is explicit and recorded
# ---------------------------------------------------------------------------

ADDR = "0x" + "ab" * 20
RPC = "https://rpc.test"
ETH = "https://api.etherscan.test/v2/api"
CODE = "0x6080604052" + "ff" * 300


class _FakeExplorer(EtherscanClient):
    def __init__(self, bundle):
        super().__init__("k", base_url=ETH, sleeper=_ns)
        self._bundle = bundle

    async def get_verified_source(self, address):
        return self._bundle


class _FakeBytecode(BytecodeAnalyzer):
    async def analyze(self, bytecode):
        return BytecodeAnalysis(
            classification=BytecodeClassification(BytecodeClass.NORMAL, len(bytecode) // 2 - 1),
            runs=[BytecodeToolRun(tool="mythril", executed=False, findings=[],
                                  error="not installed")],
        )


class _StubRouter:
    def start_audit(self, *, max_calls, deadline_seconds):
        import time

        from agentsafe.llm.router import AuditBudget

        return AuditBudget(max_calls=max_calls, deadline=time.monotonic() + deadline_seconds,
                           clock=time.monotonic)


class _OneFindingAgent:
    name = "general_discovery"

    def __init__(self, finding):
        self._f = finding

    async def analyze(self, budget, material):
        from agentsafe.agents.base import AgentResult

        return AgentResult(agent=self.name, findings=[self._f])


async def _ns(_):
    return None


class TestOrchestratorAdversarialStage:
    @respx.mock
    def test_internal_only_finding_is_downgraded_and_stage_recorded(self):
        respx.post(RPC).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": CODE})
        )
        bundle = SourceBundle(
            is_verified=True,
            contract_name="A",
            compiler_version="v0.8.19",
            files=[SourceFile(path="A.sol", content=REACH_SRC)],
        )
        finding = _finding(status=FindingStatus.LLM_SUGGESTED)
        orch = AuditOrchestrator(
            rpc=EthRpcClient(RPC, sleeper=_ns),
            explorer=_FakeExplorer(bundle),
            source_analyzer=_NoSource(),
            bytecode_analyzer=_FakeBytecode(),
            router=_StubRouter(),
            agents=[_OneFindingAgent(finding)],
            validation_agent=ValidationAgent(),
            total_timeout_seconds=60.0,
            llm_max_calls=5,
            llm_deadline_seconds=30.0,
        )
        stages: list[tuple[str, str]] = []

        def _progress(st):
            stages.append((st.name, st.state.value))

        report = asyncio.run(orch.run(ADDR, task_id="task-adv", progress=_progress))
        assert any(name == "adversarial_review" and state == "completed" for name, state in stages)
        assert report.adversarial_review.get("challenged") == 1
        assert report.adversarial_review.get("downgraded_to_informational") == 1
        # the internal-only finding never headlines as a high-severity issue
        assert "high" not in report.summary.by_severity
        assert report.summary.by_status.get("informational") == 1
        assert any("adversarial review" in lim for lim in report.limitations)


class TestRenderedAdversarialSection:
    def test_html_and_markdown_surface_the_challenge_summary(self):
        from agentsafe.report import build_report
        from agentsafe.report_render import render_html, render_markdown
        from agentsafe.schemas import LLMUsage

        rep = build_report(
            address=ADDR,
            task_id="t-render",
            is_verified_source=True,
            tool_findings=[],
            llm_findings=[],
            tools_executed=["slither"],
            tools_failed=[],
            tool_versions={},
            llm_usage=LLMUsage(),
            limitations=[],
            errors=[],
            execution_time_seconds=1.0,
            adversarial_review={
                "challenged": 2,
                "downgraded_to_informational": 1,
                "refuted": 1,
                "by_rule": {
                    "ra0_internal_unreachable": 1,
                    "ro0_readonly_contradiction": 1,
                },
            },
        )
        html = render_html(rep)
        md = render_markdown(rep)
        assert "Adversarial review" in html
        assert "Adversarial review" in md
        assert "ra0_internal_unreachable" in md


class _NoSource:
    """Source analyzer double: recounts no tool runs (static stage is not the
    subject of this test)."""

    tools_attempted = ("slither",)

    async def analyze(self, bundle):
        from agentsafe.analyzers.source import SourceAnalysis

        return SourceAnalysis(runs=[], partial_failure=False)
