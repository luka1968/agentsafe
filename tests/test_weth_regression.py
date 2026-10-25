"""WETH9 regression: the exact false-positive classes from the production
report (Critical overflow, High reentrancy on withdraw, Medium allowance
race, Medium unusual transfer) must be neutralized by the deterministic
rule engine - while REAL vulnerabilities (EtherStore reentrancy, tool-
corroborated overflow) stay actionable. Rules never special-case by
contract identity; the fixtures are ordinary source code to the engine.
"""

from pathlib import Path

from agentsafe.agents.validation import ValidationAgent
from agentsafe.report import build_report, merge_findings
from agentsafe.schemas import Finding, FindingStatus, LLMUsage, Severity

FIXTURES = Path(__file__).parent / "fixtures"
WETH = (FIXTURES / "WETH.sol").read_text()
ETHERSTORE = (FIXTURES / "EtherStore.sol").read_text()
SEGMENTS = {"WETH.sol": WETH, "EtherStore.sol": ETHERSTORE}


def _llm(**kw) -> Finding:
    base = dict(
        title="Reentrancy in withdraw()",
        severity="high",
        status=FindingStatus.LLM_SUGGESTED,
        source=["fund_flow"],
        description="hypothesis",
        evidence="msg.sender.transfer(wad);",
        file_path="WETH.sol",
        line_start=30,
        confidence=0.8,
    )
    base.update(kw)
    return Finding(**base)


def _tool(**kw) -> Finding:
    base = dict(
        title="[slither] integer-overflow",
        severity="critical",
        status=FindingStatus.TOOL_DETECTED,
        source=["slither"],
        detector_id="integer-overflow",
        description="integer overflow in batchTransfer",
        evidence="balanceOf[receivers[i]] += amount;",
        file_path="EtherStore.sol",
        line_start=26,
    )
    base.update(kw)
    return Finding(**base)


class TestWETHFalsePositives:
    def test_reentrancy_on_withdraw_rejected_by_cei_analysis(self):
        v = ValidationAgent()
        out = v.validate([_llm()], [], SEGMENTS)
        assert out.rejected == 1
        f = out.findings[0]
        assert f.status is FindingStatus.REJECTED
        meta = f.metadata["validation"]
        assert meta["rule"] == "re0_cei_satisfied"
        assert meta["original_severity"] == "high"
        # the audit trail must quote the ordering that disproves the claim
        assert "balanceOf[msg.sender] -= wad;" in meta["reason"]
        assert "msg.sender.transfer(wad);" in meta["reason"]

    def test_critical_overflow_without_attack_path_is_informational(self):
        v = ValidationAgent()
        f = _llm(
            title="Integer Overflow or Underflow",
            severity="critical",
            description=(
                "Arithmetic operations lack SafeMath; balanceOf additions "
                "could theoretically overflow."
            ),
            evidence="balanceOf[msg.sender] += msg.value;",
            line_start=23,
        )
        out = v.validate([f], [], SEGMENTS)
        assert out.informational == 1
        res = out.findings[0]
        assert res.status is FindingStatus.INFORMATIONAL
        assert res.severity is Severity.INFO
        assert res.metadata["validation"]["rule"] == "ov0_theoretical_only"

    def test_allowance_race_standard_semantics_is_informational(self):
        v = ValidationAgent()
        f = _llm(
            title="Allowance race condition on approve()",
            severity="medium",
            description=(
                "Approve front-running race: an approved spender can spend "
                "the allowance before an approval change lands. Standard "
                "ERC-20 semantics (SWC-114); no exploitable deviation shown."
            ),
            evidence="allowance[msg.sender][guy] = wad;",
            line_start=36,
        )
        out = v.validate([f], [], SEGMENTS)
        assert out.informational == 1
        res = out.findings[0]
        assert res.status is FindingStatus.INFORMATIONAL
        assert res.severity is Severity.INFO
        assert res.metadata["validation"]["rule"] == "al0_standard_behavior"

    def test_unusual_transfer_delegation_is_informational(self):
        v = ValidationAgent()
        f = _llm(
            title="Unusual transfer() implementation",
            severity="medium",
            description=(
                "transfer() delegates to transferFrom(msg.sender, dst, wad) "
                "instead of duplicating balance checks."
            ),
            evidence="return transferFrom(msg.sender, dst, wad);",
            line_start=41,
        )
        out = v.validate([f], [], SEGMENTS)
        assert out.informational == 1
        res = out.findings[0]
        assert res.status is FindingStatus.INFORMATIONAL
        assert res.severity is Severity.INFO
        assert res.metadata["validation"]["rule"] == "tr0_canonical_delegation"

    def test_all_four_false_positives_production_report_shape(self):
        v = ValidationAgent()
        findings = [
            _llm(),
            _llm(
                title="Integer Overflow or Underflow",
                severity="critical",
                description=(
                    "Arithmetic operations lack SafeMath; balanceOf additions "
                    "could theoretically overflow."
                ),
                evidence="balanceOf[msg.sender] += msg.value;",
                line_start=23,
            ),
            _llm(
                title="Allowance race condition on approve()",
                severity="medium",
                description=(
                    "Approve front-running race: an approved spender can spend "
                    "the allowance before an approval change lands. Standard "
                    "ERC-20 semantics (SWC-114); no exploitable deviation shown."
                ),
                evidence="allowance[msg.sender][guy] = wad;",
                line_start=36,
            ),
            _llm(
                title="Unusual transfer() implementation",
                severity="medium",
                description=(
                    "transfer() delegates to transferFrom(msg.sender, dst, wad) "
                    "instead of duplicating balance checks."
                ),
                evidence="return transferFrom(msg.sender, dst, wad);",
                line_start=41,
            ),
        ]
        out = v.validate(findings, [], SEGMENTS)
        assert (out.rejected, out.informational) == (1, 3)

        report = build_report(
            address="0x" + "c0" * 20,
            task_id=None,
            is_verified_source=True,
            tool_findings=[],
            llm_findings=out.findings,
            tools_executed=["slither"],
            tools_failed=[],
            tool_versions={},
            llm_usage=LLMUsage(total_calls=1),
            limitations=[],
            errors=[],
            execution_time_seconds=1.0,
        )
        # headline severities must be free of the false positives
        assert "critical" not in report.summary.by_severity
        assert "high" not in report.summary.by_severity
        assert report.summary.by_status.get("rejected") == 1
        assert report.summary.by_status.get("informational") == 3
        # rejected finding retained for auditability, sorts last
        assert report.findings[-1].status is FindingStatus.REJECTED
        # honesty rails intact
        blob = report.model_dump_json()
        assert "not a formal security audit" in report.disclaimer
        assert '"safe"' not in blob


class TestRealVulnerabilitiesNotSuppressed:
    def test_etherstore_reentrancy_stays_potential_high(self):
        v = ValidationAgent()
        f = _llm(
            title="Reentrancy in EtherStore.withdraw",
            severity="high",
            description=(
                "External call sends Ether before the balance state update; "
                "classic reentrancy."
            ),
            evidence='(bool sent, ) = msg.sender.call{value: bal}("");',
            file_path="EtherStore.sol",
            line_start=14,
        )
        out = v.validate([f], [], SEGMENTS)
        assert out.rejected == 0, out.findings[0].metadata["validation"]
        res = out.findings[0]
        assert res.status is FindingStatus.POTENTIAL
        assert res.severity is Severity.HIGH

    def test_tool_corroborated_overflow_stays_confirmed_critical(self):
        v = ValidationAgent()
        llm = _llm(
            title="Integer Overflow in batchTransfer",
            severity="critical",
            description=(
                "amount is attacker-controlled and unchecked; exploiting the "
                "overflow lets an attacker mint arbitrary total supply and "
                "drain balances."
            ),
            evidence="balanceOf[receivers[i]] += amount;",
            file_path="EtherStore.sol",
            line_start=26,
        )
        tool = _tool()
        llm_out = v.validate([llm], [tool], SEGMENTS)
        tool_out = v.validate_tools([tool], llm_out.findings, SEGMENTS)
        assert llm_out.confirmed == 1
        assert llm_out.findings[0].status is FindingStatus.CONFIRMED
        assert llm_out.findings[0].severity is Severity.CRITICAL
        assert llm_out.findings[0].metadata["validation"]["rule"] == "cr0_independent_support"
        assert tool_out.confirmed == 1
        assert tool_out.findings[0].metadata["validation"]["rule"] == "cr0_llm_corroboration"

        # report level: both merge into one confirmed critical finding
        merged = merge_findings(tool_out.findings, llm_out.findings)
        assert len(merged) == 1
        assert merged[0].status is FindingStatus.CONFIRMED
        assert merged[0].severity is Severity.CRITICAL
        assert set(merged[0].source) == {"slither", "fund_flow"}
