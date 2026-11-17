"""Priority 3: EVM transaction-semantics correctness in the validator.

Every test here encodes a fact about EVM execution, not an opinion:

- transfer() throws on failure -> the enclosing transaction reverts -> every
  state change in it is rolled back. A "permanent fund loss / locked funds /
  theft" claim about that path is contradicted by the source and downgraded.
- send()/call() return a bool and do NOT revert: an UNCHECKED result is a
  genuine loss risk (claim stays potential); a checked result (require/assert
  / inline guard) reverts and rolls back.
- A failing require/assert also reverts the whole transaction.
- try/catch swallows the failure without reverting the outer transaction, so
  a loss claim on that path is left open (potential, never silently cleared).
- Checks-Effects-Interactions: effect-before-interaction rejects a reentrancy
  claim; interaction-before-effect does not.
- An actionable POTENTIAL claim must carry the full evidence package
  (location, preconditions incl. attacker inputs, attack sequence, impact);
  otherwise it is downgraded to informational instead of inventing certainty.
"""

from __future__ import annotations

from agentsafe.agents.validation import ValidationAgent
from agentsafe.report import build_report
from agentsafe.schemas import (
    Finding,
    FindingStatus,
    LLMUsage,
    Severity,
)

ADDR = "0x" + "d0" * 20

WETH9_WITHDRAW = """pragma solidity ^0.8.0;

contract WETH9 {
    mapping(address => uint) public balanceOf;

    function withdraw(uint wad) public {
        require(balanceOf[msg.sender] >= wad);
        balanceOf[msg.sender] -= wad;
        msg.sender.transfer(wad);
    }
}
"""

SEND_UNCHECKED = """pragma solidity ^0.8.0;

contract S {
    mapping(address => uint) balances;

    function withdraw(uint a) public {
        balances[msg.sender] -= a;
        msg.sender.send(a);
    }
}
"""

SEND_CHECKED = """pragma solidity ^0.8.0;

contract S {
    mapping(address => uint) balances;

    function withdraw(uint a) public {
        balances[msg.sender] -= a;
        require(msg.sender.send(a), "send failed");
    }
}
"""

CALL_UNCHECKED = """pragma solidity ^0.8.0;

contract C {
    mapping(address => uint) balances;

    function withdraw(uint a) public {
        balances[msg.sender] -= a;
        (bool ok, ) = msg.sender.call{value: a}("");
    }
}
"""

CALL_CHECKED = """pragma solidity ^0.8.0;

contract C {
    mapping(address => uint) balances;

    function withdraw(uint a) public {
        balances[msg.sender] -= a;
        (bool ok, ) = msg.sender.call{value: a}("");
        require(ok, "transfer failed");
    }
}
"""

CALL_IN_TRY = """pragma solidity ^0.8.0;

contract C {
    mapping(address => uint) balances;

    function withdraw(uint a) public {
        balances[msg.sender] -= a;
        try payable(msg.sender).call{value: a}("") { } catch { }
    }
}
"""

REQUIRE_ONLY = """pragma solidity ^0.8.0;

contract R {
    mapping(address => uint) balances;

    function withdraw(uint a) public {
        require(balances[msg.sender] >= a, "insufficient");
        balances[msg.sender] -= a;
    }
}
"""

EFFECT_FIRST = """pragma solidity ^0.8.0;

contract E {
    mapping(address => uint) balances;

    function withdraw(uint a) public {
        balances[msg.sender] -= a;
        msg.sender.transfer(a);
    }
}
"""

INTERACTION_FIRST = """pragma solidity ^0.8.0;

contract I {
    mapping(address => uint) balances;

    function withdraw(uint a) public {
        (bool ok, ) = msg.sender.call{value: a}("");
        require(ok, "failed");
        balances[msg.sender] -= a;
    }
}
"""


def _segments(src: str, name: str) -> dict[str, str]:
    return {name: src}


def _claim(**kw) -> Finding:
    """A loss claim WITH the full evidence package (so the completeness gate
    is not what decides these tests)."""
    base = dict(
        title="Funds permanently locked after a transfer failure",
        severity="high",
        status=FindingStatus.LLM_SUGGESTED,
        source=["accounting"],
        description=(
            "If the recipient rejects the Ether transfer, the sender's balance "
            "stays deducted and the funds are permanently lost"
        ),
        evidence="msg.sender.transfer(wad);",
        preconditions="Attacker controls the receiving contract and makes "
                      "transfer() fail (e.g. reverting receive hook)",
        attack_scenario="1) withdraw(); 2) transfer() fails; 3) the deducted "
                        "balance is never restored",
        impact="Permanent loss of the withdrawn amount",
        file_path="WETH9.sol",
        line_start=8,
        confidence=0.8,
    )
    base.update(kw)
    return Finding(**base)


class TestTransferFailureRollback:
    def test_transfer_failure_claim_is_downgraded_not_confirmed(self):
        v = ValidationAgent()
        out = v.validate([_claim()], [], _segments(WETH9_WITHDRAW, "WETH9.sol"))
        assert out.confirmed == 0 and out.potential == 0
        assert out.informational == 1
        f = out.findings[0]
        assert f.status is FindingStatus.INFORMATIONAL
        assert f.severity is Severity.INFO
        assert f.metadata["validation"]["rule"] == "xf0_revert_rollback"
        assert f.validation_method == "deterministic_source_rules"
        # the original impact claim is preserved for auditability
        assert f.proposed_severity is Severity.HIGH
        # the contradiction quotes BOTH the debit and the reverting transfer
        blob = " ".join(f.contradicting_evidence)
        assert "balanceOf[msg.sender] -= wad;" in blob
        assert "msg.sender.transfer(wad);" in blob

    def test_weth9_withdraw_production_regression(self):
        """The exact production false positive: WETH9 withdraw() must never
        produce a confirmed/potential 'permanent fund loss' headline."""
        v = ValidationAgent()
        findings = [
            _claim(),
            _claim(
                title="Permanent fund loss: withdraw() debit is not rolled back",
                description=(
                    "msg.sender.transfer(wad) can fail and the balanceOf "
                    "deduction persists, so the user's funds are stolen"
                ),
                impact="User balance is permanently lost",
            ),
        ]
        out = v.validate(findings, [], _segments(WETH9_WITHDRAW, "WETH9.sol"))
        assert out.confirmed == 0
        assert out.potential == 0
        assert out.informational == 2

        report = build_report(
            address=ADDR,
            task_id="task-weth9-rollback",
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
            static_analysis_status="full",
        )
        # no fund-loss finding headlines as high/critical
        assert "critical" not in report.summary.by_severity
        assert "high" not in report.summary.by_severity
        # both claims describe the same root cause -> merged into one
        # informational entry, never a potential/confirmed fund-loss headline
        assert report.summary.total_findings == 1
        assert report.summary.by_status.get("informational") == 1
        assert report.summary.by_status.get("potential", 0) == 0
        assert report.summary.by_status.get("confirmed", 0) == 0

    def test_reentrancy_claim_on_rollback_path_still_rejected_by_cei(self):
        """A reentrancy claim on the same function is handled by the CEI rule
        (effect precedes interaction), not by the rollback rule."""
        v = ValidationAgent()
        out = v.validate(
            [
                _claim(
                    title="Reentrancy in withdraw()",
                    description="msg.sender.transfer(wad) enables reentrancy",
                    impact="Attacker re-enters withdraw()",
                )
            ],
            [],
            _segments(WETH9_WITHDRAW, "WETH9.sol"),
        )
        assert out.rejected == 1
        assert out.findings[0].metadata["validation"]["rule"] == "re0_cei_satisfied"


class TestSendAndCallSemantics:
    def test_unchecked_send_keeps_loss_claim_potential(self):
        """send() returns false instead of reverting: an unchecked result is a
        REAL loss risk - must stay an actionable candidate, not be cleared."""
        v = ValidationAgent()
        f = _claim(
            title="Funds permanently lost when send() fails",
            description=(
                "The return value of msg.sender.send(a) is ignored; when send "
                "fails the balance stays deducted and the funds are lost"
            ),
            evidence="msg.sender.send(a);",
            file_path="S.sol",
            line_start=7,
        )
        out = v.validate([f], [], _segments(SEND_UNCHECKED, "S.sol"))
        assert out.potential == 1
        f = out.findings[0]
        assert f.status is FindingStatus.POTENTIAL
        assert f.validation_result == "potential"

    def test_checked_send_rolls_back(self):
        v = ValidationAgent()
        f = _claim(
            title="Funds permanently lost when send() fails",
            description="msg.sender.send(a) may fail and the debit persists",
            evidence="require(msg.sender.send(a), \"send failed\");",
            file_path="S.sol",
            line_start=7,
        )
        out = v.validate([f], [], _segments(SEND_CHECKED, "S.sol"))
        assert out.informational == 1
        assert out.findings[0].metadata["validation"]["rule"] == "xf0_revert_rollback"

    def test_unchecked_call_keeps_loss_claim_potential(self):
        v = ValidationAgent()
        f = _claim(
            title="Funds permanently lost when call() fails",
            description=(
                "The bool returned by msg.sender.call{value: a} is ignored; a "
                "failed call leaves the debit in place and the funds are lost"
            ),
            evidence='(bool ok, ) = msg.sender.call{value: a}("");',
            file_path="C.sol",
            line_start=7,
        )
        out = v.validate([f], [], _segments(CALL_UNCHECKED, "C.sol"))
        assert out.potential == 1
        assert out.findings[0].status is FindingStatus.POTENTIAL

    def test_checked_call_rolls_back(self):
        v = ValidationAgent()
        f = _claim(
            title="Funds permanently lost when call() fails",
            description="msg.sender.call{value: a} may fail and the debit persists",
            evidence='require(ok, "transfer failed");',
            file_path="C.sol",
            line_start=8,
        )
        out = v.validate([f], [], _segments(CALL_CHECKED, "C.sol"))
        assert out.informational == 1
        assert out.findings[0].metadata["validation"]["rule"] == "xf0_revert_rollback"

    def test_try_catch_does_not_clear_the_claim(self):
        """try/catch swallows the failure: the outer tx does NOT revert, so the
        loss claim cannot be disproved and must stay open."""
        v = ValidationAgent()
        f = _claim(
            title="Funds permanently lost when call() fails",
            description=(
                "The call inside try/catch may fail; the catch block ignores it "
                "and the balance stays deducted, so the funds are lost"
            ),
            evidence='try payable(msg.sender).call{value: a}("") { } catch { }',
            file_path="C.sol",
            line_start=7,
        )
        out = v.validate([f], [], _segments(CALL_IN_TRY, "C.sol"))
        assert out.informational == 0
        assert out.potential == 1
        assert out.findings[0].metadata["validation"]["rule"] == "pt0_default"


class TestRequireRevertPropagation:
    def test_state_persisting_after_require_failure_is_contradicted(self):
        v = ValidationAgent()
        f = _claim(
            title="State persists after the require() check fails",
            description=(
                "When the require fails the revert is partial and the balance "
                "deduction persists, so the funds are permanently lost"
            ),
            evidence="balances[msg.sender] -= a;",
            file_path="R.sol",
            line_start=8,
        )
        out = v.validate([f], [], _segments(REQUIRE_ONLY, "R.sol"))
        assert out.informational == 1
        f = out.findings[0]
        assert f.metadata["validation"]["rule"] == "xf0_revert_rollback"
        assert "reverts the whole transaction" in f.metadata["validation"]["reason"]


class TestChecksEffectsInteractions:
    def test_effect_before_interaction_rejects_reentrancy(self):
        v = ValidationAgent()
        f = _claim(
            title="Reentrancy in withdraw()",
            description="balanceOf is decremented then Ether is sent; re-entry "
                        "could double-withdraw",
            evidence="msg.sender.transfer(a);",
            file_path="E.sol",
            line_start=7,
        )
        out = v.validate([f], [], _segments(EFFECT_FIRST, "E.sol"))
        assert out.rejected == 1
        f = out.findings[0]
        assert f.metadata["validation"]["rule"] == "re0_cei_satisfied"
        # the audit trail proves the ordering: effect line quoted before the
        # interaction line, with exact source locations
        assert "balances[msg.sender] -= a;" in f.metadata["validation"]["reason"]
        assert "msg.sender.transfer(a);" in f.metadata["validation"]["reason"]
        assert "E.sol:" in f.metadata["validation"]["reason"]

    def test_interaction_before_effect_keeps_reentrancy_potential(self):
        v = ValidationAgent()
        f = _claim(
            title="Reentrancy in withdraw()",
            description=(
                "The external call happens before balances is decremented; an "
                "attacker re-enters and withdraws repeatedly"
            ),
            evidence='(bool ok, ) = msg.sender.call{value: a}("");',
            file_path="I.sol",
            line_start=7,
        )
        out = v.validate([f], [], _segments(INTERACTION_FIRST, "I.sol"))
        assert out.potential == 1
        assert out.findings[0].status is FindingStatus.POTENTIAL
        # state-transition evidence is carried on the finding
        assert out.findings[0].attack_scenario


class TestCompletenessGate:
    def test_missing_attack_package_is_downgraded(self):
        """An actionable POTENTIAL claim must carry location, preconditions,
        attack sequence and impact. Missing pieces -> informational."""
        v = ValidationAgent()
        f = _claim(
            title="Authorization bypass in setFee()",
            description="setFee() can be called by anyone",
            evidence="function setFee(uint f) external { fee = f; }",
            preconditions="",
            attack_scenario="",
            impact="",
            file_path="V.sol",
            line_start=3,
        )
        src = "contract V { uint fee; function setFee(uint f) external { fee = f; } }"
        out = v.validate([f], [], {"V.sol": src})
        assert out.informational == 1
        res = out.findings[0]
        assert res.status is FindingStatus.INFORMATIONAL
        assert res.metadata["validation"]["rule"] == "pc0_incomplete_claim"
        reason = res.metadata["validation"]["reason"]
        assert "preconditions" in reason
        assert "attack execution sequence" in reason
        assert "actual impact" in reason

    def test_complete_package_stays_potential(self):
        v = ValidationAgent()
        f = _claim(
            title="Authorization bypass in setFee()",
            description="setFee() can be called by anyone",
            evidence="function setFee(uint f) external { fee = f; }",
            preconditions="No access modifier; any account can call setFee()",
            attack_scenario="1) attacker calls setFee(MAX); 2) fee changes "
                            "without authorization",
            impact="Attacker arbitrarily changes protocol fees",
            file_path="V.sol",
            line_start=3,
        )
        src = "contract V { uint fee; function setFee(uint f) external { fee = f; } }"
        out = v.validate([f], [], {"V.sol": src})
        assert out.potential == 1
        res = out.findings[0]
        assert res.status is FindingStatus.POTENTIAL
        assert res.metadata["validation"]["rule"] == "pt0_default"
        # the finding states HOW it was validated and the outcome
        assert res.validation_method == "evidence_state_machine"
        assert res.validation_result == "potential"
        # and every required field survives on the finding
        assert res.file_path and res.line_start
        assert res.preconditions and res.attack_scenario and res.impact
        assert res.evidence and res.location_status
