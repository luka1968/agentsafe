"""Section 7 — EVM/Solidity execution semantics (deterministic).

Pins the semantics that most often cause false positives, with regression
tests for each:

- transfer() reverts and rolls back earlier state -> a "state persists after a
  failed transfer" claim is refuted;
- send() returns bool and does NOT revert -> a "failed send reverts" claim is
  refuted;
- low-level call() does NOT auto-revert -> a "call failure reverts" claim is
  refuted;
- revert/require/assert are atomic -> a "partial state persists after revert"
  claim is refuted;
- ETH transfer/send is distinguished from ERC20 transfer by argument shape;
- correct statements are NOT refuted.
"""

from __future__ import annotations

from agentsafe.agents.adversarial import AdversarialVerifier
from agentsafe.agents.evm_semantics import analyze_evm_calls, refute_evm_claim
from agentsafe.intel.extract import extract_contract_intel
from agentsafe.schemas import Finding, FindingStatus

TRANSFER_SRC = "\n".join(
    [
        "pragma solidity ^0.8.0;",                                   # 1
        "contract W {",                                              # 2
        "    mapping(address => uint256) balances;",                 # 3
        "    function withdraw(uint256 amt) external {",             # 4
        "        balances[msg.sender] -= amt;",                      # 5
        "        payable(msg.sender).transfer(amt);",                # 6
        "    }",                                                     # 7
        "}",                                                         # 8
    ]
)
SEND_SRC = "\n".join(
    [
        "pragma solidity ^0.8.0;",
        "contract S {",
        "    function pay(address to) external {",
        "        to.send(1);",
        "    }",
        "}",
    ]
)
CALL_SRC = "\n".join(
    [
        "pragma solidity ^0.8.0;",
        "contract C {",
        "    function f(address to) external {",
        '        to.call("");',
        "    }",
        "}",
    ]
)
REVERT_SRC = "\n".join(
    [
        "pragma solidity ^0.8.0;",
        "contract R {",
        "    uint256 private x;",
        "    function g(uint256 v) external {",
        '        require(v > 0, "bad");',
        "        x = v;",
        "    }",
        "}",
    ]
)


def _line_of(src: str, needle: str) -> int:
    for i, ln in enumerate(src.splitlines(), start=1):
        if needle in ln:
            return i
    raise AssertionError(needle)


class TestAnalyzeCalls:
    def test_eth_transfer_versus_erc20_transfer(self):
        assert analyze_evm_calls("payable(a).transfer(1);").eth_transfer is True
        assert analyze_evm_calls("token.transfer(to, amt);").eth_transfer is False

    def test_send_and_call_and_revert_detection(self):
        a = analyze_evm_calls('to.send(1); x.call{value: 1}(""); require(ok);')
        assert a.eth_send and a.low_level_call and a.reverts_control

    def test_send_return_checked(self):
        assert analyze_evm_calls('require(to.send(1), "x");').send_return_checked
        assert not analyze_evm_calls("to.send(1);").send_return_checked


class TestRefutations:
    def test_transfer_state_persists_is_refuted(self):
        claim = (
            "The balance is deducted and remains deducted when the ETH "
            "transfer() fails, leaving accounting inconsistent"
        )
        ref = refute_evm_claim("balances[a] -= amt; payable(a).transfer(amt);", claim)
        assert ref is not None and ref.rule == "evm0_transfer_reverts_rollback"

    def test_send_reverts_is_refuted(self):
        ref = refute_evm_claim(
            "to.send(1);", "a failed send() reverts the whole transaction"
        )
        assert ref is not None and ref.rule == "evm1_send_does_not_revert"

    def test_call_reverts_is_refuted(self):
        ref = refute_evm_claim(
            'to.call("");',
            "the low-level call failure reverts the whole transaction",
        )
        assert ref is not None and ref.rule == "evm2_call_does_not_revert"

    def test_partial_state_after_revert_is_refuted(self):
        ref = refute_evm_claim(
            'require(v > 0, "x"); x = v;',
            "after the require fails the state remains partially updated",
        )
        assert ref is not None and ref.rule == "evm3_revert_is_atomic"

    def test_correct_statements_are_not_refuted(self):
        # correct: transfer reverts and rolls back
        assert refute_evm_claim(
            "payable(a).transfer(1);",
            "the transfer reverts and rolls back the balance deduction",
        ) is None
        # correct: send return is unchecked (a real issue, not a false claim)
        assert refute_evm_claim(
            "to.send(1);", "the return value of send() is unchecked"
        ) is None
        # correct: revert is atomic
        assert refute_evm_claim(
            'require(v > 0, "x");', "a failed require reverts and rolls back all state"
        ) is None


class TestAdversarialIntegration:
    def test_persist_claim_refuted_and_semantics_recorded(self):
        intel = extract_contract_intel({"W.sol": TRANSFER_SRC})
        f = Finding(
            title="Balance persists after failed ETH transfer",
            severity="high",
            status=FindingStatus.POTENTIAL,
            source=["reentrancy"],
            description="the balance stays deducted when the transfer() fails",
            evidence="payable(msg.sender).transfer(amt);",
            file_path="W.sol",
            line_start=_line_of(TRANSFER_SRC, "payable(msg.sender).transfer"),
        )
        res = AdversarialVerifier().review(
            [], [f], {"W.sol": TRANSFER_SRC}, False, intel=intel
        )
        out = res.llm_findings[0]
        assert out.status is FindingStatus.REJECTED
        assert out.metadata["challenge"]["rule"] == "evm0_transfer_reverts_rollback"
        assert out.metadata["evm_semantics"]["eth_transfer"] is True
