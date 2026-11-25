"""Section 8 — real EVM PoC execution (eth-tester/py-evm + solc).

These tests execute Solidity in-memory and assert the exploit is REALLY
reproduced on a vulnerable contract, and is NOT "reproduced" on a CEI-correct
control (a PoC that fired there would be a false positive). They are skipped
when the optional 'poc' extra is not installed; the quality gate reports the
absence honestly rather than fabricating a result.
"""

from __future__ import annotations

import pytest

from agentsafe.validation.evm_poc import (
    evm_backend_available,
    run_reentrancy_poc,
    run_reentrancy_poc_safe,
)

pytestmark = pytest.mark.skipif(
    not evm_backend_available(),
    reason="EVM PoC backend (eth-tester/py-evm + solc) not installed; "
    "install the 'poc' extra",
)


class TestReentrancyPoC:
    def test_vulnerable_reentrancy_is_reproduced_with_impact(self):
        ex = run_reentrancy_poc()
        assert ex.result == "passed"
        assert ex.impact_demonstrated is True
        # real on-chain metrics are recorded, not invented
        assert int(ex.metrics["victim_final_wei"]) == 0
        assert int(ex.metrics["victim_seeded_wei"]) == 5 * 10**18
        assert int(ex.metrics["attacker_contract_final_wei"]) > int(
            ex.metrics["attacker_deposited_wei"]
        )

    def test_cei_correct_control_is_not_reproduced(self):
        ex = run_reentrancy_poc_safe()
        # The attacker must NOT be able to drain a CEI-correct victim.
        assert ex.impact_demonstrated is False

    def test_backend_reports_availability(self):
        assert evm_backend_available() is True
