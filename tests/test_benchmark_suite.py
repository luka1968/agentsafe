"""Section 14 — categorized benchmark & regression suite.

Drives the deterministic decision plane over vulnerable AND secure/trap
contracts across all required categories and asserts metrics plus the mandatory
WETH9 guarantees. Repeatable, offline, no paid calls.
"""

from __future__ import annotations

import sys
from pathlib import Path

BENCH = Path(__file__).resolve().parents[1] / "benchmarks"
sys.path.insert(0, str(BENCH))

import categorized_suite as S  # noqa: E402

from agentsafe.agents.deployment import (  # noqa: E402
    DISPOSITION_INFORMATIONAL,
    build_deployment_context,
    finding_disposition,
)
from agentsafe.intel.extract import extract_contract_intel  # noqa: E402
from agentsafe.intel.proxy import ProxyClass, classify_contracts  # noqa: E402
from agentsafe.schemas import FindingStatus  # noqa: E402

WETH_SRC = S.WETH_FIXTURE


class TestSuiteShape:
    def test_all_required_categories_present(self):
        required = {
            "reentrancy", "cross_function", "access_control", "initialization",
            "accounting", "arithmetic", "oracle", "signature_replay",
            "token_integration", "denial_of_service", "cross_contract",
            "business_logic", "false_positive_trap", "solidity_version",
        }
        cats = {c.category for c in S.CASES}
        assert required <= cats

    def test_no_execution_failures(self):
        r = S.evaluate()
        assert r["n_errors"] == 0
        assert r["n_categories"] == 14


class TestMetrics:
    def test_aggregate_is_strong_and_fp_free(self):
        r = S.evaluate()
        agg = r["aggregate"]
        assert agg["fp"] == 0                       # no fabricated vulnerabilities
        assert agg["precision"] == 1.0
        assert agg["recall"] == 1.0                 # vulnerable cases not cleared
        assert agg["f1"] == 1.0
        assert agg["false_positive_rate"] == 0.0
        assert all(row["ok"] for row in r["cases"])

    def test_metric_math(self):
        rows = [
            {"expected": True, "predicted": True},
            {"expected": True, "predicted": False},
            {"expected": False, "predicted": True},
            {"expected": False, "predicted": False},
        ]
        m = S.metrics(rows)
        assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (1, 1, 1, 1)
        assert m["precision"] == 0.5 and m["recall"] == 0.5 and m["f1"] == 0.5
        assert m["false_positive_rate"] == 0.5

    def test_confirmed_reproducibility_reported_honestly(self):
        from agentsafe.validation.evm_poc import evm_backend_available

        r = S.evaluate()
        rate = r["confirmed_reproducibility_rate"]
        assert rate in (0.0, 1.0)
        # 1.0 only when a real EVM backend reproduced the reference scenario
        assert rate == (1.0 if evm_backend_available() else 0.0)


class TestSecureContractsNotFabricated:
    def test_every_secure_case_is_not_actionable(self):
        r = S.evaluate()
        for row in r["cases"]:
            if row["kind"] == "secure":
                assert row["predicted"] is False, row["id"]
                assert row["statuses"], row["id"]
                assert all(
                    s in ("rejected", "informational", "unverified", "needs_manual_review")
                    for s in row["statuses"]
                ), (row["id"], row["statuses"])


# ---------------------------------------------------------------------------
# mandatory WETH9 regression — the five must-not guarantees
# ---------------------------------------------------------------------------

def _claim(**kw):
    from agentsafe.schemas import Finding

    base = dict(
        title="issue", severity="high", status=FindingStatus.LLM_SUGGESTED,
        source=["benchmark"], description="d", evidence="msg.sender.transfer(wad);",
        file_path="C.sol", line_start=S._line_of(WETH_SRC, "msg.sender.transfer(wad);"),
        preconditions="attacker is an external account",
        attack_scenario="1) call withdraw()", impact="funds",
    )
    base.update(kw)
    return Finding(**base)


class TestWETH9MandatoryRegression:
    SEG = {"WETH.sol": WETH_SRC}

    def test_1_transfer_failure_does_not_leave_state_applied(self):
        out = S.decide([_claim(
            title="Balance persists after failed ETH transfer",
            description="the balance is deducted and remains deducted when transfer() fails",
        )], self.SEG, compiler="v0.4.18")
        assert out[0].status is FindingStatus.REJECTED
        assert (out[0].metadata.get("challenge") or {}).get("rule") == (
            "evm0_transfer_reverts_rollback"
        )

    def test_2_mapping_balances_cannot_overflow_each_other(self):
        out = S.decide([_claim(
            title="Integer Overflow in deposit()",
            severity="critical",
            description="different users' balance additions could theoretically "
            "overflow each other; arithmetic lacks SafeMath",
            evidence="balanceOf[msg.sender] += msg.value;",
            line_start=S._line_of(WETH_SRC, "balanceOf[msg.sender] += msg.value;"),
        )], self.SEG, compiler="v0.4.18")
        assert out[0].status is FindingStatus.INFORMATIONAL
        assert (out[0].metadata.get("validation") or {}).get("rule") == (
            "ov0_theoretical_only"
        )

    def test_3_economically_impossible_balance_is_not_a_practical_exploit(self):
        out = S.decide([_claim(
            title="Integer Overflow to an economically impossible balance",
            severity="critical",
            description="the balance mapping can overflow to an impossibly large "
            "value; arithmetic lacks SafeMath",
            evidence="balanceOf[msg.sender] += msg.value;",
            line_start=S._line_of(WETH_SRC, "balanceOf[msg.sender] += msg.value;"),
        )], self.SEG, compiler="v0.4.18")
        assert out[0].status is not FindingStatus.CONFIRMED
        assert out[0].status is FindingStatus.INFORMATIONAL

    def test_4_generic_old_compiler_warning_is_not_a_vulnerability(self):
        intel = extract_contract_intel(self.SEG)
        ctx = build_deployment_context(
            address="0x" + "c0" * 20, is_verified_source=True,
            compiler_version="v0.4.18", intel=intel,
        )
        warn = _claim(title="solc-version: pragma ^0.4.18 is outdated",
                      detector_id="solc-version", severity="low")
        # detector id alone classifies it as code quality
        assert finding_disposition(warn, ctx) == DISPOSITION_INFORMATIONAL

    def test_5_weth9_is_not_classified_as_a_proxy_without_evidence(self):
        intel = extract_contract_intel(self.SEG)
        classes = classify_contracts(intel)
        weth = next(c for c in classes if c.contract == "WETH9")
        assert weth.classification == ProxyClass.REGULAR
        assert weth.pattern == "none"
