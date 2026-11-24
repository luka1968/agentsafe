"""Section 17 — payment and existing product behavior are PRESERVED.

Guards the invariants this security-engine upgrade must not change. These are
behavioral assertions on the real modules (no payment code was modified by the
upgrade; `git diff` shows nothing under payment/, pricing.py, server.py,
config.py).
"""

from __future__ import annotations

import pytest

from agentsafe import pricing
from agentsafe.config import Settings
from agentsafe.payment.states import PaymentStatus, can_transition
from agentsafe.report import build_report
from agentsafe.report_render import render_html
from agentsafe.schemas import LLMUsage

PAY_TO = "0x" + "11" * 20
FACILITATOR = "https://facilitator.example"


class TestPricingPreserved:
    def test_tiers_are_the_advertised_table(self):
        assert pricing.AUDIT_PRICING_TIERS == (
            (100, "$0.50"), (500, "$2.50"), (1000, "$5.00"), (5000, "$25.00"),
        )
        assert pricing.MAX_AUDIT_SOURCE_LINES == 5000

    def test_tier_boundaries_and_over_max(self):
        assert pricing.audit_price_for_lines(1) == "$0.50"
        assert pricing.audit_price_for_lines(100) == "$0.50"
        assert pricing.audit_price_for_lines(101) == "$2.50"
        assert pricing.audit_price_for_lines(5000) == "$25.00"
        with pytest.raises(pricing.ContractTooLargeError):
            pricing.audit_price_for_lines(5001)
        # custom-pricing row is advertised for oversized contracts
        assert any(t.get("price") == "custom"
                   for t in pricing.pricing_summary())


class TestConfigDefaultsPreserved:
    def test_x402_defaults(self):
        # Assert the CODE defaults (a constructed Settings may load a local
        # .env / environment overrides; the defaults are what must be preserved).
        d = Settings.model_fields
        assert d["X402_NETWORK"].default == "eip155:84532"
        assert d["X402_PRICE"].default == "$0.01"
        assert d["X402_SOURCE_RETRIEVAL_PRICE"].default == "$0.01"
        assert d["X402_REST_PRICE"].default == "$3.00"
        assert d["X402_TESTNET_PRICE"].default == "$0.10"

    def test_supported_networks_unchanged(self):
        assert Settings.X402_NETWORK_TESTNET == "eip155:84532"
        assert Settings.X402_NETWORK_MAINNET == "eip155:8453"


class TestNetworkAndUsdcHandlingPreserved:
    def test_base_mainnet_and_sepolia_configs(self):
        pytest.importorskip("x402")
        from agentsafe.payment.networks import (
            NetworkConfigError,
            build_network_config,
            mainnet_config,
            testnet_config,
        )

        tn = testnet_config(PAY_TO, FACILITATOR)
        assert tn.chain_id == 84532 and tn.identifier == "eip155:84532"
        assert tn.schemes == ("exact",)
        assert tn.usdc_decimals == 6          # USDC decimal handling unchanged
        assert tn.environment == "testnet"

        mn = mainnet_config(PAY_TO, FACILITATOR)
        assert mn.chain_id == 8453 and mn.identifier == "eip155:8453"
        assert mn.usdc_decimals == 6
        assert mn.environment == "mainnet"

        # unknown network fails closed (never a silent fallback)
        with pytest.raises(NetworkConfigError):
            build_network_config("eip155:99999", PAY_TO, FACILITATOR)


class TestPaymentStateMachinePreserved:
    def test_failed_is_terminal_and_never_completes(self):
        assert can_transition(PaymentStatus.FAILED, PaymentStatus.COMPLETED) is False
        assert can_transition(PaymentStatus.FAILED, PaymentStatus.SETTLED) is False

    def test_completed_is_terminal_no_recharge(self):
        for target in PaymentStatus:
            assert can_transition(PaymentStatus.COMPLETED, target) is False

    def test_settlement_flow_and_retry_safety(self):
        # a settled payment can only COMPLETE - it is never marked unpaid again
        assert can_transition(PaymentStatus.SETTLED, PaymentStatus.COMPLETED) is True
        assert can_transition(PaymentStatus.SETTLED, PaymentStatus.PAYMENT_REQUIRED) is False
        assert can_transition(PaymentStatus.SETTLED, PaymentStatus.CREATED) is False
        # the happy path is intact
        assert can_transition(PaymentStatus.CREATED, PaymentStatus.PAYMENT_REQUIRED)
        assert can_transition(PaymentStatus.VERIFIED, PaymentStatus.RESOURCE_PROCESSING)


class TestPartialAuditNotSuccessful:
    def test_partial_audit_state_is_reported_partial(self):
        rep = build_report(
            address=PAY_TO, task_id="t", is_verified_source=True,
            tool_findings=[], llm_findings=[], tools_executed=["slither"],
            tools_failed=["mythril"], tool_versions={}, llm_usage=LLMUsage(),
            limitations=["partial failures: a tool did not run"],
            errors=[], execution_time_seconds=1.0, audit_state="partial",
            static_analysis_status="partial",
        )
        assert rep.summary.audit_state == "partial"
        html = render_html(rep)
        assert "PARTIAL" in html
        # never a "safe"/"passed" verdict string anywhere in the artifact
        blob = rep.model_dump_json()
        assert '"safe"' not in blob
        assert "security audit passed" not in blob.lower()
        assert "not a formal security audit" in rep.disclaimer
