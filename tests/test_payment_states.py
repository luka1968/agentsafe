"""Payment state machine unit tests (PROMPT 5).

Pure logic - always runs. Covers legal transitions for the exact/EIP-3009
(authorization) flow, illegal moves, terminal states, and the reconciliation
rule (audit failure AFTER settlement preserves the SETTLED record).
"""

from __future__ import annotations

import pytest

from agentsafe.payment.states import (
    PaymentStatus as PS,
    can_transition,
    sources_for,
)

FLOW = [
    (PS.CREATED, PS.PAYMENT_REQUIRED),
    (PS.PAYMENT_REQUIRED, PS.SIGNATURE_RECEIVED),
    (PS.SIGNATURE_RECEIVED, PS.VERIFIED),
    (PS.VERIFIED, PS.RESOURCE_PROCESSING),
    (PS.RESOURCE_PROCESSING, PS.SETTLEMENT_PENDING),
    (PS.SETTLEMENT_PENDING, PS.SETTLED),
    (PS.SETTLED, PS.COMPLETED),
]


class TestLegalFlow:
    @pytest.mark.parametrize("src,tgt", FLOW)
    def test_authorization_flow_is_legal(self, src: PS, tgt: PS):
        assert can_transition(src, tgt), f"{src.value} -> {tgt.value} must be legal"

    def test_every_flow_target_reports_its_sources(self):
        for src, tgt in FLOW:
            assert src in sources_for(tgt), f"{src.value} must be a source of {tgt.value}"


class TestIllegalMoves:
    @pytest.mark.parametrize(
        "src,tgt",
        [
            (PS.VERIFIED, PS.COMPLETED),  # skips settlement
            (PS.VERIFIED, PS.SETTLED),  # skips resource+settlement_pending
            (PS.CREATED, PS.VERIFIED),  # skips signature
            (PS.SETTLED, PS.SETTLEMENT_PENDING),  # backwards
            (PS.COMPLETED, PS.COMPLETED),  # terminal
            (PS.FAILED, PS.SETTLED),  # terminal
            (PS.COMPLETED, PS.FAILED),  # no failure after completion
            (PS.PAYMENT_REQUIRED, PS.RESOURCE_PROCESSING),
        ],
    )
    def test_illegal_transitions_rejected(self, src: PS, tgt: PS):
        assert not can_transition(src, tgt), f"{src.value} -> {tgt.value} must be illegal"


class TestFailurePaths:
    @pytest.mark.parametrize(
        "src",
        [
            PS.CREATED,
            PS.PAYMENT_REQUIRED,
            PS.SIGNATURE_RECEIVED,
            PS.VERIFIED,
            PS.RESOURCE_PROCESSING,
            PS.SETTLEMENT_PENDING,
        ],
    )
    def test_each_in_flight_state_may_fail(self, src: PS):
        assert can_transition(src, PS.FAILED), f"{src.value} -> failed must be legal"


class TestSettlementPreservation:
    def test_audit_failure_after_settlement_preserves_record(self):
        # PROMPT 3/5: an audit failing after a successful settlement must NOT
        # move the payment away from SETTLED (record preserved; credit policy
        # governs, never 'silently unpaid').
        assert not can_transition(PS.SETTLED, PS.FAILED)
        assert can_transition(PS.SETTLED, PS.COMPLETED)

    def test_sources_of_settled_is_exactly_settlement_pending(self):
        # The only legal path INTO settled is via settlement_pending, so an
        # on-chain confirmation is always recorded through the pending guard.
        assert sources_for(PS.SETTLED) == (PS.SETTLEMENT_PENDING,)
