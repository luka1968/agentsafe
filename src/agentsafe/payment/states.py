"""Payment state machine — AgentSafe x402 (PROMPT 5).

The selected flow is the official exact/EIP-3009 **authorization** flow:
verify -> resource (dispatch) -> settle after-handler. Only the states this
flow actually traverses are used; the prompt's suggested REFUND_*/MANUAL_REVIEW
states are intentionally NOT part of this machine because:

- the exact-EVM scheme provides no refund primitive (it is a single
  transferWithAuthorization; there is no cancel/refund path),
- ambiguity is handled by RECONCILIATION instead of a manual-review state:
  a row stuck in SETTLEMENT_PENDING with a stored transaction hash is
  reconciled to SETTLED; anything else is exposed for operator inspection.

State flow (terminal failure paths omitted for readability):

    CREATED ──> PAYMENT_REQUIRED ──> SIGNATURE_RECEIVED ──> VERIFIED
                                                                │
    VERIFIED ──> RESOURCE_PROCESSING ──> SETTLEMENT_PENDING ──> SETTLED ──> COMPLETED

  - SIGNATURE_RECEIVED / VERIFIED / RESOURCE_PROCESSING / SETTLEMENT_PENDING
    may all transition to FAILED (verify failed, dispatch failed, settle failed).
  - SETTLED is a terminal *funds* state: an audit that fails AFTER a successful
    settlement keeps the payment record SETTLED (never marked unpaid), per the
    credit/refund policy in REFUND_POLICY.md.
"""

from __future__ import annotations

from enum import StrEnum


class PaymentStatus(StrEnum):
    CREATED = "created"
    PAYMENT_REQUIRED = "payment_required"
    SIGNATURE_RECEIVED = "signature_received"
    VERIFIED = "verified"
    SETTLEMENT_PENDING = "settlement_pending"
    SETTLED = "settled"
    RESOURCE_PROCESSING = "resource_processing"
    COMPLETED = "completed"
    FAILED = "failed"


#: States actually used by the exact/EIP-3009 flow. Kept as one source of
#: truth so schema and transitions cannot drift.
USED_STATES: frozenset[PaymentStatus] = frozenset(PaymentStatus)


#: Allowed transitions: a missing key/entry means the move is illegal.
_ALLOWED: dict[PaymentStatus, set[PaymentStatus]] = {
    PaymentStatus.CREATED: {
        PaymentStatus.PAYMENT_REQUIRED,
        PaymentStatus.FAILED,
    },
    PaymentStatus.PAYMENT_REQUIRED: {
        PaymentStatus.SIGNATURE_RECEIVED,
        PaymentStatus.FAILED,  # terms expired
    },
    PaymentStatus.SIGNATURE_RECEIVED: {
        PaymentStatus.VERIFIED,
        PaymentStatus.FAILED,  # verification failed
    },
    PaymentStatus.VERIFIED: {
        PaymentStatus.RESOURCE_PROCESSING,
        PaymentStatus.FAILED,  # dispatch failed
    },
    PaymentStatus.RESOURCE_PROCESSING: {
        PaymentStatus.SETTLEMENT_PENDING,
        PaymentStatus.FAILED,  # resource (dispatch) failed
    },
    PaymentStatus.SETTLEMENT_PENDING: {
        PaymentStatus.SETTLED,  # settle confirmed
        PaymentStatus.FAILED,  # settle rejected / timed out
    },
    PaymentStatus.SETTLED: {
        PaymentStatus.COMPLETED,  # audit completed
        # NOTE: an audit failing after settlement leaves the payment at
        # SETTLED — the record is preserved, never silently unpaid.
    },
    PaymentStatus.COMPLETED: set(),
    PaymentStatus.FAILED: set(),  # terminal
}


class InvalidPaymentTransition(ValueError):
    """Illegal payment-state transition (also raised on a forked/lost race)."""


def can_transition(current: PaymentStatus, target: PaymentStatus) -> bool:
    """Whether `current -> target` is legal in the exact-flow machine."""
    allow = _ALLOWED.get(current)
    return allow is not None and target in allow


def sources_for(target: PaymentStatus) -> tuple[PaymentStatus, ...]:
    """Allowed source states for a target state (for atomic SQL guards)."""
    return tuple(src for src, targets in _ALLOWED.items() if target in targets)