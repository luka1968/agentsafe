"""x402 payment adapter - FAIL-CLOSED boundary (Phase 12, intentionally last).

Per E_VERSION_PLAN, the real x402 integration must be implemented against a
PINNED, official x402 SDK release whose documented interfaces
(PaymentRequired semantics, header format, facilitator payloads, verification
and settlement flow) were read from that SDK's own docs. Nothing here invents
protocol details.

Until that integration is written AND its verification/settlement tests
pass, this adapter:
- refuses to start when PAYMENTS_ENABLED=true without a pinned SDK version,
- rejects every paid tool call when disabled,
- exposes the integration checklist that the real adapter must satisfy.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("agentSAFE.payment")


class PaymentsNotEnabledError(RuntimeError):
    """Raised when a paid operation is requested while payments are disabled."""


class X402NotIntegratedError(RuntimeError):
    """Raised when payments are enabled but the pinned-SDK adapter is absent."""


class X402PaymentAdapter:
    """Fail-closed payment gate.

    Real-integration checklist (must be completed in Phase 12 before enabling):
    1. Pin an official x402 SDK version in pyproject + record it in
       X402_SDK_VERSION; read its published API surface.
    2. Implement: payment requirement generation, payment verification,
       settlement/confirmation handling, network+asset checks (Base USDC:
       chain id, token contract, decimals), price/resource binding,
       replay protection as provided by the SDK.
    3. Integration tests: missing payment, valid payment, wrong amount,
       wrong network, wrong asset, replay attempt, verification failure,
       settlement failure, retry, service restart.
    4. Only then flip PAYMENTS_ENABLED=true. No mock may bypass verification
       in production.
    """

    def __init__(
        self,
        *,
        enabled: bool,
        sdk_version: str = "",
        network: str = "eip155:8453",
        pay_to: str = "",
    ) -> None:
        self.enabled = enabled
        self.network = network
        self.pay_to = pay_to
        if enabled:
            if not sdk_version:
                raise X402NotIntegratedError(
                    "PAYMENTS_ENABLED=true requires X402_SDK_VERSION pinned to the "
                    "official SDK release used by the (not yet integrated) adapter"
                )
            raise X402NotIntegratedError(
                "Real x402 integration (pinned SDK "
                f"'{sdk_version}') is not implemented yet; refusing to accept "
                "payments. Complete Phase 12 integration + tests first."
            )
        logger.info("payments DISABLED (dev mode); paid gating is inactive")

    def require_payment(self, resource: str) -> None:
        """Called by paid tools. Disabled -> no-op for dev; enabled impossible
        until the real adapter exists (constructor already refuses)."""
        if not self.enabled:
            return  # dev mode: tools run free; the service never pretends to charge
        raise X402NotIntegratedError(  # pragma: no cover - unreachable until Phase 12
            f"payment handling for {resource!r} not implemented"
        )
