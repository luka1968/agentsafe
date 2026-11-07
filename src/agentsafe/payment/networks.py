"""Centralized, typed x402 network/payment configuration (Phase: x402 V2 foundation).

Single source of truth for everything the payment layer knows about a
supported network. Token metadata (USDC contract, decimals, EIP-712 domain
name/version) is loaded from the pinned official SDK asset registry
(``x402.mechanisms.evm.default_assets``) at construction time and cross-checked
- NEVER hardcoded here and never taken from client input - so the domain the
browser signs always matches what the facilitator verifies.

Fail-closed rules enforced here and by callers:
  - an unknown network identifier is a construction error, not a fallback;
  - a configured USDC asset that disagrees with the SDK registry is an error;
  - the environment mode must agree with the chain (84532 testnet, 8453 mainnet);
  - the facilitator must advertise the exact scheme at protocol version 2 for
    every advertised network before the server offers it (checked in
    x402_adapter via x402ResourceServer.get_supported_kind, the official API).

This module must stay import-light (stdlib + pinned SDK only): config.py and
the payment adapter both depend on it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import x402
from x402.mechanisms.evm.default_assets import get_default_asset

from agentsafe.schemas import normalize_address

#: Official x402 protocol version served by the pinned SDK. All advertised
#: payment options, accepted payloads, and capability checks use exactly this
#: version; a mismatch with the SDK constant fails at import time.
X402_PROTOCOL_VERSION: int = x402.X402_VERSION
if X402_PROTOCOL_VERSION != 2:  # pragma: no cover - pin guard
    raise RuntimeError(
        f"x402 V2 foundation requires protocol version 2, SDK reports "
        f"{X402_PROTOCOL_VERSION!r}"
    )

#: The only payment scheme this service implements (EIP-3009
#: transferWithAuthorization; deterministic, no approvals, no custody).
SUPPORTED_SCHEMES: tuple[str, ...] = ("exact",)

_EIP155_RE = re.compile(r"^eip155:(\d+)$")
_EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


class NetworkConfigError(ValueError):
    """A network/payment configuration is invalid. Fail closed at startup."""


@dataclass(frozen=True, slots=True)
class NetworkPaymentConfig:
    """Typed, immutable payment configuration for ONE network.

    Fields map 1:1 to the required configuration surface (network
    identifier, chain id, display name, USDC contract + decimals, payment
    recipient, facilitator URL, enabled schemes, environment mode).
    """

    identifier: str  # CAIP-2, e.g. "eip155:84532"
    chain_id: int
    display_name: str
    usdc_address: str
    usdc_decimals: int
    usdc_name: str  # EIP-712 domain `name` the facilitator verifies
    usdc_version: str  # EIP-712 domain `version`
    pay_to: str
    facilitator_url: str
    schemes: tuple[str, ...]
    environment: str  # "testnet" | "mainnet"

    @property
    def is_testnet(self) -> bool:
        return self.environment == "testnet"

    @property
    def is_mainnet(self) -> bool:
        return self.environment == "mainnet"


def _environment_for_chain(chain_id: int) -> str:
    """Environment mode derived from the chain id (single truth).

    84532 (Base Sepolia) is the only testnet this service knows; every other
    chain is a mainnet. Unknown chains never reach here: the SDK asset
    registry lookup in build_network_config fails closed first, and the
    PRIMARY network is additionally restricted to 8453/84532 by settings
    validation.
    """
    return "testnet" if chain_id == 84532 else "mainnet"


def build_network_config(
    identifier: str,
    pay_to: str,
    facilitator_url: str,
    *,
    asset: str = "",
    display_name: str = "",
) -> NetworkPaymentConfig:
    """Build and fully validate the payment config for one network.

    `asset` may be empty (use the SDK registry USDC) or must match the
    registry entry for that network exactly - a diverging asset fails closed
    because a wrong token address would silently redirect real payments.
    """
    if not isinstance(identifier, str) or not identifier.strip():
        raise NetworkConfigError("network identifier must be a non-empty string")
    identifier = identifier.strip()
    match = _EIP155_RE.match(identifier)
    if not match:
        raise NetworkConfigError(
            f"network identifier {identifier!r} is not an eip155:<chain_id> CAIP-2 id"
        )
    chain_id = int(match.group(1))

    try:
        registry = get_default_asset(identifier)
    except Exception as exc:  # noqa: BLE001 - registry miss must fail closed
        raise NetworkConfigError(
            f"network {identifier!r} has no USDC entry in the pinned x402 asset "
            f"registry: {exc}"
        ) from exc

    usdc = str(registry.get("asset", "")).strip()
    if not _EVM_ADDRESS_RE.match(usdc):
        raise NetworkConfigError(
            f"SDK registry returned an invalid USDC address for {identifier!r}: {usdc!r}"
        )
    if asset and asset.strip() and asset.strip().lower() != usdc.lower():
        raise NetworkConfigError(
            f"configured asset {asset!r} for {identifier!r} does not match the "
            f"official USDC contract {usdc!r}; refusing to advertise a payment "
            f"option with a diverging token"
        )

    environment = _environment_for_chain(chain_id)
    try:
        pay_to = normalize_address(pay_to)
    except ValueError as exc:
        raise NetworkConfigError(f"payment recipient for {identifier!r}: {exc}") from exc

    if not facilitator_url or not facilitator_url.strip():
        raise NetworkConfigError(f"facilitator URL for {identifier!r} is required")
    facilitator_url = facilitator_url.strip()
    if not facilitator_url.startswith(("https://", "http://")):
        raise NetworkConfigError(
            f"facilitator URL for {identifier!r} must be an http(s) URL"
        )

    if not SUPPORTED_SCHEMES:
        raise NetworkConfigError("no payment schemes configured")  # pragma: no cover

    return NetworkPaymentConfig(
        identifier=identifier,
        chain_id=chain_id,
        display_name=display_name.strip() or ("Base" if environment == "mainnet" else "Base Sepolia (testnet)"),
        usdc_address=usdc,
        usdc_decimals=int(registry.get("decimals", 6)),
        usdc_name=str(registry.get("name", "")),
        usdc_version=str(registry.get("version", "2")),
        pay_to=pay_to,
        facilitator_url=facilitator_url,
        schemes=SUPPORTED_SCHEMES,
        environment=environment,
    )


def testnet_config(pay_to: str, facilitator_url: str) -> NetworkPaymentConfig:
    """Complete, separate Base Sepolia (testnet) payment configuration."""
    return build_network_config("eip155:84532", pay_to, facilitator_url)


def mainnet_config(pay_to: str, facilitator_url: str) -> NetworkPaymentConfig:
    """Complete, separate Base (mainnet) payment configuration.

    Building the config does NOT enable mainnet payments: advertisement is
    additionally gated by X402_ALLOW_MAINNET at startup validation.
    """
    return build_network_config("eip155:8453", pay_to, facilitator_url)
