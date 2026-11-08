"""Tests for the centralized x402 V2 payment network configuration (PROMPT 2).

Covers: typed network config built from the official SDK asset registry,
environment-mode consistency, fail-closed validation on any divergence,
the startup facilitator capability check, and protocol version pinning.
"""

from __future__ import annotations

import pytest
from x402.mechanisms.evm.default_assets import get_default_asset

from agentsafe.config import Settings, SettingsError
from agentsafe.payment import networks as net_mod
from agentsafe.payment.networks import (
    X402_PROTOCOL_VERSION,
    NetworkConfigError,
    build_network_config,
)

import x402

FACILITATOR = "https://x402.org/facilitator"
PAY_TO = "0x" + "ab" * 20


class TestProtocolVersion:
    def test_version_is_official_v2(self):
        # The foundation pins protocol version 2 and mirrors the SDK constant.
        assert X402_PROTOCOL_VERSION == 2
        assert x402.X402_VERSION == 2

    def test_schemes_are_exact_only(self):
        from agentsafe.payment.networks import SUPPORTED_SCHEMES

        assert SUPPORTED_SCHEMES == ("exact",)


class TestNetworkConfigs:
    def test_testnet_config_matches_sdk_registry(self):
        cfg = net_mod.testnet_config(PAY_TO, FACILITATOR)
        reg = get_default_asset("eip155:84532")
        assert cfg.identifier == "eip155:84532"
        assert cfg.chain_id == 84532
        assert cfg.environment == "testnet"
        assert cfg.is_testnet and not cfg.is_mainnet
        assert cfg.usdc_address.lower() == reg["asset"].lower()
        assert cfg.usdc_decimals == reg["decimals"] == 6
        assert cfg.usdc_name == reg["name"]
        assert cfg.usdc_version == reg["version"]
        assert cfg.pay_to == PAY_TO.lower()
        assert cfg.facilitator_url == FACILITATOR
        assert cfg.schemes == ("exact",)

    def test_mainnet_config_matches_sdk_registry(self):
        cfg = net_mod.mainnet_config(PAY_TO, FACILITATOR)
        reg = get_default_asset("eip155:8453")
        assert cfg.identifier == "eip155:8453"
        assert cfg.chain_id == 8453
        assert cfg.environment == "mainnet"
        assert cfg.is_mainnet and not cfg.is_testnet
        assert cfg.usdc_address.lower() == reg["asset"].lower()
        assert cfg.usdc_name == reg["name"] == "USD Coin"
        assert cfg.usdc_decimals == 6

    def test_mainnet_and_testnet_are_fully_separate(self):
        t = net_mod.testnet_config(PAY_TO, FACILITATOR)
        m = net_mod.mainnet_config(PAY_TO, FACILITATOR)
        assert t.usdc_address.lower() != m.usdc_address.lower()
        assert t.chain_id != m.chain_id
        assert t.environment != m.environment
        assert t.display_name != m.display_name

    def test_unknown_network_fails_closed(self):
        with pytest.raises(NetworkConfigError):
            build_network_config("eip155:999999", PAY_TO, FACILITATOR)

    def test_non_eip155_identifier_fails(self):
        with pytest.raises(NetworkConfigError):
            build_network_config("solana:mainnet", PAY_TO, FACILITATOR)

    def test_diverging_usdc_asset_fails_closed(self):
        wrong = "0x" + "de" * 20
        with pytest.raises(NetworkConfigError, match="does not match the official USDC"):
            build_network_config("eip155:84532", PAY_TO, FACILITATOR, asset=wrong)

    def test_registry_usdc_asset_is_accepted_case_insensitive(self):
        reg = get_default_asset("eip155:84532")["asset"]
        cfg = build_network_config("eip155:84532", PAY_TO, FACILITATOR, asset=reg.lower())
        assert cfg.usdc_address.lower() == reg.lower()

    def test_invalid_pay_to_fails(self):
        with pytest.raises(NetworkConfigError):
            build_network_config("eip155:84532", "not-an-address", FACILITATOR)

    def test_empty_facilitator_fails(self):
        with pytest.raises(NetworkConfigError):
            build_network_config("eip155:84532", PAY_TO, "  ")

    def test_non_https_facilitator_rejected(self):
        with pytest.raises(NetworkConfigError):
            build_network_config("eip155:84532", PAY_TO, "ftp://x")


class TestStartupCapabilityCheck:
    """The adapter must refuse to advertise a network the facilitator does
    not support (exact scheme at protocol version 2) - fail closed."""

    def _build(self, supported_networks: list[str]):
        from agentsafe.payment import x402_adapter
        from agentsafe.payment.x402_adapter import X402PaymentAdapter

        class FakeKind:
            x402_version = X402_PROTOCOL_VERSION
            scheme = "exact"

        class FakeServer:
            def __init__(self, supported):
                self._supported = supported

            def register(self, network, scheme):
                pass

            def initialize(self):
                pass

            def get_supported_kind(self, version, network, scheme):
                if version == X402_PROTOCOL_VERSION and network in self._supported and scheme == "exact":
                    return FakeKind()
                return None

            def build_payment_requirements(self, config):
                from x402.schemas import PaymentRequirements

                return [
                    PaymentRequirements.model_validate(
                        {
                            "scheme": "exact",
                            "network": config.network,
                            "asset": "0x" + "11" * 20,
                            "amount": "100",
                            "pay_to": config.pay_to,
                            "max_timeout_seconds": 300,
                            "extra": {"name": "USDC", "version": "2"},
                        }
                    )
                ]

        return x402_adapter, X402PaymentAdapter, FakeServer

    def test_unsupported_network_fails_startup(self, monkeypatch):
        x402_adapter, adapter_cls, fake = self._build([])
        monkeypatch.setattr(x402, "x402ResourceServer", lambda _facilitator: fake([]), raising=True)
        with pytest.raises(Exception, match="does not support scheme"):
            adapter_cls(
                enabled=True,
                sdk_version="2.25.0",
                network="eip155:84532",
                pay_to=PAY_TO,
                facilitator_url=FACILITATOR,
                price="$0.01",
            )

    def test_supported_network_advertises(self, monkeypatch):
        x402_adapter, adapter_cls, fake = self._build([])
        monkeypatch.setattr(
            x402, "x402ResourceServer", lambda _f: fake(["eip155:84532"]), raising=True
        )
        adapter = adapter_cls(
            enabled=True,
            sdk_version="2.25.0",
            network="eip155:84532",
            pay_to=PAY_TO,
            facilitator_url=FACILITATOR,
            price="$0.01",
        )
        assert adapter.accepts
        assert adapter.accepts[0].network == "eip155:84532"
        assert adapter.accepts[0].scheme == "exact"


class TestSettingsNetworkConfigs:
    def _base(self, **kw) -> Settings:
        base = {
            "INFURA_ETH_ENDPOINT": "https://rpc.test",
            "ETHERSCAN_API_KEY": "k",
            "GITHUB_TOKEN": "t",
            "GITHUB_REPO": "owner/repo",
            "LLM_PROVIDERS_JSON": '[{"name":"p","base_url":"https://llm.test/v1","api_key":"sk","model":"m","rpm_limit":60}]',
            "TASK_STORE": "memory",
            "PAYMENTS_ENABLED": True,
            "X402_NETWORK": "eip155:84532",
            "X402_PAY_TO": PAY_TO,
            "X402_FACILITATOR_URL": FACILITATOR,
            "X402_SDK_VERSION": "2.25.0",
        }
        base.update(kw)
        return Settings(_env_file=None, **base)

    def test_disabled_payments_returns_empty(self):
        s = self._base(PAYMENTS_ENABLED=False)
        assert s.payment_network_configs() == []

    def test_testnet_primary_builds_one_config(self):
        s = self._base()
        cfgs = s.payment_network_configs()
        assert [c.identifier for c in cfgs] == ["eip155:84532"]

    def test_extras_are_validated_against_registry(self):
        arb_usdc = get_default_asset("eip155:42161")["asset"]
        s = self._base(
            X402_ALLOW_MAINNET="true",
            X402_NETWORKS_JSON=(
                '{"eip155:42161": {"asset": "%s", "pay_to": "%s"}}' % (arb_usdc, PAY_TO)
            ),
        )
        cfgs = s.payment_network_configs()
        assert [c.identifier for c in cfgs] == ["eip155:84532", "eip155:42161"]

    def test_diverging_extra_asset_raises_settings_error(self):
        wrong = "0x" + "de" * 20
        s = self._base(
            X402_NETWORKS_JSON=(
                '{"eip155:42161": {"asset": "%s", "pay_to": "%s"}}' % (wrong, PAY_TO)
            ),
        )
        with pytest.raises(SettingsError, match="does not match the official USDC"):
            s.payment_network_configs()

    def test_validate_runtime_rejects_diverging_asset(self):
        wrong = "0x" + "de" * 20
        s = self._base(
            X402_NETWORKS_JSON=(
                '{"eip155:42161": {"asset": "%s", "pay_to": "%s"}}' % (wrong, PAY_TO)
            ),
        )
        from agentsafe.config import validate_runtime_settings

        with pytest.raises(SettingsError, match="does not match the official USDC"):
            validate_runtime_settings(s)

    def test_extra_mainnet_requires_allow_mainnet(self):
        usdc = get_default_asset("eip155:8453")["asset"]
        s = self._base(
            X402_ALLOW_MAINNET="false",
            X402_NETWORKS_JSON=(
                '{"eip155:8453": {"asset": "%s", "pay_to": "%s"}}' % (usdc, PAY_TO)
            ),
        )
        from agentsafe.config import validate_runtime_settings

        with pytest.raises(SettingsError, match="requires X402_ALLOW_MAINNET"):
            validate_runtime_settings(s)


class TestProductionControls:
    """PROMPT 8: production kill-switch / environment-separation controls."""

    def _base(self, **kw) -> Settings:
        base = {
            "INFURA_ETH_ENDPOINT": "https://rpc.test",
            "ETHERSCAN_API_KEY": "k",
            "GITHUB_TOKEN": "t",
            "GITHUB_REPO": "owner/repo",
            "LLM_PROVIDERS_JSON": '[{"name":"p","base_url":"https://llm.test/v1","api_key":"sk","model":"m","rpm_limit":60}]',
            "TASK_STORE": "memory",
            "PAYMENTS_ENABLED": True,
            "X402_NETWORK": "eip155:84532",
            "X402_PAY_TO": PAY_TO,
            "X402_FACILITATOR_URL": FACILITATOR,
            "X402_SDK_VERSION": "2.25.0",
        }
        base.update(kw)
        return Settings(_env_file=None, **base)

    def test_environment_must_agree_with_network(self):
        from agentsafe.config import validate_runtime_settings

        # testnet network + mainnet env -> refuse (never mix configs)
        s = self._base(X402_ENVIRONMENT="mainnet")
        with pytest.raises(SettingsError, match="contradicts"):
            validate_runtime_settings(s)
        # mainnet network + testnet env -> refuse
        s = self._base(X402_NETWORK="eip155:8453", X402_ALLOW_MAINNET=True,
                       X402_ENVIRONMENT="testnet")
        with pytest.raises(SettingsError, match="contradicts"):
            validate_runtime_settings(s)

    def test_environment_matching_network_is_accepted(self):
        from agentsafe.config import validate_runtime_settings

        s = self._base(X402_ENVIRONMENT="testnet")
        validate_runtime_settings(s)  # must not raise

    def test_mainnet_requires_explicit_allow(self):
        from agentsafe.config import validate_runtime_settings

        s = self._base(X402_NETWORK="eip155:8453", X402_ALLOW_MAINNET=False)
        with pytest.raises(SettingsError, match="X402_ALLOW_MAINNET"):
            validate_runtime_settings(s)

    def test_sepolia_recipient_override_applies(self):
        sep_recipient = "0x" + "cd" * 20
        s = self._base(X402_SEPOLIA_RECIPIENT=sep_recipient)
        cfg = s.payment_network_configs()[0]
        assert cfg.pay_to == sep_recipient.lower()

    def test_mainnet_recipient_override_is_separate(self):
        mainnet_recipient = "0x" + "ee" * 20
        sep_recipient = "0x" + "cd" * 20
        s = self._base(
            X402_MAINNET_RECIPIENT=mainnet_recipient,
            X402_SEPOLIA_RECIPIENT=sep_recipient,
        )
        # primary is testnet -> sepolia recipient applies
        assert s.payment_network_configs()[0].pay_to == sep_recipient.lower()

    def test_invalid_network_recipient_fails(self):
        from agentsafe.config import validate_runtime_settings

        s = self._base(X402_SEPOLIA_RECIPIENT="not-an-address")
        with pytest.raises(SettingsError, match="EVM address"):
            validate_runtime_settings(s)

    def test_invalid_facilitator_url_fails(self):
        from agentsafe.config import validate_runtime_settings

        s = self._base(X402_SEPOLIA_FACILITATOR_URL="ftp://x")
        with pytest.raises(SettingsError, match=r"http\(s\) URL"):
            validate_runtime_settings(s)

    def test_missing_shared_recipient_disables(self):
        # PAYMENTS_ENABLED but no recipient anywhere -> must fail closed.
        from agentsafe.config import validate_runtime_settings

        s = self._base(X402_PAY_TO="", X402_SEPOLIA_RECIPIENT="")
        with pytest.raises(SettingsError):
            validate_runtime_settings(s)
