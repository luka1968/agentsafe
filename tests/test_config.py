"""Phase 1 tests: configuration validation and fail-fast startup rules."""

import json

import pytest
from pydantic import ValidationError

from agentsafe.config import (
    LLMProviderConfig,
    Settings,
    SettingsError,
    mask_secret,
    validate_runtime_settings,
)

VALID_PROVIDER = {
    "name": "prov-a",
    "base_url": "https://api.example.com/v1",
    "api_key": "sk-test-123",
    "model": "test-model",
    "rpm_limit": 5,
}


def _settings(**overrides) -> Settings:
    base = {
        "INFURA_ETH_ENDPOINT": "https://mainnet.infura.io/v3/test",
        "ETHERSCAN_API_KEY": "test-key",
        "GITHUB_TOKEN": "ghp-test",
        "GITHUB_REPO": "owner/repo",
        "LLM_PROVIDERS_JSON": json.dumps([VALID_PROVIDER]),
    }
    base.update(overrides)
    return Settings.model_validate(base)


class TestSettingsDefaults:
    def test_payments_disabled_by_default(self):
        s = Settings()
        assert s.PAYMENTS_ENABLED is False

    def test_numeric_ranges_defaults(self):
        s = Settings()
        assert 1 <= s.LLM_GLOBAL_RPM <= 1000
        assert s.AUDIT_TIMEOUT_SECONDS >= 30
        assert s.ARTIFACT_RETENTION_DAYS >= 1

    def test_invalid_log_level_rejected(self):
        with pytest.raises(ValidationError):
            Settings.model_validate({"LOG_LEVEL": "VERBOSE"})

    def test_invalid_repo_format_rejected(self):
        with pytest.raises(ValidationError):
            Settings.model_validate({"GITHUB_REPO": "not-a-repo"})

    def test_workflow_file_path_traversal_rejected(self):
        with pytest.raises(ValidationError):
            Settings.model_validate({"GITHUB_WORKFLOW_FILE": "../evil.yml"})
        with pytest.raises(ValidationError):
            Settings.model_validate({"GITHUB_WORKFLOW_FILE": "/abs/audit.yml"})


class TestLLMProviderParsing:
    def test_valid_provider_list(self):
        s = _settings()
        providers = s.llm_providers()
        assert len(providers) == 1
        assert providers[0].name == "prov-a"
        assert providers[0].rpm_limit == 5

    def test_invalid_json_rejected(self):
        s = _settings(LLM_PROVIDERS_JSON="{not json")
        with pytest.raises(SettingsError, match="not valid JSON"):
            s.llm_providers()

    def test_missing_required_field_rejected(self):
        bad = dict(VALID_PROVIDER)
        del bad["api_key"]
        s = _settings(LLM_PROVIDERS_JSON=json.dumps([bad]))
        with pytest.raises(SettingsError, match="api_key"):
            s.llm_providers()

    def test_duplicate_provider_names_rejected(self):
        s = _settings(LLM_PROVIDERS_JSON=json.dumps([VALID_PROVIDER, VALID_PROVIDER]))
        with pytest.raises(SettingsError, match="unique"):
            s.llm_providers()

    def test_provider_base_url_must_be_http(self):
        bad = dict(VALID_PROVIDER, base_url="ftp://nope")
        with pytest.raises(ValidationError):
            LLMProviderConfig.model_validate(bad)


class TestSecretHygiene:
    def test_mask_secret_never_leaks_value(self):
        masked = mask_secret("sk-super-secret-key")
        assert "super-secret" not in masked
        assert masked.startswith("<redacted:")

    def test_provider_repr_has_no_api_key(self):
        p = LLMProviderConfig.model_validate(VALID_PROVIDER)
        r = repr(p)
        assert "sk-test-123" not in r
        assert "<redacted>" in r

    def test_secrets_report_masks_everything(self):
        s = _settings()
        report = s.secrets_report()
        assert "test-key" not in report["ETHERSCAN_API_KEY"]
        assert "ghp-test" not in report["GITHUB_TOKEN"]


class TestStartupValidation:
    def test_full_config_passes(self):
        validate_runtime_settings(_settings())

    def test_missing_multiple_settings_reports_all(self):
        s = Settings(
            INFURA_ETH_ENDPOINT="",
            ETHERSCAN_API_KEY="",
            GITHUB_TOKEN="",
            GITHUB_REPO="",
            LLM_PROVIDERS_JSON="[]",
        )
        with pytest.raises(SettingsError) as exc:
            validate_runtime_settings(s)
        msg = str(exc.value)
        assert "INFURA_ETH_ENDPOINT" in msg
        assert "ETHERSCAN_API_KEY" in msg
        assert "GITHUB_TOKEN" in msg
        assert "LLM_PROVIDERS_JSON" in msg

    def test_payments_enabled_without_sdk_fails_closed(self):
        s = _settings(PAYMENTS_ENABLED=True)
        with pytest.raises(SettingsError, match="X402_SDK_VERSION"):
            validate_runtime_settings(s)

    def test_payments_enabled_without_pay_to_fails_closed(self):
        s = _settings(PAYMENTS_ENABLED=True, X402_SDK_VERSION="1.2.3")
        with pytest.raises(SettingsError, match="X402_PAY_TO"):
            validate_runtime_settings(s)

    def test_optional_groups_can_be_relaxed(self):
        s = Settings(
            INFURA_ETH_ENDPOINT="",
            ETHERSCAN_API_KEY="",
            LLM_PROVIDERS_JSON="[]",
            GITHUB_TOKEN="",
            GITHUB_REPO="",
        )
        # LLM+GitHub not required in this profile; RPC/Etherscan still required.
        with pytest.raises(SettingsError, match="INFURA"):
            validate_runtime_settings(s, require_llm=False, require_github=False)
        with pytest.raises(SettingsError, match="ETHERSCAN"):
            validate_runtime_settings(s, require_llm=False, require_github=False)
