"""Server + payment acceptance: MCP tools via FastMCP in-memory client."""

import io
import json
import zipfile
from datetime import UTC

import httpx
import pytest
import respx
from fastmcp import Client

from agentsafe.config import Settings, SettingsError
from agentsafe.payment.x402_adapter import X402NotIntegratedError, X402PaymentAdapter
from agentsafe.server import build_server

ADDR = "0x" + "ab" * 20
GH = "https://api.github.com"
RPC = "https://rpc.test"
ETH = "https://api.etherscan.test/v2/api"


def _settings(**kw) -> Settings:
    base = {
        "INFURA_ETH_ENDPOINT": RPC,
        "ETHERSCAN_API_KEY": "k",
        "ETHERSCAN_BASE_URL": ETH,
        "GITHUB_TOKEN": "ghp-t",
        "GITHUB_REPO": "owner/repo",
        "LLM_PROVIDERS_JSON": json.dumps(
            [
                {
                    "name": "p",
                    "base_url": "https://llm.test/v1",
                    "api_key": "sk",
                    "model": "m",
                    "rpm_limit": 60,
                }
            ]
        ),
        "TASK_STORE": "memory",
        "PAYMENTS_ENABLED": False,
    }
    base.update(kw)
    return Settings.model_validate(base)


def _wire_dispatch_and_runs():
    """Capture the dispatched task_id, then surface a matching run."""
    from datetime import datetime, timedelta

    state: dict = {}
    created_at = (datetime.now(UTC) + timedelta(seconds=5)).isoformat()

    def capture_dispatch(request):
        state["task_id"] = json.loads(request.read())["inputs"]["task_id"]
        return httpx.Response(204)

    def runs(request):
        tid = state.get("task_id", "unknown")
        return httpx.Response(
            200,
            json={
                "workflow_runs": [
                    {
                        "id": 5,
                        "name": f"audit-{tid}",
                        "created_at": created_at,
                        "status": "in_progress",
                        "conclusion": None,
                    }
                ]
            },
        )

    respx.post(f"{GH}/repos/owner/repo/actions/workflows/audit.yml/dispatches").mock(
        side_effect=capture_dispatch
    )
    respx.get(f"{GH}/repos/owner/repo/actions/workflows/audit.yml/runs").mock(side_effect=runs)
    return state


def _report_zip(report: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("report.json", json.dumps(report))
    return buf.getvalue()


def _unwrap(result):
    data = getattr(result, "data", result)
    if hasattr(data, "model_dump"):
        data = data.model_dump()
    if isinstance(data, str):
        data = json.loads(data)
    return data


class TestPaymentAdapterFailClosed:
    def test_disabled_dev_mode_noop(self):
        adapter = X402PaymentAdapter(enabled=False)
        adapter.require_payment("audit")  # free in dev

    def test_enabled_without_sdk_refuses(self):
        with pytest.raises(X402NotIntegratedError, match="X402_SDK_VERSION"):
            X402PaymentAdapter(enabled=True)

    def test_enabled_with_sdk_still_refuses_until_phase12(self):
        with pytest.raises(X402NotIntegratedError, match="not implemented yet"):
            X402PaymentAdapter(enabled=True, sdk_version="1.2.3")

    def test_server_start_fails_when_payments_enabled_without_sdk(self):
        with pytest.raises(SettingsError, match="X402_SDK_VERSION"):
            build_server(_settings(PAYMENTS_ENABLED=True))


class TestServerTools:
    @respx.mock
    async def test_audit_contract_dispatch_flow(self):
        _wire_dispatch_and_runs()
        server = build_server(_settings())
        async with Client(server) as client:
            result = _unwrap(await client.call_tool("audit_contract", {"address": ADDR.upper()}))
        assert result["ok"] is True
        assert 8 <= len(result["task_id"]) <= 64
        assert result["state"] == "running"
        assert result["run_id"] == 5

    async def test_audit_contract_rejects_invalid_address(self):
        server = build_server(_settings())
        async with Client(server) as client:
            result = _unwrap(await client.call_tool("audit_contract", {"address": "0x12"}))
        assert result["ok"] is False
        assert result["error_code"] == "invalid_address"

    async def test_check_status_unknown_task(self):
        server = build_server(_settings())
        async with Client(server) as client:
            result = _unwrap(
                await client.call_tool("check_audit_status", {"task_id": "does-not-exist-123"})
            )
        assert result["ok"] is False
        assert result["error_code"] == "unknown_task"

    async def test_check_status_rejects_weird_task_id(self):
        server = build_server(_settings())
        async with Client(server) as client:
            result = _unwrap(await client.call_tool("check_audit_status", {"task_id": "x" * 200}))
        assert result["error_code"] == "invalid_task_id"

    @respx.mock
    async def test_get_contract_info(self):
        respx.post(RPC).mock(
            return_value=httpx.Response(
                200, json={"jsonrpc": "2.0", "id": 1, "result": "0x6080" + "ff" * 100}
            )
        )
        respx.get(ETH).mock(
            return_value=httpx.Response(
                200,
                json={
                    "status": "1",
                    "message": "OK",
                    "result": [
                        {"SourceCode": "", "ABI": "", "ContractName": "", "CompilerVersion": ""}
                    ],
                },
            )
        )
        server = build_server(_settings())
        async with Client(server) as client:
            result = _unwrap(await client.call_tool("get_contract_info", {"address": ADDR}))
        assert result["ok"] is True
        assert result["is_contract"] is True
        assert result["bytecode_size_bytes"] == 102
        assert result["verified_source"] is False

    @respx.mock
    async def test_status_completed_returns_report(self):
        state = _wire_dispatch_and_runs()
        report = {
            "address": ADDR,
            "chain": "ethereum-mainnet",
            "findings": [],
            "summary": {"total_findings": 0},
            "disclaimer": "AI-assisted risk screening, not a formal audit.",
        }
        server = build_server(_settings())

        async with Client(server) as client:
            created = _unwrap(await client.call_tool("audit_contract", {"address": ADDR}))
            assert created["ok"] is True
            task_id = created["task_id"]

        respx.get(f"{GH}/repos/owner/repo/actions/runs/5").mock(
            return_value=httpx.Response(
                200, json={"id": 5, "status": "completed", "conclusion": "success"}
            )
        )
        respx.get(f"{GH}/repos/owner/repo/actions/runs/5/artifacts").mock(
            return_value=httpx.Response(
                200,
                json={
                    "artifacts": [
                        {"id": 9, "name": f"audit-report-{task_id}", "expired": False, "run_id": 5}
                    ]
                },
            )
        )
        respx.get(f"{GH}/repos/owner/repo/actions/artifacts/9/zip").mock(
            return_value=httpx.Response(200, content=_report_zip(report))
        )

        async with Client(server) as client:
            status = _unwrap(await client.call_tool("check_audit_status", {"task_id": task_id}))
        assert status["ok"] is True
        assert status["state"] == "completed"
        assert status["report"]["address"] == ADDR
        assert state["task_id"] == task_id  # association captured end-to-end

    @respx.mock
    async def test_expired_artifact_reports_expired(self):
        _wire_dispatch_and_runs()
        server = build_server(_settings())

        async with Client(server) as client:
            created = _unwrap(await client.call_tool("audit_contract", {"address": ADDR}))
            task_id = created["task_id"]

        respx.get(f"{GH}/repos/owner/repo/actions/runs/5").mock(
            return_value=httpx.Response(
                200, json={"id": 5, "status": "completed", "conclusion": "success"}
            )
        )
        respx.get(f"{GH}/repos/owner/repo/actions/runs/5/artifacts").mock(
            return_value=httpx.Response(
                200,
                json={
                    "artifacts": [
                        {"id": 9, "name": f"audit-report-{task_id}", "expired": True, "run_id": 5}
                    ]
                },
            )
        )

        async with Client(server) as client:
            status = _unwrap(await client.call_tool("check_audit_status", {"task_id": task_id}))
        assert status["state"] == "expired"

    @respx.mock
    async def test_failed_run_maps_to_failed_state(self):
        _wire_dispatch_and_runs()
        server = build_server(_settings())

        async with Client(server) as client:
            created = _unwrap(await client.call_tool("audit_contract", {"address": ADDR}))
            task_id = created["task_id"]

        respx.get(f"{GH}/repos/owner/repo/actions/runs/5").mock(
            return_value=httpx.Response(
                200, json={"id": 5, "status": "completed", "conclusion": "failure"}
            )
        )

        async with Client(server) as client:
            status = _unwrap(await client.call_tool("check_audit_status", {"task_id": task_id}))
        assert status["state"] == "failed"
