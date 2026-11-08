"""x402 REST endpoint tests (POST /api/audit + GET /openapi.json).

These endpoints back the x402scan / indexer discovery flow:
  - GET  /openapi.json  -> machine-readable OpenAPI discovery document
  - POST /api/audit     -> official x402 v2 HTTP wire protocol:
        no payment     -> 402 + PAYMENT-REQUIRED header
        valid payment  -> dispatch + settle-after-handler (PAYMENT-RESPONSE)
        replay         -> 402 (payload never accepted twice)

The facilitator HTTP API is mocked via respx (same infrastructure as
test_payments.py). The REST route runs against the FastMCP http_app via an
in-process httpx ASGI transport - custom routes do not need the MCP session
manager, so no lifespan bootstrap is involved here.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest
import respx

from agentsafe.server import build_server
from tests.test_payments import (
    ADDR,
    FAC,
    GH,
    _mock_facilitator,
    _mock_source,
    _settings,
    _wire_dispatch_and_runs,
)

try:  # decode/encode helpers from the pinned SDK
    from x402.http import (
        decode_payment_required_header,
        encode_payment_signature_header,
    )
    from x402.schemas import PaymentPayload
except ImportError:  # pragma: no cover - SDK is pinned in requirements
    decode_payment_required_header = None
    encode_payment_signature_header = None
    PaymentPayload = None

ETH = "https://api.etherscan.test/v2/api"


def _http_client(server) -> httpx.AsyncClient:
    app = server.http_app(stateless_http=True, json_response=True)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test")


async def _payment_header_from_402(client: httpx.AsyncClient, **body_overrides) -> str:
    """Run the real client dance: unpaid POST -> decode PAYMENT-REQUIRED ->
    echo the advertised terms back as a PAYMENT-SIGNATURE header."""
    first = await client.post("/api/audit", json={"address": ADDR})
    assert first.status_code == 402, first.text
    header = first.headers.get("payment-required")
    assert header, f"no PAYMENT-REQUIRED header: {dict(first.headers)}"
    required = decode_payment_required_header(header)
    accepted = required.accepts[0].model_dump(by_alias=True, exclude_none=True)
    accepted.update(body_overrides)
    payload = PaymentPayload.model_validate(
        {
            "x402Version": 2,
            "payload": {"kind": "exact/eip3009", "data": {"signature": "0x" + "22" * 32}},
            "accepted": accepted,
            "resource": {
                "url": "https://test/api/audit",
                "description": "",
                "mimeType": "application/json",
            },
        }
    )
    return encode_payment_signature_header(payload)


class TestOpenApiDiscovery:
    @pytest.mark.respx
    async def test_openapi_served_and_crawler_ready(self, respx_mock):
        server = build_server(_settings(PAYMENTS_ENABLED=False))
        async with _http_client(server) as client:
            resp = await client.get("/openapi.json")
        assert resp.status_code == 200
        spec = resp.json()
        assert spec["openapi"].startswith("3.0")
        assert "/api/audit" in spec["paths"]
        op = spec["paths"]["/api/audit"]["post"]
        # x402scan parses the structured extension
        ext = op["x-402-payment"]
        assert ext["network"] == "eip155:8453"
        assert ext["price"] == "$3.00"
        assert ext["maxAmountRequired"] == "3000000"  # $3.00 at 6 decimals
        assert ext["scheme"] == "exact"
        assert ext["payTo"].startswith("0x")
        # payment terms also human-readable in the description
        assert "3.00" in op["description"]
        # the 402 response is documented
        assert "402" in op["responses"]
        # x402scan discovery requirements: paid classification inputs
        assert op["security"] == [{"x402": []}]  # non-empty -> not "unprotected"
        assert op["x-payment-info"] == {
            "price": "3.00",
            "currency": "USD",
            "protocols": ["x402"],
        }
        assert spec["components"]["securitySchemes"]["x402"]["type"] == "http"
        # ownership / contact surfacing for the x402scan listing
        contact = spec["info"]["contact"]
        assert "@" in contact["email"]

    async def test_openapi_file_is_valid_json_on_disk(self):
        from agentsafe.server import _OPENAPI_FILE

        spec = json.loads(_OPENAPI_FILE.read_text(encoding="utf-8"))
        assert spec["info"]["title"].startswith("agentSAFE")
        assert spec["info"]["contact"]["email"]

    @pytest.mark.respx
    async def test_favicon_served_at_api_root(self, respx_mock):
        """x402scan surfaces /favicon.ico in listings; it must exist."""
        server = build_server(_settings(PAYMENTS_ENABLED=False))
        async with _http_client(server) as client:
            resp = await client.get("/favicon.ico")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("image/x-icon")
        # ICO magic: reserved 0 + type 1
        assert resp.content[:4] == b"\x00\x00\x01\x00"

    @pytest.mark.respx
    async def test_logo_png_served_for_logotype_fields(self, respx_mock):
        """Directory listings' 'Logotype URL' fields prefer a square PNG."""
        server = build_server(_settings(PAYMENTS_ENABLED=False))
        async with _http_client(server) as client:
            resp = await client.get("/logo.png")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("image/png")
        # PNG magic + dimensions via header bytes (IHDR width/height BE u32)
        assert resp.content[:8] == b"\x89PNG\r\n\x1a\n"
        assert resp.content[16:24] == (512).to_bytes(4, "big") * 2


class TestRestAuditFlow:
    @respx.mock
    async def test_unpaid_request_gets_official_402(self):
        routes = _mock_facilitator()
        server = build_server(_settings())
        async with _http_client(server) as client:
            resp = await client.post("/api/audit", json={"address": ADDR})
        assert resp.status_code == 402
        assert "payment-required" in resp.headers
        body = resp.json()
        assert body["x402Version"] == 2
        assert body["accepts"][0]["scheme"] == "exact"
        assert body["accepts"][0]["amount"] == "100000"  # testnet primary $0.10
        assert body["accepts"][0]["payTo"].lower() == _settings().X402_PAY_TO.lower()
        assert body["accepts"][0]["network"] == "eip155:84532"
        # no dispatch happened
        assert routes["supported"].call_count == 1  # startup only

    @respx.mock
    async def test_multichain_402_advertises_per_chain_prices(self):
        """REST 402 advertises every configured chain with its own amount:
        mainnets at the flat $3.00, a testnet at its per-chain $0.0001
        override. The client can pick whichever network it wants to pay on."""
        routes = _mock_facilitator()
        routes["supported"].mock(
            return_value=httpx.Response(
                200,
                json={
                    "kinds": [
                        {"x402Version": 2, "scheme": "exact", "network": "eip155:8453", "extra": None},
                        {"x402Version": 2, "scheme": "exact", "network": "eip155:84532", "extra": None},
                    ],
                    "extensions": [],
                },
            )
        )
        server = build_server(
            _settings(
                X402_NETWORK="eip155:8453",
                X402_ALLOW_MAINNET=True,
                X402_NETWORKS_JSON=(
                    '{"eip155:84532": {"asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e", '
                    '"pay_to": "0x' + "ef" * 20 + '", "price": "$0.0001"}}'
                ),
            )
        )
        async with _http_client(server) as client:
            resp = await client.post("/api/audit", json={"address": ADDR})
        assert resp.status_code == 402
        body = resp.json()
        assert [a["network"] for a in body["accepts"]] == ["eip155:8453", "eip155:84532"]
        assert body["accepts"][0]["amount"] == "3000000"  # $3.00 flat
        assert body["accepts"][1]["amount"] == "100"  # $0.0001 testnet
        # Each accept carries the authoritative EIP-712 domain params the
        # frontend must sign with (Base mainnet "USD Coin", Base Sepolia
        # testnet "USDC") so the client never hardcodes a token name.
        assert body["accepts"][0].get("extra", {}).get("name") == "USD Coin"
        assert body["accepts"][0].get("extra", {}).get("version") == "2"
        assert body["accepts"][1].get("extra", {}).get("name") == "USDC"
        assert body["accepts"][1].get("extra", {}).get("version") == "2"

    @respx.mock
    async def test_paid_request_dispatches_and_settles(self):
        _mock_facilitator()
        gh_state = _wire_dispatch_and_runs()
        server = build_server(_settings())
        async with _http_client(server) as client:
            header = await _payment_header_from_402(client)
            resp = await client.post(
                "/api/audit",
                json={"address": ADDR},
                headers={"PAYMENT-SIGNATURE": header},
            )
        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert body["ok"] is True
        assert body["state"] == "running"
        assert "settlement_error" not in body
        # official settlement receipt header present
        assert "payment-response" in resp.headers
        # audit was really dispatched to GitHub Actions
        assert "task_id" in gh_state

    @respx.mock
    async def test_replayed_payment_is_rejected(self):
        _mock_facilitator()
        _wire_dispatch_and_runs()
        server = build_server(_settings())
        async with _http_client(server) as client:
            header = await _payment_header_from_402(client)
            first = await client.post(
                "/api/audit", json={"address": ADDR}, headers={"PAYMENT-SIGNATURE": header}
            )
            assert first.status_code == 202
            replay = await client.post(
                "/api/audit", json={"address": ADDR}, headers={"PAYMENT-SIGNATURE": header}
            )
        assert replay.status_code == 402
        assert replay.json()["error_code"] == "payment_replay"

    @respx.mock
    async def test_oversized_contract_never_settles(self):
        """MAINNET: the flat $3.00 fee covers <=500 lines; a bigger contract
        is rejected BEFORE settlement so no funds ever move. Testnet gets a
        relaxed cap (see test_rest_testnet_oversized_allowed), mainnet keeps
        the commercial flat-fee cap."""
        routes = _mock_facilitator(networks=["eip155:8453", "eip155:84532"])  # mocks 10-line source; override below
        respx.get(ETH).mock(
            return_value=httpx.Response(
                200,
                json={
                    "status": "1",
                    "message": "OK",
                    "result": [
                        {
                            "SourceCode": "pragma solidity ^0.8.20;\n" + "uint256 v;\n" * 899,
                            "ContractName": "C",
                            "CompilerVersion": "v0.8.20+commit.a1b79de6",
                            "OptimizationUsed": "0",
                            "Runs": "",
                            "ABI": "[]",
                            "Proxy": "0",
                            "Implementation": "",
                        }
                    ],
                },
            )
        )
        respx.post(f"{FAC}/settle").mock(
            return_value=httpx.Response(200, json={"success": True, "transaction": "0x" + "11" * 32})
        )
        _wire_dispatch_and_runs()
        # MAINNET: keeps the 500-line flat-fee cap.
        server = build_server(_settings(X402_NETWORK="eip155:8453", X402_ALLOW_MAINNET=True))
        async with _http_client(server) as client:
            header = await _payment_header_from_402(client)
            resp = await client.post(
                "/api/audit", json={"address": ADDR}, headers={"PAYMENT-SIGNATURE": header}
            )
        assert resp.status_code == 422
        body = resp.json()
        assert body["error_code"] == "REST_FLAT_FEE_LINE_LIMIT"
        # Actionable guidance: the caller must be told the exact alternative,
        # that nothing was charged, and where to go next.
        assert body["source_lines"] == 900
        assert body["flat_fee_max_lines"] == 500
        assert body["mcp_tier_price"] == "$5.00"  # 501-1000 tier
        assert body["mcp_tool"] == "audit_contract"
        assert body["mcp_endpoint"] == "/mcp"
        assert body["charged"] is False
        assert "No payment was taken" in body["message"]
        assert "audit_contract" in body["message"]
        assert "$5.00" in body["message"]
        # settle endpoint was NEVER called: verify-only, no funds moved
        assert routes["settle"].call_count == 0
        assert resp.headers.get("payment-response") is None

    @respx.mock
    async def test_rest_testnet_oversized_allowed(self):
        """TESTNET: the flat fee cap is relaxed (X402_REST_TESTNET_MAX_LINES)
        so larger contracts can be audited end-to-end on the free test
        channel. 900 lines on Base Sepolia dispatches (202) instead of 422."""
        routes = _mock_facilitator()
        respx.get(ETH).mock(
            return_value=httpx.Response(
                200,
                json={
                    "status": "1",
                    "message": "OK",
                    "result": [
                        {
                            "SourceCode": "pragma solidity ^0.8.20;\n" + "uint256 v;\n" * 899,
                            "ContractName": "C",
                            "CompilerVersion": "v0.8.20+commit.a1b79de6",
                            "OptimizationUsed": "0",
                            "Runs": "",
                            "ABI": "[]",
                            "Proxy": "0",
                            "Implementation": "",
                        }
                    ],
                },
            )
        )
        respx.post(f"{FAC}/settle").mock(
            return_value=httpx.Response(200, json={"success": True, "transaction": "0x" + "11" * 32})
        )
        _wire_dispatch_and_runs()
        server = build_server(_settings())  # default: Base Sepolia testnet
        async with _http_client(server) as client:
            header = await _payment_header_from_402(client)
            resp = await client.post(
                "/api/audit", json={"address": ADDR}, headers={"PAYMENT-SIGNATURE": header}
            )
        assert resp.status_code == 202
        assert routes["settle"].call_count == 1
        assert resp.headers.get("payment-response") is not None

    @respx.mock
    async def test_rest_testnet_over_5000_still_rejected(self):
        """TESTNET cap is 5000; a 5100-line contract is still refused before
        settlement, so nothing moves even on the free channel."""
        routes = _mock_facilitator()
        respx.get(ETH).mock(
            return_value=httpx.Response(
                200,
                json={
                    "status": "1",
                    "message": "OK",
                    "result": [
                        {
                            "SourceCode": "pragma solidity ^0.8.20;\n" + "uint256 v;\n" * 5099,
                            "ContractName": "C",
                            "CompilerVersion": "v0.8.20+commit.a1b79de6",
                            "OptimizationUsed": "0",
                            "Runs": "",
                            "ABI": "[]",
                            "Proxy": "0",
                            "Implementation": "",
                        }
                    ],
                },
            )
        )
        respx.post(f"{FAC}/settle").mock(
            return_value=httpx.Response(200, json={"success": True, "transaction": "0x" + "11" * 32})
        )
        _wire_dispatch_and_runs()
        server = build_server(_settings())
        async with _http_client(server) as client:
            header = await _payment_header_from_402(client)
            resp = await client.post(
                "/api/audit", json={"address": ADDR}, headers={"PAYMENT-SIGNATURE": header}
            )
        assert resp.status_code == 422
        body = resp.json()
        assert body["error_code"] == "REST_FLAT_FEE_LINE_LIMIT"
        assert body["source_lines"] == 5100
        assert body["flat_fee_max_lines"] == 5000
        assert body["charged"] is False
        assert routes["settle"].call_count == 0

    @respx.mock
    async def test_dispatch_failure_never_settles(self):
        _mock_facilitator()
        respx.post(f"{GH}/repos/owner/repo/actions/workflows/audit.yml/dispatches").mock(
            return_value=httpx.Response(403, json={"message": "forbidden"})
        )
        server = build_server(_settings())
        async with _http_client(server) as client:
            header = await _payment_header_from_402(client)
            resp = await client.post(
                "/api/audit", json={"address": ADDR}, headers={"PAYMENT-SIGNATURE": header}
            )
        assert resp.status_code == 502
        assert resp.json()["error_code"] == "dispatch_failed"
        assert "payment-response" not in resp.headers

    @respx.mock
    async def test_unpaid_gate_precedes_body_validation(self):
        """x402 fail-closed semantics: an unpaid caller gets the 402 payment
        gate BEFORE any request-body validation, so it learns nothing about
        the paid resource for free."""
        _mock_facilitator()
        server = build_server(_settings())
        async with _http_client(server) as client:
            resp = await client.post(
                "/api/audit", content=b"not-json", headers={"content-type": "application/json"}
            )
        assert resp.status_code == 402

    @respx.mock
    async def test_paid_request_with_bad_address_is_rejected(self):
        """A verified payment with a malformed address is rejected without
        dispatch or settlement (funds never move)."""
        _mock_facilitator()
        _wire_dispatch_and_runs()
        server = build_server(_settings())
        async with _http_client(server) as client:
            header = await _payment_header_from_402(client)
            resp = await client.post(
                "/api/audit", json={"address": "0x123"}, headers={"PAYMENT-SIGNATURE": header}
            )
        assert resp.status_code == 400
        assert resp.json()["error_code"] == "invalid_address"

    @respx.mock
    async def test_dev_mode_invalid_body_and_address(self):
        """Dev mode validates the body directly (no payment gate)."""
        _mock_source()
        server = build_server(_settings(PAYMENTS_ENABLED=False))
        async with _http_client(server) as client:
            bad_json = await client.post(
                "/api/audit", content=b"not-json", headers={"content-type": "application/json"}
            )
            bad_addr = await client.post("/api/audit", json={"address": "0x123"})
        assert bad_json.status_code == 400
        assert bad_addr.status_code == 400
        assert bad_addr.json()["error_code"] == "invalid_address"

    @respx.mock
    async def test_dev_mode_dispatches_free(self):
        """Payments disabled (dev): no 402, direct free dispatch - mirrors
        the free MCP tools so local testing works end-to-end."""
        _mock_source()
        gh_state = _wire_dispatch_and_runs()
        server = build_server(_settings(PAYMENTS_ENABLED=False))
        async with _http_client(server) as client:
            resp = await client.post("/api/audit", json={"address": ADDR})
        assert resp.status_code == 202, resp.text
        assert resp.json()["ok"] is True
        assert "task_id" in gh_state


class TestPaymentErrorDiagnostics:
    """The _log_payment_error helper must surface the browser-signed domain
    (network/asset/payTo/amount/extra + nonce length) on every facilitator
    rejection, so invalid_exact_evm_signature-style failures are diagnosable
    without guessing."""

    def test_logs_signed_domain_from_xpayment_header(self, caplog):
        from agentsafe.server import _log_payment_error

        class _Instr:
            body = {"error": "invalid_exact_evm_signature"}

        payload = {
            "x402Version": 2,
            "accepted": {
                "network": "eip155:84532",
                "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                "payTo": "0x03ee35B45382d19b7BDcE1A2B1eD72Aae01c48cc",
                "amount": "10000",
                "extra": {"name": "USDC", "version": "2"},
            },
            "payload": {
                "authorization": {
                    "from": "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A",
                    "to": "0x03ee35B45382d19b7BDcE1A2B1eD72Aae01c48cc",
                    "value": "10000",
                    "nonce": "0x" + "ab" * 32,
                }
            },
        }
        header = base64.b64encode(json.dumps(payload).encode()).decode()

        class _Req:
            headers = {"X-PAYMENT": header}

        class _Ctx:
            request = _Req()

        with caplog.at_level("WARNING", logger="agentSAFE.server"):
            _log_payment_error(_Ctx(), _Instr(), b"")

        joined = "\n".join(rec.getMessage() for rec in caplog.records)
        assert "REST payment rejected" in joined
        assert "invalid_exact_evm_signature" in joined
        assert "USDC" in joined  # signed domain name surfaced
        assert "eip155:84532" in joined
        assert "'auth_nonce_hex_len': 64" in joined or "64" in joined

    def test_logs_fallback_to_body(self, caplog):
        from agentsafe.server import _log_payment_error

        class _Instr:
            body = {"error": "invalid_exact_evm_signature"}

        class _Req:
            headers = {}  # no X-PAYMENT header

        class _Ctx:
            request = _Req()

        body = json.dumps(
            {"accepted": {"network": "eip155:84532", "asset": "0x036CbD"}}
        ).encode()
        with caplog.at_level("WARNING", logger="agentSAFE.server"):
            _log_payment_error(_Ctx(), _Instr(), body)
        assert "eip155:84532" in "\n".join(r.getMessage() for r in caplog.records)


class TestRESTReportFailed:
    """A paid audit whose workflow FAILED (e.g. a build/image failure) must
    surface a clear audit_failed response on the report endpoint - not a
    vague 409 'not completed yet' - while preserving the settled payment."""

    @respx.mock
    async def test_failed_run_returns_audit_failed(self):
        _mock_facilitator()
        _wire_dispatch_and_runs()
        from agentsafe.server import build_server

        server = _settings(TASK_STORE="memory")
        async with _http_client(build_server(server)) as client:
            header = await _payment_header_from_402(client)
            paid = await client.post(
                "/api/audit",
                json={"address": ADDR},
                headers={"PAYMENT-SIGNATURE": header},
            )
            assert paid.status_code == 202
            tid = paid.json()["task_id"]
            # The workflow fails after dispatch (build/image failure).
            respx.get(f"{GH}/repos/owner/repo/actions/runs/5").mock(
                return_value=httpx.Response(
                    200,
                    json={"id": 5, "status": "completed", "conclusion": "failure"},
                )
            )
            report = await client.get(f"/api/audit/{tid}/report.md")
        assert report.status_code == 409
        body = report.json()
        assert body["error_code"] == "audit_failed"
        assert body["state"] == "failed"
        assert "credit/refund policy" in body["error"].lower()

    @respx.mock
    async def test_in_progress_run_still_returns_not_ready(self):
        _mock_facilitator()
        _wire_dispatch_and_runs()
        from agentsafe.server import build_server

        server = _settings(TASK_STORE="memory")
        async with _http_client(build_server(server)) as client:
            header = await _payment_header_from_402(client)
            paid = await client.post(
                "/api/audit",
                json={"address": ADDR},
                headers={"PAYMENT-SIGNATURE": header},
            )
            assert paid.status_code == 202
            tid = paid.json()["task_id"]
            respx.get(f"{GH}/repos/owner/repo/actions/runs/5").mock(
                return_value=httpx.Response(
                    200,
                    json={"id": 5, "status": "in_progress", "conclusion": None},
                )
            )
            report = await client.get(f"/api/audit/{tid}/report.md")
        assert report.status_code == 409
        assert report.json()["error_code"] == "not_ready"
        assert report.json()["state"] == "running"
