"""Server-side x402 payment flow tests (PROMPT 3).

Covers every required failure path on POST /api/audit:
  Step A  unpaid          -> 402 + official terms, NO dispatch, NO task
  Step B  bad binding     -> v1 payload / missing or foreign resource /
                             wrong network / expired authorization -> 402
          facilitator     -> malformed or unreachable -> 502 fail closed
  Step D  settlement      -> success reports transaction; failure reports
                             settlement_failed and never a fabricated hash
          replay          -> same payload never accepted twice
  storage                 -> payment record preserved across task failure;
                             Redis TTL is expressed in real days
"""

from __future__ import annotations

import base64
import json
import time

import httpx
import pytest
import respx

from tests.test_payments import (
    ADDR,
    FAC,
    PAYER,
    _mock_facilitator,
    _settings,
    _wire_dispatch_and_runs,
)
from tests.test_rest_x402 import _http_client, _payment_header_from_402

try:
    from x402.http import decode_payment_required_header, encode_payment_signature_header
    from x402.schemas import PaymentPayload
except ImportError:  # pragma: no cover
    decode_payment_required_header = None
    encode_payment_signature_header = None
    PaymentPayload = None

require_sdk = pytest.mark.skipif(
    decode_payment_required_header is None, reason="pinned x402 SDK unavailable"
)


def _v2_header(accepted: dict, resource_url: str, *, with_resource: bool = True,
               inner_payload: dict | None = None) -> str:
    """Build a v2 PAYMENT-SIGNATURE header the way real clients do."""
    payload = {
        "x402Version": 2,
        "payload": inner_payload
        if inner_payload is not None
        else {"kind": "exact/eip3009", "data": {"signature": "0x" + "22" * 32}},
        "accepted": accepted,
    }
    if with_resource:
        payload["resource"] = {"url": resource_url, "mimeType": "application/json"}
    model = PaymentPayload.model_validate(payload)
    return encode_payment_signature_header(model)


async def _verified_header(client: httpx.AsyncClient, **accepted_overrides) -> str:
    """Real dance: unpaid 402 -> echo advertised terms (optionally mutated)."""
    first = await client.post("/api/audit", json={"address": ADDR})
    assert first.status_code == 402, first.text
    required = decode_payment_required_header(first.headers.get("payment-required"))
    accepted = required.accepts[0].model_dump(by_alias=True, exclude_none=True)
    accepted.update(accepted_overrides)
    return accepted


@require_sdk
class TestStepAUnpaid:
    @respx.mock
    async def test_unpaid_gets_terms_no_dispatch_no_task(self):
        routes = _mock_facilitator()
        dispatch = _wire_dispatch_and_runs()
        server = _settings()  # default: PAYMENTS_ENABLED=True, testnet primary
        from agentsafe.server import build_server

        async with _http_client(build_server(server)) as client:
            resp = await client.post("/api/audit", json={"address": ADDR})
        assert resp.status_code == 402
        required = decode_payment_required_header(resp.headers.get("payment-required"))
        assert required.accepts, "terms must be advertised"
        terms = required.accepts[0]
        assert terms.scheme == "exact"
        assert terms.network == "eip155:84532"
        assert terms.pay_to == _settings().X402_PAY_TO.lower()
        assert int(terms.amount) > 0
        # Step A: nothing started, nothing recorded
        assert routes["verify"].call_count == 0
        assert routes["settle"].call_count == 0
        assert "task_id" not in dispatch


@require_sdk
class TestStepBBinding:
    @respx.mock
    async def test_v1_payload_rejected(self):
        _mock_facilitator()
        dispatch = _wire_dispatch_and_runs()
        from agentsafe.server import build_server

        accepted = None  # filled from the real 402 below
        server = _settings()
        async with _http_client(build_server(server)) as client:
            first = await client.post("/api/audit", json={"address": ADDR})
            assert first.status_code == 402
            required = decode_payment_required_header(first.headers.get("payment-required"))
            accepted = required.accepts[0].model_dump(by_alias=True, exclude_none=True)
            v1 = {
                "x402Version": 1,
                "scheme": "exact",
                "network": "eip155:84532",
                "payload": {"signature": "0x" + "33" * 32},
                "accepted": accepted,
            }
            header = base64.b64encode(json.dumps(v1).encode()).decode()
            resp = await client.post(
                "/api/audit",
                json={"address": ADDR},
                headers={"PAYMENT-SIGNATURE": header},
            )
        assert resp.status_code == 402
        body = resp.json()
        assert "version" in str(body.get("error", "")).lower()
        assert "task_id" not in dispatch

    @respx.mock
    async def test_resource_mismatch_rejected(self):
        _mock_facilitator()
        dispatch = _wire_dispatch_and_runs()
        from agentsafe.server import build_server

        server = _settings()
        async with _http_client(build_server(server)) as client:
            accepted = await self._terms(client)
            header = _v2_header(accepted, "https://evil.example/api/audit")
            resp = await client.post(
                "/api/audit",
                json={"address": ADDR},
                headers={"PAYMENT-SIGNATURE": header},
            )
        assert resp.status_code == 402
        assert resp.json()["error_code"] == "payment_resource_mismatch"
        assert "task_id" not in dispatch

    @respx.mock
    async def test_missing_resource_rejected(self):
        _mock_facilitator()
        dispatch = _wire_dispatch_and_runs()
        from agentsafe.server import build_server

        server = _settings()
        async with _http_client(build_server(server)) as client:
            accepted = await self._terms(client)
            header = _v2_header(accepted, "", with_resource=False)
            resp = await client.post(
                "/api/audit",
                json={"address": ADDR},
                headers={"PAYMENT-SIGNATURE": header},
            )
        assert resp.status_code == 402
        assert resp.json()["error_code"] == "payment_resource_missing"
        assert "task_id" not in dispatch

    @respx.mock
    async def test_wrong_network_rejected(self):
        _mock_facilitator()
        dispatch = _wire_dispatch_and_runs()
        from agentsafe.server import build_server

        server = _settings()
        async with _http_client(build_server(server)) as client:
            accepted = await self._terms(client, network="eip155:8453")
            header = _v2_header(accepted, "https://test/api/audit")
            resp = await client.post(
                "/api/audit",
                json={"address": ADDR},
                headers={"PAYMENT-SIGNATURE": header},
            )
        assert resp.status_code == 402
        assert "task_id" not in dispatch

    @respx.mock
    async def test_expired_authorization_rejected(self):
        _mock_facilitator()
        dispatch = _wire_dispatch_and_runs()
        from agentsafe.server import build_server

        server = _settings()
        async with _http_client(build_server(server)) as client:
            accepted = await self._terms(client)
            expired = {
                "authorization": {
                    "from": "0x" + "11" * 20,
                    "to": accepted["payTo"],
                    "value": accepted["amount"],
                    "validAfter": "0",
                    "validBefore": str(int(time.time()) - 10),
                    "nonce": "0x" + "ab" * 32,
                },
                "signature": "0x" + "22" * 65,
            }
            header = _v2_header(accepted, "https://test/api/audit", inner_payload=expired)
            resp = await client.post(
                "/api/audit",
                json={"address": ADDR},
                headers={"PAYMENT-SIGNATURE": header},
            )
        assert resp.status_code == 402
        assert resp.json()["error_code"] == "payment_authorization_expired"
        assert "task_id" not in dispatch

    @respx.mock
    async def test_facilitator_timeout_fails_closed(self):
        routes = _mock_facilitator()
        dispatch = _wire_dispatch_and_runs()
        from agentsafe.server import build_server

        server = _settings()
        routes["verify"].mock(side_effect=httpx.ConnectError("facilitator down"))
        async with _http_client(build_server(server)) as client:
            header = await _payment_header_from_402(client)
            resp = await client.post(
                "/api/audit",
                json={"address": ADDR},
                headers={"PAYMENT-SIGNATURE": header},
            )
        assert resp.status_code == 502
        assert resp.json()["error_code"] == "facilitator_unreachable"
        assert "task_id" not in dispatch
        assert routes["settle"].call_count == 0

    @respx.mock
    async def test_facilitator_malformed_fails_closed(self):
        routes = _mock_facilitator()
        dispatch = _wire_dispatch_and_runs()
        from agentsafe.server import build_server

        server = _settings()
        routes["verify"].mock(return_value=httpx.Response(200, text="<html>oops</html>"))
        async with _http_client(build_server(server)) as client:
            header = await _payment_header_from_402(client)
            resp = await client.post(
                "/api/audit",
                json={"address": ADDR},
                headers={"PAYMENT-SIGNATURE": header},
            )
        assert resp.status_code == 502
        assert resp.json()["error_code"] == "facilitator_malformed"
        assert "task_id" not in dispatch
        assert routes["settle"].call_count == 0

    @staticmethod
    async def _terms(client: httpx.AsyncClient, **overrides) -> dict:
        first = await client.post("/api/audit", json={"address": ADDR})
        assert first.status_code == 402, first.text
        required = decode_payment_required_header(first.headers.get("payment-required"))
        accepted = required.accepts[0].model_dump(by_alias=True, exclude_none=True)
        accepted.update(overrides)
        return accepted


@require_sdk
class TestStepDSettlement:
    @respx.mock
    async def test_success_reports_structured_payment(self):
        _mock_facilitator()
        dispatch = _wire_dispatch_and_runs()
        from agentsafe.server import build_server

        server = _settings()
        async with _http_client(build_server(server)) as client:
            header = await _payment_header_from_402(client)
            resp = await client.post(
                "/api/audit",
                json={"address": ADDR},
                headers={"PAYMENT-SIGNATURE": header},
            )
        assert resp.status_code == 202, resp.text
        body = resp.json()
        payment = body["payment"]
        assert payment["status"] == "settled"
        assert payment["network"] == "eip155:84532"
        assert payment["transaction"] == "0x" + "11" * 32
        assert payment["payer"] == PAYER
        assert len(payment["payment_ref"]) == 64  # sha256 fingerprint
        assert payment["service_ref"] == body["task_id"]
        assert "settlement_error" not in body

    @respx.mock
    async def test_settlement_failure_never_fabricates_success(self):
        routes = _mock_facilitator()
        dispatch = _wire_dispatch_and_runs()
        from agentsafe.server import build_server

        server = _settings()
        routes["settle"].mock(
            return_value=httpx.Response(
                200,
                json={"success": False, "errorReason": "insufficient_tax"},
            )
        )
        async with _http_client(build_server(server)) as client:
            header = await _payment_header_from_402(client)
            resp = await client.post(
                "/api/audit",
                json={"address": ADDR},
                headers={"PAYMENT-SIGNATURE": header},
            )
        assert resp.status_code == 202
        body = resp.json()
        assert body["payment"]["status"] == "settlement_failed"
        assert "transaction" not in body["payment"]
        assert "insufficient_tax" in body["settlement_error"]

    @respx.mock
    async def test_replay_never_accepted_twice(self):
        routes = _mock_facilitator()
        dispatch = _wire_dispatch_and_runs()
        from agentsafe.server import build_server

        server = _settings()
        async with _http_client(build_server(server)) as client:
            header = await _payment_header_from_402(client)
            first = await client.post(
                "/api/audit",
                json={"address": ADDR},
                headers={"PAYMENT-SIGNATURE": header},
            )
            second = await client.post(
                "/api/audit",
                json={"address": ADDR},
                headers={"PAYMENT-SIGNATURE": header},
            )
        assert first.status_code == 202
        assert second.status_code == 402
        assert second.json()["error_code"] == "payment_replay"
        # verify runs per submission (SDK order), but the payload may only
        # ever be dispatched + settled ONCE.
        assert routes["settle"].call_count == 1
        assert "task_id" in dispatch


class TestPaymentRecordPreservation:
    async def test_task_failure_preserves_payment_record(self):
        from agentsafe.schemas import TaskState
        from agentsafe.task_store import MemoryTaskStore

        store = MemoryTaskStore()
        task = store.create_task(ADDR)
        store.mark_paid(task.task_id, "f" * 64)
        # An audit failing AFTER settlement must never silently unmark payment.
        store.set_state(task.task_id, TaskState.FAILED, error_code="audit_failed")
        reloaded = store.get(task.task_id)
        assert reloaded.paid is True
        assert reloaded.payment_ref == "f" * 64
        assert reloaded.state is TaskState.FAILED


class TestRedisTTL:
    def test_ttl_is_expressed_in_real_days(self):
        from agentsafe.task_store import redis_ttl_seconds

        assert redis_ttl_seconds(2) == 2 * 86_400
        assert redis_ttl_seconds(14) == 14 * 86_400

    def test_create_task_sets_day_based_ttl(self, monkeypatch):
        import threading

        from agentsafe import task_store as ts_mod

        captured: dict = {}

        class FakePipeline:
            def set(self, key, value, ex=None):
                captured["ex"] = ex

            def execute(self):
                return True

        class FakeRedis:
            def pipeline(self):
                return FakePipeline()

        monkeypatch.setattr(ts_mod.redis_client, "from_url", lambda *a, **k: FakeRedis())
        store = ts_mod.RedisTaskStore("redis://x", retention_days=2)
        store.create_task(ADDR)
        assert captured["ex"] == 2 * 86_400
        assert threading.current_thread() is not None  # keep import meaningful


@require_sdk
class TestMCPVersionCheck:
    async def test_v1_payload_denied_at_mcp_tool(self, monkeypatch):
        from agentsafe.payment import x402_adapter
        import x402 as x402_mod

        class FakeServer:
            def register(self, network, scheme):
                pass

            def initialize(self):
                pass

            def get_supported_kind(self, version, network, scheme):
                return object()

            def build_payment_requirements(self, config):
                from x402.schemas import PaymentRequirements

                return [
                    PaymentRequirements.model_validate(
                        {
                            "scheme": config.scheme,
                            "network": config.network,
                            "asset": "0x" + "11" * 20,
                            "amount": "10000",
                            "pay_to": config.pay_to,
                            "max_timeout_seconds": config.max_timeout_seconds,
                            "extra": {"name": "USDC", "version": "2"},
                        }
                    )
                ]

            def find_matching_requirements(self, accepts, payload):
                return None

            async def create_payment_required_response(self, accepts, resource, error):
                class _PR:
                    def model_dump(self, by_alias, exclude_none):
                        return {"x402Version": 2, "error": error}

                return _PR()

            async def verify_payment(self, payload, matched):
                raise AssertionError("must not reach facilitator")

        monkeypatch.setattr(
            x402_mod, "x402ResourceServer", lambda _facilitator: FakeServer(), raising=True
        )
        adapter = x402_adapter.X402PaymentAdapter(
            enabled=True,
            sdk_version="2.25.0",
            network="eip155:84532",
            pay_to="0x" + "ab" * 20,
            facilitator_url=FAC,
            price="$0.01",
        )

        class _Meta(dict):
            pass

        class _RC:
            meta = {"x402/payment": {"x402Version": 1, "accepted": {}}}

        class _Ctx:
            request_context = _RC()

        verified, deny = await adapter.verify(_Ctx(), "audit_contract")
        assert verified is None
        assert deny is not None
        assert "protocol version" in json.dumps(deny.structured_content)
