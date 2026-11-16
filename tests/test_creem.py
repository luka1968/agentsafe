"""Creem card-checkout channel tests.

Covers: webhook HMAC signature verification (fail-closed), the
checkout -> webhook -> dispatch happy path with task-store binding,
idempotent webhook replay, product mismatch, dispatch-before-webhook
(402 payment_pending), and the disabled-channel 503.

The Creem API and GitHub dispatches are mocked via respx (same pattern as
test_payments.py / test_rest_x402.py); signature verification is local.
"""

from __future__ import annotations

import hashlib
import hmac
import json

import httpx
import pytest
import respx

from agentsafe.payment.creem import (
    checkout_amount,
    checkout_customer_email,
    checkout_is_completed,
    checkout_order_id,
    checkout_product_id,
    checkout_request_id,
    parse_event,
    verify_signature,
)
from agentsafe.server import build_server
from tests.test_payments import (
    ADDR,
    _mock_facilitator,
    _settings,
    _wire_dispatch_and_runs,
)

CREEM_BASE = "https://api.creem.io"
WEBHOOK_SECRET = "whsec_test_0123456789abcdef"
PRODUCT_ID = "prod_test_0001"


def _http_client(server) -> httpx.AsyncClient:
    app = server.http_app(stateless_http=True, json_response=True)
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://test"
    )


def _creem_settings(**kw):
    base = {
        "CREEM_ENABLED": True,
        "CREEM_API_KEY": "creem_test_key",
        "CREEM_WEBHOOK_SECRET": WEBHOOK_SECRET,
        "CREEM_PRODUCT_ID": PRODUCT_ID,
        "CREEM_API_BASE": CREEM_BASE,
    }
    base.update(kw)
    return _settings(**base)


def _signed_body(payload: dict, secret: str = WEBHOOK_SECRET) -> tuple[bytes, dict]:
    raw = json.dumps(payload).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    return raw, {"creem-signature": sig}


def _checkout_completed_event(task_id: str, order_id: str = "ord_1") -> dict:
    return {
        "id": "evt_1",
        "eventType": "checkout.completed",
        "created_at": 1728734327412,
        "object": {
            "id": "ch_1",
            "object": "checkout",
            "request_id": task_id,
            "status": "completed",
            "order": {
                "id": order_id,
                "status": "paid",
                "amount_paid": 100,
                "currency": "EUR",
                "product": PRODUCT_ID,
            },
            "product": {"id": PRODUCT_ID, "name": "Audit"},
            "customer": {"email": "buyer@example.com"},
        },
    }


# ---------------------------------------------------------------- unit tests
class TestSignatureVerification:
    def test_valid_signature_passes(self):
        raw, headers = _signed_body({"a": 1})
        assert verify_signature(raw, headers["creem-signature"], WEBHOOK_SECRET)

    def test_tampered_body_fails(self):
        raw, headers = _signed_body({"a": 1})
        assert not verify_signature(
            raw + b" ", headers["creem-signature"], WEBHOOK_SECRET
        )

    def test_wrong_secret_fails(self):
        raw, headers = _signed_body({"a": 1})
        assert not verify_signature(raw, headers["creem-signature"], "other")

    def test_missing_signature_fails(self):
        raw, _ = _signed_body({"a": 1})
        assert not verify_signature(raw, None, WEBHOOK_SECRET)
        assert not verify_signature(raw, "", WEBHOOK_SECRET)


class TestEventHelpers:
    def test_parse_event_rejects_garbage(self):
        with pytest.raises(ValueError):
            parse_event(b"not json")
        with pytest.raises(ValueError):
            parse_event(b'{"eventType": "checkout.completed"}')  # no object

    def test_parse_event_accepts_valid(self):
        raw, _ = _signed_body(_checkout_completed_event("t" * 8))
        event = parse_event(raw)
        assert event["eventType"] == "checkout.completed"

    def test_field_extractors(self):
        obj = _checkout_completed_event("t" * 8)["object"]
        assert checkout_request_id(obj) == "t" * 8
        assert checkout_product_id(obj) == PRODUCT_ID
        assert checkout_order_id(obj) == "ord_1"
        assert checkout_customer_email(obj) == "buyer@example.com"
        assert checkout_amount(obj) == "100"
        assert checkout_is_completed(obj)


# -------------------------------------------------------- route integration
@pytest.mark.asyncio
async def test_checkout_creates_task_and_session():
    with respx.mock:
        _mock_facilitator()
        respx.post(f"{CREEM_BASE}/v1/checkouts").mock(
            return_value=httpx.Response(
                201, json={"id": "ch_1", "checkout_url": "https://creem.io/c/x"}
            )
        )
        server = build_server(_creem_settings())
        async with _http_client(server) as client:
            res = await client.post(
                "/api/pay/creem/checkout",
                json={"address": ADDR, "email": "a@example.com"},
            )
        assert res.status_code == 201
        data = res.json()
        assert data["task_id"] and data["checkout_url"] == "https://creem.io/c/x"


@pytest.mark.asyncio
async def test_checkout_disabled_returns_503():
    with respx.mock:
        _mock_facilitator()
        server = build_server(_settings())  # CREEM_ENABLED absent -> off
        async with _http_client(server) as client:
            res = await client.post("/api/pay/creem/checkout", json={"address": ADDR})
    assert res.status_code == 503
    assert res.json()["error_code"] == "creem_disabled"


@pytest.mark.asyncio
async def test_webhook_rejects_bad_signature():
    with respx.mock:
        _mock_facilitator()
        server = build_server(_creem_settings())
        raw, _ = _signed_body(_checkout_completed_event("t" * 8))
        async with _http_client(server) as client:
            res = await client.post(
                "/api/pay/creem/webhook",
                content=raw,
                headers={"creem-signature": "0" * 64, "content-type": "application/json"},
            )
    assert res.status_code == 400
    assert res.json()["error_code"] == "bad_signature"


@pytest.mark.asyncio
async def test_full_flow_checkout_webhook_dispatch():
    with respx.mock:
        _mock_facilitator()
        respx.post(f"{CREEM_BASE}/v1/checkouts").mock(
            return_value=httpx.Response(
                201, json={"id": "ch_1", "checkout_url": "https://creem.io/c/x"}
            )
        )
        gh_state = _wire_dispatch_and_runs()
        server = build_server(_creem_settings())
        async with _http_client(server) as client:
            # 1) create checkout session
            res = await client.post(
                "/api/pay/creem/checkout",
                json={"address": ADDR, "email": "a@example.com"},
            )
            assert res.status_code == 201
            task_id = res.json()["task_id"]

            # 2) dispatch before webhook -> 402 payment_pending (retryable)
            pend = await client.post(
                "/api/pay/creem/dispatch", json={"task_id": task_id}
            )
            assert pend.status_code == 402
            assert pend.json()["error_code"] == "payment_pending"

            # 3) signed webhook marks the task paid
            raw, headers = _signed_body(_checkout_completed_event(task_id))
            hook = await client.post(
                "/api/pay/creem/webhook",
                content=raw,
                headers={**headers, "content-type": "application/json"},
            )
            assert hook.status_code == 200

            # 4) dispatch releases the audit (reuses the x402 dispatch plumbing)
            disp = await client.post(
                "/api/pay/creem/dispatch", json={"task_id": task_id}
            )
            assert disp.status_code == 202
            assert disp.json()["state"] == "running"
            assert gh_state["task_id"] == task_id

            # 5) idempotent re-dispatch is a no-op with the same task
            again = await client.post(
                "/api/pay/creem/dispatch", json={"task_id": task_id}
            )
            assert again.status_code == 200


@pytest.mark.asyncio
async def test_webhook_replay_is_idempotent():
    with respx.mock:
        _mock_facilitator()
        respx.post(f"{CREEM_BASE}/v1/checkouts").mock(
            return_value=httpx.Response(
                201, json={"id": "ch_1", "checkout_url": "https://creem.io/c/x"}
            )
        )
        _wire_dispatch_and_runs()
        server = build_server(_creem_settings())
        async with _http_client(server) as client:
            res = await client.post(
                "/api/pay/creem/checkout", json={"address": ADDR}
            )
            task_id = res.json()["task_id"]
            raw, headers = _signed_body(_checkout_completed_event(task_id))
            for _ in range(2):
                hook = await client.post(
                    "/api/pay/creem/webhook",
                    content=raw,
                    headers={**headers, "content-type": "application/json"},
                )
                assert hook.status_code == 200
            disp = await client.post(
                "/api/pay/creem/dispatch", json={"task_id": task_id}
            )
            assert disp.status_code == 202


@pytest.mark.asyncio
async def test_webhook_product_mismatch_never_binds():
    with respx.mock:
        _mock_facilitator()
        respx.post(f"{CREEM_BASE}/v1/checkouts").mock(
            return_value=httpx.Response(
                201, json={"id": "ch_1", "checkout_url": "https://creem.io/c/x"}
            )
        )
        server = build_server(_creem_settings())
        async with _http_client(server) as client:
            res = await client.post(
                "/api/pay/creem/checkout", json={"address": ADDR}
            )
            task_id = res.json()["task_id"]
            event = _checkout_completed_event(task_id)
            event["object"]["product"]["id"] = "prod_OTHER"
            raw, headers = _signed_body(event)
            hook = await client.post(
                "/api/pay/creem/webhook",
                content=raw,
                headers={**headers, "content-type": "application/json"},
            )
            assert hook.status_code == 200  # acked, but NOT bound
            disp = await client.post(
                "/api/pay/creem/dispatch", json={"task_id": task_id}
            )
            assert disp.status_code == 402  # still unpaid


@pytest.mark.asyncio
async def test_webhook_unknown_event_acked():
    with respx.mock:
        _mock_facilitator()
        server = build_server(_creem_settings())
        raw, headers = _signed_body(
            {"id": "evt_x", "eventType": "subscription.update", "object": {"id": "sub_1"}}
        )
        async with _http_client(server) as client:
            res = await client.post(
                "/api/pay/creem/webhook",
                content=raw,
                headers={**headers, "content-type": "application/json"},
            )
    assert res.status_code == 200
    assert res.json() == {"ok": True}
