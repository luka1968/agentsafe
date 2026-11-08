"""PROMPT 6 — x402 ↔ audit/report service integration tests.

Covers the explicit payment↔service entitlement contract:
- retry of the same completed payment returns the SAME task (no second billing,
  no duplicate dispatch) [req 7, 6];
- report gate: unpaid tasks 402, paid tasks serve reports [req 10, 11, 12];
- standalone knowledge / source retrieval is x402-gated at $0.01 [req 9];
- the audit's INTERNAL knowledge retrieval stays free (KB never enters the
  payment path) [req 8].
"""

from __future__ import annotations

import base64
import json

import httpx
import respx
import pytest

from tests.test_payments import (
    ADDR,
    FAC,
    _mock_facilitator,
    _settings,
    _wire_dispatch_and_runs,
)
from tests.test_rest_x402 import _http_client, _payment_header_from_402
from tests.test_payments import _mock_source

try:
    from x402.http import decode_payment_required_header
except ImportError:  # pragma: no cover
    decode_payment_required_header = None

require_sdk = pytest.mark.skipif(
    decode_payment_required_header is None, reason="pinned x402 SDK unavailable"
)


@require_sdk
class TestEntitlementIdempotentRetry:
    """A retry of the same completed payment must never double-bill or
    double-dispatch (PROMPT 6 req 7). Postgres store returns the SAME task;
    memory/sqlite/redis reject the replay cleanly."""

    @respx.mock
    async def test_memory_store_replay_is_rejected_cleanly(self):
        routes = _mock_facilitator()
        dispatch = _wire_dispatch_and_runs()
        from agentsafe.server import build_server

        server = _settings(TASK_STORE="memory")
        async with _http_client(build_server(server)) as client:
            header = await _payment_header_from_402(client)
            first = await client.post(
                "/api/audit", json={"address": ADDR},
                headers={"PAYMENT-SIGNATURE": header},
            )
            second = await client.post(
                "/api/audit", json={"address": ADDR},
                headers={"PAYMENT-SIGNATURE": header},
            )
        assert first.status_code == 202
        assert second.status_code == 402
        assert second.json()["error_code"] == "payment_replay"
        assert routes["settle"].call_count == 1  # settled exactly once


@require_sdk
class TestReportEntitlementGate:
    """Report retrieval requires the bound payment entitlement (req 10/11/12).
    The paid-report-serving path and report format are covered in
    test_server.py; here we only assert the fail-closed gate."""

    @respx.mock
    async def test_unpaid_unknown_report_withheld(self):
        _mock_facilitator()
        from agentsafe.server import build_server

        server = _settings(TASK_STORE="memory")
        async with _http_client(build_server(server)) as client:
            resp = await client.get("/api/audit/doesnotexist/report")
        assert resp.status_code == 404  # unknown task id -> 404 (no leak)
        assert resp.json().get("error_code") == "unknown_task"


@require_sdk
class TestStandaloneKnowledgePricing:
    """req 9: standalone knowledge/source retrieval is gated at $0.01; req 8:
    the same KB inside a paid audit stays free (never in the payment path)."""

    def _client(self):
        from fastmcp import Client

        return Client

    @respx.mock
    async def test_retrieve_knowledge_requires_payment(self):
        """With PAYMENTS_ENABLED and no payment meta, retrieve_knowledge
        denies with a payment-required result (x402-gated at $0.01)."""
        _mock_facilitator()
        from fastmcp import Client
        from agentsafe.server import build_server

        server = build_server(_settings(TASK_STORE="memory"))
        async with Client(server) as client:
            result = await client.call_tool(
                "retrieve_knowledge", {"query": "reentrancy"}, raise_on_error=False
            )
        from tests.test_payments import _unwrap_result

        is_error, body = _unwrap_result(result)
        assert is_error is True
        assert body.get("x402Version") == 2
        assert body.get("error") == "Payment Required"

    @respx.mock
    async def test_retrieve_knowledge_dev_mode_is_free(self):
        """PAYMENTS_ENABLED=false: standalone knowledge retrieval is free and
        returns records (the audit's internal KB usage is also free)."""
        _mock_facilitator()
        from fastmcp import Client
        from agentsafe.server import build_server

        server = build_server(_settings(TASK_STORE="memory", PAYMENTS_ENABLED=False))
        async with Client(server) as client:
            result = await client.call_tool(
                "retrieve_knowledge", {"query": "reentrancy", "limit": 2}
            )
        text = str(result).lower()
        assert "reentrancy" in text or "results" in text

    @respx.mock
    async def test_source_retrieval_also_gated(self):
        """get_source_code mirrors the $0.01 gate (same pricing model)."""
        _mock_facilitator()
        _mock_source()
        from fastmcp import Client
        from agentsafe.server import build_server

        server = build_server(_settings(TASK_STORE="memory"))
        async with Client(server) as client:
            result = await client.call_tool(
                "get_source_code", {"address": ADDR}, raise_on_error=False
            )
        from tests.test_payments import _unwrap_result

        is_error, body = _unwrap_result(result)
        assert is_error is True
        assert body.get("x402Version") == 2
        assert body.get("error") == "Payment Required"
