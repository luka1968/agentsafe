"""Validation that the checked-in openapi.json (served at /openapi.json and
/.well-known/openapi.json, indexed by x402scan) stays accurate and in sync
with the real REST surface. Catches stale paths/URLs before a customer or
indexer reads them."""

from __future__ import annotations

import json
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
OPENAPI = ROOT / "openapi.json"

PROD_BASE = "https://x402.workfern.com"

# The REST surface actually served by src/agentsafe/server.py.
EXPECTED_PATHS: dict[str, set[str]] = {
    "/api/audit": {"post"},
    "/api/audit/{task_id}/report": {"get"},
    "/api/audit/{task_id}/report.json": {"get"},
    "/api/audit/{task_id}/report.pdf": {"get"},
    "/api/audit/{task_id}/report.md": {"get"},
}


@pytest.fixture(scope="module")
def spec() -> dict:
    return json.loads(OPENAPI.read_text())


def test_openapi_is_valid_json(spec: dict) -> None:
    assert "openapi" in spec
    assert "paths" in spec
    assert "info" in spec


def test_all_served_routes_are_documented(spec: dict) -> None:
    """Every real REST route must appear in openapi.json (no undocumented
    surface, no stale missing route like a dropped report.md)."""
    documented = set(spec["paths"].keys())
    missing = set(EXPECTED_PATHS) - documented
    assert not missing, f"served routes missing from openapi.json: {missing}"


def test_documented_paths_match_served_methods(spec: dict) -> None:
    for path, methods in EXPECTED_PATHS.items():
        ops = set((spec["paths"].get(path) or {}).keys())
        missing = methods - ops
        assert not missing, f"path {path} missing methods {missing} in openapi.json"


def test_servers_url_is_production(spec: dict) -> None:
    urls = [s["url"] for s in spec.get("servers", [])]
    assert PROD_BASE in urls, (
        f"openapi.json server URL {urls} does not advertise {PROD_BASE}"
    )


def test_refund_url_is_production(spec: dict) -> None:
    desc = spec["info"]["description"]
    assert f"{PROD_BASE}/refund" in desc, (
        "info.description refund URL is not the production refund endpoint"
    )


def test_x402_payment_block_is_present_and_consistent(spec: dict) -> None:
    """The audit dispatch must carry the x402 terms indexers read."""
    audit = spec["paths"]["/api/audit"]["post"]
    block = audit.get("x-402-payment")
    assert block, "POST /api/audit must declare an x-402-payment block"
    assert block["scheme"] == "exact"
    assert block["network"] == "eip155:8453"  # Base Mainnet
    assert block["x402Version"] == 2
    assert block["price"].startswith("$")
    # asset must be a 0x-prefixed 40-hex USDC address
    asset = block["asset"]
    assert asset.startswith("0x") and len(asset) == 42
    # payTo must be a 0x-prefixed 40-hex address
    payto = block["payTo"]
    assert payto.startswith("0x") and len(payto) == 42


def test_security_scheme_is_x402(spec: dict) -> None:
    auth = spec["paths"]["/api/audit"]["post"].get("security")
    assert auth == [{"x402": []}]
    scheme = spec["components"]["securitySchemes"]["x402"]
    assert scheme["scheme"] == "x402"