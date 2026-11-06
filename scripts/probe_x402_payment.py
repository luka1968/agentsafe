"""End-to-end x402 payment probe: buyer signs off-line, no MetaMask.

The landing-page flow depends on MetaMask signing eth_signTypedData_v4 in
the browser, which is the step that keeps failing with
"The requested account and/or method has not been authorized by the user."
This probe isolates the SERVER side of the payment chain so you can tell
whether the backend/facilitator actually accepts a correctly-signed payment,
independent of any wallet popup.

It follows the official x402 buyer flow exactly:
    1. POST {base}/api/audit            -> expect 402 + PAYMENT-REQUIRED header
    2. parse accepts[], pick the target network
    3. build PaymentRequirements from the authoritative accept terms
    4. ExactEvmClientScheme + eth_account LocalAccount signs off-line
       (EIP-3009 transferWithAuthorization, EIP-712)
    5. retry with the X-PAYMENT header  -> 202/200 means the server accepted

Nothing touches a browser or MetaMask. A throwaway payer key is generated
unless --payer-key is given.

Two run modes:
  --asgi       Build the server in-process (no network listener) using the
               current .env, overridden to the target testnet network. Real
               GitHub dispatch still happens when a payment verifies.
  --base-url   Probe a server that is already running at the given URL.

Usage (Windows):
    .venv\\Scripts\\python.exe scripts\\probe_x402_payment.py ^
        --asgi --address 0xADDRESS_TO_AUDIT ^
        --network eip155:84532

Output is a step-by-step trace and a final JSON verdict.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import os
import sys
from pathlib import Path

import httpx
from eth_account import Account

from agentsafe.config import Settings

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("probe.x402")

AUDIT_PATH = "/api/audit"
ROOT = Path(__file__).resolve().parents[1]


def _b64decode(s: str) -> dict:
    pad = "=" * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s + pad).decode("utf-8"))


def _payload_header(payload: dict) -> str:
    return (
        base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8"))
        .decode("utf-8")
        .rstrip("=")
    )


def build_payment_requirements(accept: dict) -> dict:
    """Map the server's accept terms to x402 PaymentRequirements fields."""
    extra = accept.get("extra") or {}
    return {
        "scheme": "exact",
        "network": accept["network"],
        "asset": accept["asset"],
        "amount": str(accept["amount"]),
        "pay_to": accept["payTo"],
        "max_timeout_seconds": int(accept.get("maxTimeoutSeconds") or 300),
        "extra": extra,
    }


def _testnet_settings(network: str) -> Settings:
    """Build testnet Settings, overriding the (often mainnet) .env."""
    base = Settings(_env_file=ROOT / ".env")
    if network.startswith("eip155:84532"):
        overrides = {
            "PAYMENTS_ENABLED": "true",
            "X402_FACILITATOR_URL": "https://x402.org/facilitator",
            "X402_NETWORK": "eip155:84532",
            "X402_ALLOW_MAINNET": "false",
            "X402_NETWORKS_JSON": "",
            "X402_PAY_TO": base.X402_PAY_TO,
            # The audit worker talks to real mainnet RPC/explorer; a probe
            # only needs a well-formed URL to pass server construction checks.
            "INFURA_ETH_ENDPOINT": base.INFURA_ETH_ENDPOINT or "https://rpc.test",
            "ETHERSCAN_API_KEY": base.ETHERSCAN_API_KEY or "test",
        }
        return Settings(_env_file=None, **overrides)
    return base


async def _run_probe(client: httpx.AsyncClient, base_url: str, address: str, network: str, payer_key: str | None) -> dict:
    from x402.mechanisms.evm.exact import ExactEvmClientScheme
    from x402.schemas import PaymentRequirements

    account = Account.create() if not payer_key else Account.from_key(payer_key)
    logger.info("payer=%s", account.address)

    # Step 1: request without payment -> expect 402 + PAYMENT-REQUIRED header.
    r0 = await client.post(base_url + AUDIT_PATH, json={"address": address})
    logger.info("step1 unpaid -> HTTP %s", r0.status_code)
    if r0.status_code != 402:
        return {
            "ok": False,
            "step": "step1-unpaid-expected-402",
            "http": r0.status_code,
            "body": r0.text[:400],
        }
    req_header = r0.headers.get("PAYMENT-REQUIRED")
    if not req_header:
        return {"ok": False, "step": "step1-missing-payment-required-header", "http": 402}
    terms = _b64decode(req_header)
    accepts = terms.get("accepts") or []
    if not accepts:
        return {"ok": False, "step": "step1-empty-accepts", "body": json.dumps(terms)[:400]}
    logger.info("server advertises networks: %s", [a.get("network") for a in accepts])
    accept = next((a for a in accepts if a.get("network") == network), None)
    if not accept:
        return {
            "ok": False,
            "step": "step2-target-network-not-advertised",
            "network": network,
            "advertised": [a.get("network") for a in accepts],
        }
    logger.info(
        "target network=%s amount=%s asset=%s payTo=%s extra=%s",
        network,
        accept.get("amount"),
        accept.get("asset"),
        accept.get("payTo"),
        accept.get("extra"),
    )

    # Steps 3+4: sign off-line with a local account (no MetaMask).
    requirements = PaymentRequirements.model_validate(build_payment_requirements(accept))
    scheme = ExactEvmClientScheme(account)
    inner = scheme.create_payment_payload(requirements)
    logger.info("signed payload nonce=%s", inner.get("authorization", {}).get("nonce"))
    payload = {
        "x402Version": 2,
        "scheme": "exact",
        "network": accept["network"],
        "resource": {"url": base_url + AUDIT_PATH, "mimeType": "application/json"},
        "accepted": accept,
        "payload": inner,
    }

    # Step 5: retry with the X-PAYMENT header.
    r1 = await client.post(
        base_url + AUDIT_PATH,
        json={"address": address},
        headers={"X-PAYMENT": _payload_header(payload)},
    )
    body = {}
    try:
        body = r1.json()
    except Exception:
        body = {"raw": r1.text[:400]}
    logger.info("step5 paid -> HTTP %s", r1.status_code)
    ok = r1.status_code in (200, 202)
    return {
        "ok": ok,
        "step": "step5-paid",
        "http": r1.status_code,
        "task_id": body.get("task_id") or body.get("taskId"),
        "error": body.get("error") or body.get("error_description"),
        "body": json.dumps(body, ensure_ascii=False)[:400],
    }


async def _run_asgi(settings: Settings, address: str, network: str, payer_key: str | None) -> dict:
    from agentsafe.server import build_server

    mcp = build_server(settings, validate=False)
    app = mcp.http_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
        timeout=60.0,
    ) as client:
        return await _run_probe(client, "", address, network, payer_key)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", required=True, help="EVM contract address to audit (0x...)")
    parser.add_argument(
        "--network",
        default="eip155:84532",
        help="Network to pay on (default testnet Base Sepolia eip155:84532)",
    )
    parser.add_argument("--payer-key", default=None, help="Optional payer private key (mainnet only).")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--asgi", action="store_true", help="Build server in-process (testnet overrides)")
    mode.add_argument("--base-url", default=None, help="Probe a running server at this URL")
    args = parser.parse_args()

    settings = _testnet_settings(args.network)
    logger.info(
        "configured facilitator=%s primary=%s allow_mainnet=%s",
        settings.X402_FACILITATOR_URL,
        settings.X402_NETWORK,
        settings.X402_ALLOW_MAINNET,
    )

    if args.asgi:
        result = asyncio.run(_run_asgi(settings, args.address, args.network, args.payer_key))
    else:
        async def _run_base():
            async with httpx.AsyncClient(timeout=60.0) as client:
                return await _run_probe(client, args.base_url.rstrip("/"), args.address, args.network, args.payer_key)
        result = asyncio.run(_run_base())

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())