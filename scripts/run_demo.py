"""One-click testnet payment demo. Double-click / run, no config needed.

Automates the WHOLE chain with the wallet created for you (address printed
when you run this; faucet-funded by you beforehand):

    1. Boot the server in-process (testnet: x402.org facilitator, Base Sepolia).
    2. Ask the server for payment terms (402 -> PAYMENT-REQUIRED header).
    3. Sign an EIP-3009 transferWithAuthorization off-line with the demo wallet.
    4. Send the signed payment -> server verifies -> GitHub Actions audit dispatched.
    5. Poll the task until the audit completes.
    6. Fetch the Markdown report and print it to the screen.

You only need to have funded the demo wallet's address with Base Sepolia test
USDC first (see the 3-step guide). Everything else is automatic.

Run:
    .venv\\Scripts\\python.exe scripts\\run_demo.py
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import sys
import time
from pathlib import Path

import httpx
from eth_account import Account

from agentsafe.config import Settings

ROOT = Path(__file__).resolve().parents[1]
AUDIT_PATH = "/api/audit"
DEFAULT_ADDRESS = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"  # UniSwap V2 Router, well-known contract


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


def _read_demo_key() -> str:
    """Read X402_DEMO_KEY directly from .env (Settings ignores undeclared keys)."""
    env_path = ROOT / ".env"
    try:
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("X402_DEMO_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except FileNotFoundError:
        return ""
    return ""


def _testnet_settings() -> Settings:
    base = Settings(_env_file=ROOT / ".env")
    overrides = {
        "PAYMENTS_ENABLED": "true",
        "X402_FACILITATOR_URL": "https://x402.org/facilitator",
        "X402_NETWORK": "eip155:84532",
        "X402_ALLOW_MAINNET": "false",
        "X402_NETWORKS_JSON": "",
        "X402_PAY_TO": base.X402_PAY_TO,
        "INFURA_ETH_ENDPOINT": base.INFURA_ETH_ENDPOINT or "https://rpc.test",
        "ETHERSCAN_API_KEY": base.ETHERSCAN_API_KEY or "test",
    }
    return Settings(_env_file=None, **overrides)


async def run_demo(settings: Settings, key: str, address: str, timeout_s: int) -> dict:
    from x402.mechanisms.evm.exact import ExactEvmClientScheme
    from x402.schemas import PaymentRequirements
    from agentsafe.server import build_server

    account = Account.from_key(key)
    print("=" * 72)
    print("agentSAFE 測試網支付 Demo")
    print("=" * 72)
    print(f"  測試買家錢包 : {account.address}")
    print(f"  要審計的合約 : {address}")
    print(f"  網路         : eip155:84532 (Base Sepolia 測試網)")
    print(f"  Facilitator  : {settings.X402_FACILITATOR_URL}")
    print("=" * 72)
    print("\n[1/5] 啟動伺服器…")
    mcp = build_server(settings, validate=False)
    app = mcp.http_app()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
        timeout=120.0,
    ) as client:
        # Step 1: no payment -> expect 402 + PAYMENT-REQUIRED header.
        print("[2/5] 向伺服器索取付款條件…")
        r0 = await client.post(AUDIT_PATH, json={"address": address})
        if r0.status_code != 402:
            print(f"!! 伺服器未回 402，回傳 HTTP {r0.status_code}: {r0.text[:200]}")
            return {"ok": False, "step": "no-402"}
        req_header = r0.headers.get("PAYMENT-REQUIRED")
        if not req_header:
            print("!! 402 回應缺少 PAYMENT-REQUIRED header")
            return {"ok": False, "step": "no-payment-required-header"}
        terms = _b64decode(req_header)
        accepts = terms.get("accepts") or []
        accept = next((a for a in accepts if a.get("network") == "eip155:84532"), None)
        if not accept:
            print(f"!! 伺服器未提供測試網付款條件: {[a.get('network') for a in accepts]}")
            return {"ok": False, "step": "no-testnet-accept"}
        amount_usdc = int(accept["amount"]) / 1e6
        print(f"   付款條件 OK：{amount_usdc} USDC → {accept['payTo']}")
        print(f"   代幣：{accept['asset']}")

        # Step 2: sign EIP-3009 off-line (no MetaMask).
        print("[3/5] 用測試錢包離線簽署付款…")
        requirements = PaymentRequirements.model_validate(build_payment_requirements(accept))
        scheme = ExactEvmClientScheme(account)
        inner = scheme.create_payment_payload(requirements)
        payload = {
            "x402Version": 2,
            "scheme": "exact",
            "network": accept["network"],
            "resource": {"url": AUDIT_PATH, "mimeType": "application/json"},
            "accepted": accept,
            "payload": inner,
        }

        # Step 3: send signed payment.
        print("[4/5] 送出付款並觸發審計…")
        r1 = await client.post(
            AUDIT_PATH,
            json={"address": address},
            headers={"X-PAYMENT": _payload_header(payload)},
        )
        if r1.status_code not in (200, 202):
            body = {}
            try:
                body = r1.json()
            except Exception:
                body = {"raw": r1.text[:300]}
            print(f"!! 付款被拒 HTTP {r1.status_code}: {json.dumps(body, ensure_ascii=False)[:300]}")
            if "insufficient_balance" in json.dumps(body):
                print("\n👉 關鍵提示：測試錢包餘額不足！")
                print(f"   請到 Base Sepolia USDC 水龍頭，給下面地址領測試 USDC：")
                print(f"      {account.address}")
                print("   領完後重新跑一次本腳本即可。")
            return {"ok": False, "step": "payment-rejected", "http": r1.status_code, "body": body}
        task_id = None
        try:
            task_id = r1.json().get("task_id") or r1.json().get("taskId")
        except Exception:
            task_id = None
        if not task_id:
            print(f"!! 付款成功但未取得 task_id: {r1.text[:200]}")
            return {"ok": False, "step": "no-task-id"}
        print(f"   審計已派發！task_id = {task_id}")

        # Step 4: poll until the report is ready.
        print(f"[5/5] 等待審計完成（最多 {timeout_s} 秒）…")
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            await asyncio.sleep(10)
            rr = await client.get(f"{AUDIT_PATH}/{task_id}/report.md")
            if rr.status_code == 200:
                print("\n" + "=" * 72)
                print("審計報告（Markdown）")
                print("=" * 72)
                print(rr.text)
                return {"ok": True, "task_id": task_id}
            if rr.status_code == 404:
                print("!! task 不存在（可能已過期）")
                return {"ok": False, "step": "task-not-found"}
            # 409 not_ready -> keep waiting; 402 paid-but-not-bound is unexpected.
            if rr.status_code == 402:
                print(f"!! 報告被鎖（付款未綁定）：{rr.text[:200]}")
                return {"ok": False, "step": "report-payment-locked"}
        print("!! 等待審計超時。審計可能仍在 GitHub Actions 排隊或執行中。")
        print(f"   可用 task_id 稍後手動查看：{task_id}")
        return {"ok": False, "step": "timeout", "task_id": task_id}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", default=DEFAULT_ADDRESS, help="Contract address to audit")
    parser.add_argument("--timeout", type=int, default=600, help="Max seconds to wait for the audit")
    args = parser.parse_args()

    settings = _testnet_settings()
    key = os.environ.get("X402_DEMO_KEY") or _read_demo_key()
    if not key:
        print("!! 缺少 X402_DEMO_KEY（測試錢包私鑰）。請確認 .env 已設定。")
        return 1

    result = asyncio.run(run_demo(settings, key, args.address, args.timeout))
    if not result.get("ok"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())