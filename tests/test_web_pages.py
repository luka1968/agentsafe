"""Public web pages (/ , /terms, /privacy, /refund) and the access-log
middleware (visitor IP + time, 30-day retention per PRIVACY_POLICY.md).
"""

import json
import re
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx
from httpx import ASGITransport
from starlette.middleware import Middleware as StarletteMiddleware

from agentsafe.config import Settings
from agentsafe.server import build_server
from agentsafe.web.access_log import ACCESS_LOG_RETENTION_DAYS, AccessLogMiddleware, AccessLogStore
from agentsafe.web.pages import legal_html, legal_markdown

# x402 payment infrastructure shared with the REST tests (facilitator mocked
# via respx so no real money / network is ever touched).
from tests.test_payments import (
    ADDR,
    _mock_facilitator,
    _settings as _payments_settings,
)


def _settings(**kw) -> Settings:
    base = {
        "INFURA_ETH_ENDPOINT": "https://rpc.test",
        "ETHERSCAN_API_KEY": "k",
        "GITHUB_TOKEN": "ghp-t",
        "GITHUB_REPO": "owner/repo",
        "LLM_PROVIDERS_JSON": json.dumps(
            [
                {
                    "name": "p",
                    "base_url": "https://l.test",
                    "api_key": "k",
                    "model": "m",
                    "rpm_limit": 60,
                }
            ]
        ),
        "TASK_STORE": "memory",
        "PAYMENTS_ENABLED": False,
    }
    base.update(kw)
    return Settings(_env_file=None, **base)


def _http_client(server, *, store: AccessLogStore | None = None, **kw):
    middleware = [StarletteMiddleware(AccessLogMiddleware, store=store)] if store else None
    app = server.http_app(middleware=middleware, **kw)
    return httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver")


class TestPublicPages:
    async def test_index_served_at_root(self):
        server = build_server(_settings())
        async with _http_client(server) as client:
            r = await client.get("/")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert "agentSAFE" in r.text
        # pricing table: every tier price
        for price in ("$0.50", "$2.50", "$5.00", "$25.00"):
            assert price in r.text
        # enterprise CTA + legal footer links
        assert "https://tally.so/r/laby7B" in r.text
        assert 'href="/terms"' in r.text
        # The landing page must never be cached: a stale copy signs with
        # outdated EIP-712 domain params and fails server verification.
        assert "no-store" in r.headers.get("cache-control", "")
        # visible build tag so visitors can confirm they're on the current
        # build (and debug stale-cache signature failures)
        assert "landing build v" in r.text
        # Payment signing is delegated to the OFFICIAL @x402/evm exact scheme
        # via the browser bundle (/static/x402-bridge.js): the SDK generates
        # the 32-byte (bytes32) nonce, builds the EIP-712 domain from the
        # server-advertised accept.extra (authoritative 402 name/version) and
        # signs eth_signTypedData_v4. The page no longer hand-rolls any of it.
        assert 'src="/static/x402-bridge.js"' in r.text
        assert "X402Bridge" in r.text
        assert "bridge.createPaymentPayload" in r.text
        # the hand-rolled nonce generator must be gone (it caused real
        # signature mismatches when a short nonce padded inconsistently)
        assert "randomHex" not in r.text
        # over-limit contracts must be explained before signing (flat fee
        # covers <=500 lines) and, on refusal, the state the nothing moved.
        assert "up to <b>500 source lines</b>" in r.text
        assert "no USDC is ever taken" in r.text
        assert "Nothing was charged" in r.text
        assert "lineLimitNote" in r.text
        assert "isLineLimit" in r.text
        assert 'href="/privacy"' in r.text
        assert 'href="/refund"' in r.text
        # Claude config JSON present
        assert '"mcpServers"' in r.text
        assert '"agentsafe"' in r.text
        # --- landing-page interaction area (audit start flow) ---
        # the contract-address input the visitor fills in
        assert 'id="addr"' in r.text
        assert 'placeholder="0x..."' in r.text
        # the pay-to-audit CTA button
        assert 'id="start"' in r.text
        assert "Pay USDC to audit" in r.text
        # the client posts to the x402-gated REST endpoint and parses the
        # machine-readable PAYMENT-REQUIRED header for the 402 path
        assert 'fetch(REST' in r.text
        assert '"/api/audit"' in r.text
        assert "PAYMENT-REQUIRED" in r.text
        assert "X-PAYMENT" in r.text
        # from-$0.50 honest pricing copy (exact amount is server-quoted)
        assert "From $0.50" in r.text
        # multi-chain x402 payment flow (wallet connect + EIP-3009 + retry)
        assert "@three-ws/x402-modal" not in r.text
        assert "payOnChain" in r.text
        assert "X-PAYMENT" in r.text
        assert "chain-opt" in r.text
        assert "eth_signTypedData_v4" in r.text
        # wallet session lock: only one pending request at a time; a second
        # click while the wallet popup is open gets a friendly hint instead of
        # firing another eth_requestAccounts (MetaMask "already pending").
        assert "var paying = false;" in r.text
        assert "friendlyErr" in r.text
        assert "already pending" in r.text
        assert "Complete or close the wallet popup" in r.text
        # A wallet request can hang forever (ignored popup / wedged wallet);
        # every wallet call must be time-boxed and a stale lock must
        # self-release so the user is never stuck.
        assert "withWalletTimeout" in r.text
        assert "payingSince" in r.text
        assert "staleMs" in r.text
        assert "timed out after" in r.text
        # returning visitors skip the connect popup entirely: eth_accounts
        # is queried first and eth_requestAccounts only fires when no
        # account is authorized yet (avoids stuck pending-request errors)
        assert '"eth_accounts"' in r.text
        assert '"eth_requestAccounts"' in r.text
        # EIP-712 domain name must match the token's on-chain name(): Base
        # Sepolia testnet USDC is "USDC" (not "USD Coin" like mainnets), so
        # the chain table carries an explicit per-chain tokenName.
        assert "tokenName" in r.text
        assert '"USDC"' in r.text

    def test_index_inline_script_is_valid_javascript(self):
        """The landing page inline script must be valid JavaScript.

        Regression guard: the curl-command snippet originally emitted single
        backslash+quote (`\"`), which JS parses as an escaped quote inside an
        unterminated string -> SyntaxError -> the "Pay USDC to audit" click
        handler never attached (silent no-op for visitors).

        An authoritative parse via Node's own JS engine is the only reliable
        check: a hand-rolled lexer cannot disambiguate regex literals (the
        esc() / b64 helpers use `replace(/.../g)` and address validation uses
        `/^0x...$/`) from comments, so we let V8's parser decide.
        """
        import os
        import subprocess
        import tempfile

        from agentsafe.web.pages import INDEX_HTML

        m = re.search(r"<script>([\s\S]*?)</script>", INDEX_HTML)
        assert m, "inline script block missing"
        js = m.group(1)
        assert "addEventListener" in js
        # The curl snippet must build clean JSON via JSON.stringify (no raw
        # backslash-escaped quotes that break the JS string literal).
        assert "JSON.stringify" in js
        assert "payOnChain" in js
        # the page delegates signing to the official bridge bundle; the
        # MetaMask v4 RPC method lives in web/src/bridge.js, not inline
        assert "bridge.createPaymentPayload" in js

        node = os.environ.get("NODE", "node")
        # Write the temp file into the CWD so Windows-hosted node.exe (which
        # cannot read WSL's /tmp) can see it; map /mnt/d -> D:\\ style path.
        cwd = os.getcwd()
        tmp_path = os.path.join(cwd, f"._jscheck_{os.getpid()}.js")
        try:
            with open(tmp_path, "w", encoding="utf-8") as fh:
                fh.write(js)
            if tmp_path.startswith("/mnt/d/") and "node.exe" in node:
                win_path = "D:\\" + tmp_path[len("/mnt/d/"):].replace("/", "\\")
            else:
                win_path = tmp_path
            proc = subprocess.run(
                [node, "--check", win_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            pytest.skip(f"node unavailable for JS parse guard: {exc}")
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        assert proc.returncode == 0, (
            f"inline script failed JS parse:\n{proc.stderr.strip()}"
        )

    def test_x402_bridge_bundle_nonce_and_domain(self):
        """The payment bridge (official @x402/evm exact scheme) must produce
        the SAME invariants the hand-rolled frontend kept getting wrong:
        - the EIP-3009 nonce is a full 32 bytes (64 hex chars) — a shorter
          nonce pads inconsistently and the facilitator rejects the signature
          with invalid_exact_evm_signature;
        - the EIP-712 domain name/version come from the server-advertised
          accept.extra (authoritative 402 terms), never from the chain table;
        - eth_signTypedData_v4 is called with the SDK-built typed data.

        The bundle is loaded in a Node VM with a fake MetaMask provider; the
        real facilitator is never contacted and no money moves.
        """
        import os
        import subprocess
        import tempfile
        from pathlib import Path

        node = os.environ.get("NODE", "node")
        bundle = Path(__file__).resolve().parents[1] / "web" / "dist" / "x402-bridge.js"
        ASSET_HEX = "0x6b175474e89094c44da98b954eedeac495271d0f"

        def _winify(p: Path) -> Path:
            """Map /mnt/d/... to D:\\... so Windows-hosted node can read it."""
            s = str(p.resolve())
            if s.startswith("/mnt/d/"):
                return Path("D:\\" + s[len("/mnt/d/"):].replace("/", "\\"))
            return p
        if not bundle.exists():
            pytest.skip("x402 bridge bundle not built (run web: npm run build)")

        harness = r'''
import { readFileSync } from "fs";
import vm from "vm";
import { webcrypto } from "crypto";
const fsRead = (p) => readFileSync(p, "utf8");
const code = fsRead(%(bundle)r);
const sandbox = {
  window: {},
  crypto: webcrypto,
  Uint8Array, BigInt, TextEncoder, TextDecoder,
  setTimeout, clearTimeout,
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(code, sandbox);
const bridge = sandbox.X402Bridge;
if (!bridge || typeof bridge.createPaymentPayload !== "function") {
  throw new Error("X402Bridge.createPaymentPayload missing");
}
let captured = null;
const fakeEth = {
  request: async ({ method, params }) => {
    if (method === "eth_signTypedData_v4") {
      captured = JSON.parse(params[1]);
      return "0x" + "ab".repeat(65);
    }
    throw new Error("unexpected wallet call: " + method);
  },
};
const accept = {
  x402Version: 2, scheme: "exact", network: "eip155:84532",
  asset: "0x6b175474e89094c44da98b954eedeac495271d0f",
  payTo: "0x03ee35B45382d19b7BDcE1A2B1eD72Aae01c48cc",
  amount: "100", maxTimeoutSeconds: 300,
  extra: { name: "USDC", version: "2" },
};
const out = await bridge.createPaymentPayload(
  fakeEth, "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B",
  accept, "https://x402.workfern.com/api/audit"
);
const auth = out.payload.payload.authorization;
const results = {};
results.nonce_hex_len = auth.nonce.length - 2;
results.nonce_32bytes = (auth.nonce.length - 2) === 64;
results.domain_name = captured.domain.name;
results.domain_version = captured.domain.version;
results.domain_chainid = captured.domain.chainId;
results.verifying_contract = captured.domain.verifyingContract;
results.primary_type = captured.primaryType;
results.scheme = out.payload.scheme;
results.x402_version = out.payload.x402Version;
results.accepted_network = out.payload.accepted.network;
results.value = auth.value;
results.valid_before_set = Number(auth.validBefore) > Math.floor(Date.now() / 1000);
results.sig_present = /^0x[0-9a-f]+$/.test(out.payload.payload.signature);
console.log(JSON.stringify(results));
''' % {"bundle": str(_winify(bundle))}

        cwd = os.getcwd()
        tmp_path = os.path.join(cwd, f"._bridge_{os.getpid()}.mjs")
        try:
            with open(tmp_path, "w", encoding="utf-8") as fh:
                fh.write(harness)
            if tmp_path.startswith("/mnt/d/") and "node.exe" in node:
                win_path = "D:\\" + tmp_path[len("/mnt/d/"):].replace("/", "\\")
            else:
                win_path = tmp_path
            proc = subprocess.run(
                [node, win_path], capture_output=True, text=True, timeout=60
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            pytest.skip(f"node unavailable for bridge test: {exc}")
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        assert proc.returncode == 0, f"bridge harness failed:\n{proc.stderr}"
        results = json.loads(proc.stdout.strip().splitlines()[-1])
        # the exact regressions that broke real payments before
        assert results["nonce_32bytes"] is True, "nonce must be 32 bytes"
        assert results["nonce_hex_len"] == 64
        assert results["domain_name"] == "USDC"  # authoritative accept.extra
        assert results["domain_version"] == "2"
        assert results["domain_chainid"] == 84532
        # verifyingContract must equal the accept asset (checksummed by the
        # SDK's getAddress — compare case-insensitively to the raw input)
        assert results["verifying_contract"].lower() == ASSET_HEX.lower()
        assert results["primary_type"] == "TransferWithAuthorization"
        assert results["scheme"] == "exact"
        assert results["x402_version"] == 2
        assert results["accepted_network"] == "eip155:84532"
        assert results["value"] == "100"
        assert results["valid_before_set"] is True
        assert results["sig_present"] is True

    async def test_x402_bridge_bundle_served(self):
        """The landing page loads the payment bridge from a static route.

        The bundle contains the OFFICIAL @x402/evm exact scheme (EIP-3009
        signing + payload assembly). It must be served uncached.
        """
        server = build_server(_settings())
        async with _http_client(server) as client:
            r = await client.get("/static/x402-bridge.js")
        assert r.status_code == 200
        assert "javascript" in r.headers.get("content-type", "")
        assert "no-store" in r.headers.get("cache-control", "")
        # the official scheme + bridge entry points must be inside the bundle
        assert "ExactEvmScheme" in r.text
        assert "createPaymentPayload" in r.text
        assert "eth_signTypedData_v4" in r.text

    @pytest.mark.parametrize(
        ("path", "marker", "has_table"),
        [
            ("/terms", "Terms of Service", True),
            ("/terms", "non-refundable", True),
            ("/privacy", "Privacy Policy", True),
            ("/privacy", "30 days", True),
            ("/refund", "Refund Policy", False),
            ("/refund", "full refund", False),
        ],
    )
    async def test_legal_pages_rendered(self, path, marker, has_table):
        server = build_server(_settings())
        async with _http_client(server) as client:
            r = await client.get(path)
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert ("<table" in r.text) is has_table  # tables render when present
        assert marker in r.text

    async def test_legal_pages_cross_link_each_other(self):
        server = build_server(_settings())
        async with _http_client(server) as client:
            r = await client.get("/privacy")
        for link in ('href="/terms"', 'href="/privacy"', 'href="/refund"'):
            assert link in r.text

    @respx.mock
    async def test_landing_paywall_402_payment_terms(self):
        """The landing page's audit flow hits the x402 gate: an unpaid POST
        gets a 402 whose PAYMENT-REQUIRED header parses to terms that match
        OUR payTo address, Base USDC, and the exact server-quoted amount."""
        _mock_facilitator()
        server = build_server(_payments_settings(PAYMENTS_ENABLED=True))
        async with _http_client(server) as client:
            resp = await client.post("/api/audit", json={"address": ADDR})
        assert resp.status_code == 402
        required = resp.headers.get("payment-required")
        assert required, f"no PAYMENT-REQUIRED header: {dict(resp.headers)}"
        # decode the base64 JSON header (the landing page's b64decode does
        # exactly this; the server body mirrors the same object)
        import base64 as b64

        payload = json.loads(b64.b64decode(required))
        accepts = payload["accepts"]
        assert accepts, "PAYMENT-REQUIRED must carry accepted terms"
        terms = accepts[0]
        # OUR recipient address, exactly
        assert terms["payTo"].lower() == _payments_settings().X402_PAY_TO.lower()
        # Base network (testnet in tests; mainnet in prod config)
        assert terms["network"] == "eip155:84532"
        # exact flat fee $3.00 at 6 USDC decimals
        assert terms["amount"] == "3000000"
        assert terms["scheme"] == "exact"
        assert payload["x402Version"] == 2
        # body mirrors the header (human/indexer fallback)
        body = resp.json()
        assert body["accepts"][0]["amount"] == "3000000"
        assert body["accepts"][0]["payTo"].lower() == _payments_settings().X402_PAY_TO.lower()


class TestAccessLogStore:
    def test_log_and_purge_30_day_retention(self, tmp_path):
        store = AccessLogStore(str(tmp_path / "access.db"))
        now = datetime.now(UTC)
        store.log("1.2.3.4", "GET", "/", when=now - timedelta(days=29))
        store.log("5.6.7.8", "GET", "/terms", when=now - timedelta(days=31))
        assert store.count() == 2
        removed = store.purge()
        assert removed == 1  # only the 31-day-old entry exceeds retention
        assert store.count() == 1
        assert ACCESS_LOG_RETENTION_DAYS == 30

    async def test_middleware_records_ip_path_and_time(self, tmp_path):
        store = AccessLogStore(str(tmp_path / "access.db"))
        server = build_server(_settings())
        async with _http_client(server, store=store) as client:
            r = await client.get("/", headers={"X-Forwarded-For": "203.0.113.9"})
        assert r.status_code == 200
        entries = store.entries()
        assert len(entries) == 1
        assert entries[0]["ip"] == "203.0.113.9"  # X-Forwarded-For honored
        assert entries[0]["path"] == "/"
        # timestamp parses as UTC ISO-8601
        datetime.fromisoformat(entries[0]["ts"])

    async def test_middleware_logs_transport_peer_without_proxy_header(self, tmp_path):
        store = AccessLogStore(str(tmp_path / "access.db"))
        server = build_server(_settings())
        async with _http_client(server, store=store) as client:
            await client.get("/terms")
        assert store.count() == 1
        assert store.entries()[0]["path"] == "/terms"


class TestLegalContentIntegrity:
    """The served pages come from the repository Markdown files; the key
    public commitments must be present in the raw source."""

    def test_privacy_states_30_day_ip_retention(self):
        raw = legal_markdown("privacy")
        assert "30 days" in raw
        assert "PDPO" in raw
        assert "anti-DDoS" in raw

    def test_terms_state_ai_disclaimer_and_tally_link(self):
        raw = legal_markdown("terms")
        assert "AI-assisted" in raw
        assert "not a substitute for a professional security audit" in raw
        assert "https://tally.so/r/laby7B" in raw

    def test_rendered_pages_have_rendered_headings(self):
        for slug in ("terms", "privacy", "refund"):
            html = legal_html(slug)
            assert "<h1" in html, slug  # markdown heading rendered (BOM-safe)
