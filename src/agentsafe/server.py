"""FastMCP server - the AgentSafe MCP entry point.

Tools:
  audit_contract(address)        -> dispatch GitHub Actions audit, return task_id
  check_audit_status(task_id)   -> recoverable status + report when ready
  get_contract_info(address)    -> on-chain + verification snapshot

Modes:
  stdio  : local development / single-client (default)
  http   : remote deployment (run behind an authenticating proxy)

Payments: fail-closed x402 gate (Phase 12). PAYMENTS_ENABLED=false runs free
in dev mode; true requires the pinned official x402 SDK (see
payment/x402_adapter.py) and gates audit_contract with verify-before-execution
/ settle-after-execution. Report retrieval is bound to the verified payment.
"""

from __future__ import annotations

import base64
import json
import logging
import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Final

from fastmcp import Context, FastMCP
from fastmcp.tools import ToolResult
from starlette.requests import Request
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    Response,
)

from agentsafe import __version__
from agentsafe.config import Settings, validate_runtime_settings
from agentsafe.explorer import ContractNotVerifiedError, EtherscanClient, ExplorerError
from agentsafe.github_client import (
    ArtifactExpiredError,
    GitHubActionsClient,
    GitHubClientError,
    RunAssociationError,
)
from agentsafe.metrics import get_metrics
from agentsafe import notify
from agentsafe.payment.x402_adapter import (
    StarletteRequestAdapter,
    VerifiedPayment,
    X402PaymentAdapter,
)
from x402.http.facilitator_client_base import FacilitatorResponseError
import httpx
from agentsafe.pricing import (
    CUSTOM_PRICING_CONTACT_URL,
    ContractTooLargeError,
    audit_price_for_lines,
    count_source_lines,
    pricing_summary,
)
from agentsafe.report_render import (
    ReportRenderError,
    render_html,
    render_markdown,
    render_pdf,
)
from agentsafe.rpc import EthRpcClient
from agentsafe.schemas import AuditReport, TaskState, normalize_address
from agentsafe.task_store import open_task_store
from agentsafe.web import INDEX_HTML, LegalDocumentMissingError, legal_html

logger = logging.getLogger("agentSAFE.server")

# -------------------------------------------------------------- x402 REST API
# Machine-readable discovery (openapi.json, indexed by x402scan & co) plus a
# real x402-gated REST dispatch endpoint mirroring the MCP audit_contract
# flow. This is NOT part of the MCP protocol surface; it exists so that
# x402 indexers and plain-HTTP x402 clients can discover and pay for audits.
REST_AUDIT_PATH = "/api/audit"


def _clean_email(raw: Any) -> str | None:
    """Optional customer email from the dispatch body. Returns a trimmed,
    validated address or None; an invalid non-empty value raises ValueError
    (the dispatch responds 400 invalid_email). Empty/absent -> None (feature
    off for this task; audits without email keep working unchanged)."""
    if raw is None:
        return None
    email = str(raw).strip()
    if not email:
        return None
    if not notify.is_valid_email(email):
        raise ValueError(
            "email must be a valid address like name@example.com")
    return email


def _maybe_notify_report_ready(task_store, task_id: str, base_url: str,
                               report_markdown: str | None = None) -> None:
    """Send the single report-ready email when the customer supplied an
    address at dispatch. Idempotent by construction: the send happens only
    when the task has an email AND notified_at is unset; a successful send
    marks notified_at. Mail failures are logged, never raised, and leave
    notified_at unset so the next status/report probe retries."""
    try:
        task = task_store.get(task_id)
        if task is None or not task.email or task.notified_at is not None:
            return
        ok = notify.send_report_ready_email(
            task.email, task_id, base_url, report_markdown=report_markdown)
        if ok:
            task_store.mark_notified(task_id)
    except Exception:  # noqa: BLE001 - notification must never break the route
        logger.exception("report-ready notify failed task=%s", task_id)


def _base_url_from_request(request: Any) -> str:
    """Public base URL for report links (honors proxy headers on Vercel)."""
    try:
        host = (request.headers.get("x-forwarded-host")
                or request.headers.get("host") or "localhost")
        proto = (request.headers.get("x-forwarded-proto")
                 or ("https" if "workfern.com" in host or "vercel.app" in host
                     else "http"))
        return f"{proto}://{host}"
    except Exception:  # noqa: BLE001 - best-effort only
        return ""
# The REST endpoint's flat fee (X402_REST_PRICE) only covers contracts up to
# this many source lines on mainnet chains. Larger contracts must use the MCP
# endpoint's tiered pricing (audit_contract) or the enterprise channel; this
# cap prevents the flat REST fee from undercutting the higher MCP tiers.
# The testnet cap is deliberately higher (Settings.X402_REST_TESTNET_MAX_LINES)
# so end-to-end tests can exercise larger contracts on the free test channel
# without touching mainnet pricing semantics.
REST_AUDIT_MAX_LINES = 500
# Testnet networks (per-chain) get the relaxed cap. Paying on any of these
# networks means the caller used the testnet channel, where REST audits up to
# the testnet cap are allowed.
TESTNET_CHAIN_IDS: Final[set[str]] = {"84532"}  # Base Sepolia


def _rest_max_lines_for_network(
    settings: Settings,
    network: str | None,
) -> int:
    """Effective REST source-line cap for the network the payment used.

    Mainnet (or unknown) networks keep the flat-fee cap; testnet networks
    (chain id in TESTNET_CHAIN_IDS) use the relaxed testnet cap so larger
    contracts can be audited end-to-end on the free test channel.
    """
    if network:
        for chain_id in TESTNET_CHAIN_IDS:
            if network.endswith(f":{chain_id}"):
                return settings.X402_REST_TESTNET_MAX_LINES
    return settings.X402_REST_MAX_LINES


class _SlidingWindowLimiter:
    """Per-key sliding-window rate limiter (Stage 11 HTTP hardening).

    Tracks request timestamps per client key (default: client IP); a request
    is allowed when fewer than ``rate`` requests were seen in the last
    ``window_seconds``. Memory-bounded: keys are evicted when their window
    is empty. Thread-safe. Used on REST endpoints only — MCP tool calls are
    never rate limited by this.
    """

    __slots__ = ("_rate", "_window", "_seen", "_lock")

    def __init__(self, rate: int, window_seconds: float = 60.0) -> None:
        self._rate = max(1, int(rate))
        self._window = float(window_seconds)
        self._seen: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            dq = self._seen.get(key)
            if dq is None:
                self._seen[key] = [now]
                return True
            while dq and now - dq[0] > self._window:
                dq.pop(0)
            if not dq:
                self._seen[key] = [now]
                return True
            if len(dq) >= self._rate:
                return False
            dq.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._seen.clear()


_OPENAPI_FILE = Path(__file__).resolve().parents[2] / "openapi.json"
_FAVICON_FILE = Path(__file__).resolve().parents[2] / "favicon.ico"
_LOGO_FILE = Path(__file__).resolve().parents[2] / "logo.png"
# Browser bundle bridging the landing page to the official @x402/evm scheme.
# Built from web/src/bridge.js (esbuild IIFE); committed so the serverless
# build needs no node/npm step.
_X402_BRIDGE_PATH = Path(__file__).resolve().parents[2] / "web" / "dist" / "x402-bridge.js"

mcp: FastMCP | None = None


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    # httpx logs full request URLs at INFO; Etherscan URLs embed the API key
    # as a query parameter, so those lines must never be emitted.
    logging.getLogger("httpx").setLevel(logging.WARNING)


def _log_payment_error(ctx: Any, instr: Any, body_bytes: bytes) -> None:
    """Emit a high-cardinality diagnostic when the facilitator rejects a
    payment, so the browser-signed domain can be reconciled with the
    facilitator's expectation (root cause of ``invalid_exact_evm_signature``
    is usually a name/version/chainId/asset domain mismatch or a wallet
    account mismatch). Extracts the signed domain from the submitted payload
    and logs it alongside the exact rejection reason.
    """
    try:
        reason = (instr.body or {}).get("error") if isinstance(instr.body, dict) else None
        if not reason:
            reason = getattr(instr, "status", None)
        # Payload arrives in the X-PAYMENT header (base64) and/or body. Pull
        # the EIP-712 domain components the browser actually signed with.
        # The header is decoded with the SDK's official codec
        # (decode_payment_signature_header) so diagnostics always see the
        # payload exactly as the payment layer parses it.
        import json as _json

        from x402.http.utils import decode_payment_signature_header

        doc = None
        try:
            for h in ("PAYMENT-SIGNATURE", "X-PAYMENT", "x-payment"):
                hdr = (ctx.request.headers.get(h) if hasattr(ctx, "request") else None)
                if hdr:
                    doc = decode_payment_signature_header(hdr)
                    break
        except Exception:  # noqa: BLE001
            doc = None
        if doc is None:
            # Diagnostics-only lenient fallback: this function's entire job is
            # to surface MALFORMED payment payloads (the payment flow itself
            # rejects them), so a strict SDK parse failure must not blind it.
            # The lenient read never feeds verification or settlement.
            from base64 import b64decode as _b64decode

            try:
                for h in ("PAYMENT-SIGNATURE", "X-PAYMENT", "x-payment"):
                    hdr = (ctx.request.headers.get(h) if hasattr(ctx, "request") else None)
                    if hdr:
                        doc = _json.loads(_b64decode(hdr))
                        break
            except Exception:  # noqa: BLE001
                doc = None
        if doc is None and body_bytes:
            try:
                doc = _json.loads(body_bytes)
            except Exception:  # noqa: BLE001
                doc = None
        signed = {}
        if doc is not None:
            try:
                if isinstance(doc, dict):
                    acc = doc.get("accepted", doc.get("requirements", {})) or {}
                    auth = (doc.get("payload", {}) or {}).get("authorization", {}) or {}
                else:
                    # Official PaymentPayload model (by_alias camelCase dump)
                    dumped = doc.model_dump(by_alias=True, exclude_none=True)
                    acc = dumped.get("accepted", {}) or {}
                    auth = (dumped.get("payload", {}) or {}).get("authorization", {}) or {}
                signed = {
                    "network": acc.get("network"),
                    "asset": acc.get("asset"),
                    "payTo": acc.get("payTo"),
                    "amount": acc.get("amount"),
                    "extra": acc.get("extra"),
                    "auth_from": auth.get("from"),
                    "auth_to": auth.get("to"),
                    "auth_nonce_hex_len": (
                        (len(str(auth.get("nonce", ""))) - 2) if auth.get("nonce") else None
                    ),
                }
            except Exception:  # noqa: BLE001
                signed = {"unparseable": True}
        logger.warning(
            "REST payment rejected reason=%r signed=%r",
            reason,
            signed,
        )
    except Exception:  # noqa: BLE001 - diagnostics must never break the request
        logger.warning("REST payment rejected (diagnostics unavailable)")


def build_server(settings: Settings, *, validate: bool = True) -> FastMCP:
    """Construct the FastMCP instance. Fails fast on bad config.

    validate=False defers configuration validation to server startup via a
    lifespan hook. Used for cloud deployments (FastMCP Cloud / Horizon)
    where build-time inspection runs without environment variables; a
    misconfigured deployment still refuses to serve at runtime.
    """
    if validate:
        validate_runtime_settings(settings)  # raises SettingsError with ALL problems

    # Stage 11 HTTP hardening: per-client-IP sliding window limiter for the
    # REST surface only (MCP tools are not HTTP).
    limiter = _SlidingWindowLimiter(
        rate=settings.HTTP_RATE_LIMIT_PER_MINUTE, window_seconds=60.0
    )

    # Task store: explicit TASK_STORE wins; otherwise auto-selected from the
    # environment - 'redis' when a Redis/Upstash URL is detectable (serverless
    # safe, survives cold starts), else 'sqlite' for durable local state.
    store_mode = settings.resolved_task_store
    task_store = open_task_store(
        store_mode,
        Path(settings.TASK_DB_PATH),
        redis_url=settings.effective_redis_url if store_mode == "redis" else "",
        retention_days=settings.ARTIFACT_RETENTION_DAYS,
        dsn=settings.payment_database_url if store_mode == "postgres" else "",
    )

    # Payments gate (fail-closed; disabled = dev no-op). When the task store
    # is the Postgres store, its payments table is the authoritative replay /
    # state machine; the adapter uses it (replay_store) so MCP-tool payments
    # enjoy the same atomic replay protection as the REST flow.
    payment = X402PaymentAdapter(
        enabled=settings.PAYMENTS_ENABLED,
        sdk_version=settings.X402_SDK_VERSION,
        network=settings.X402_NETWORK,
        pay_to=settings.X402_PAY_TO,
        facilitator_url=settings.X402_FACILITATOR_URL,
        price=settings.X402_PRICE,
        asset=settings.X402_ASSET,
        max_timeout_seconds=settings.X402_MAX_TIMEOUT_SECONDS,
        extra_networks=settings.multichain_networks,
        replay_store=task_store if hasattr(task_store, "reserve_payment") else None,
    )
    # Re-arm replay protection: payloads already consumed before a restart
    # must stay rejected (bounded by the task-store retention window).
    if payment.enabled:
        payment.seed_replay_ledger(task_store.payment_refs())
    # Reconcile ambiguous settlements at startup (PROMPT 5): rows left in
    # SETTLEMENT_PENDING with a stored transaction hash (e.g. an on-chain
    # settlement that confirmed right before a database write failed) are
    # moved to SETTLED idempotently.
    if hasattr(task_store, "reconcile_pending_settlements"):
        try:
            reconciled = task_store.reconcile_pending_settlements()
            if reconciled:
                logger.info("reconciled %d pending settlements to settled", len(reconciled))
        except Exception:  # noqa: BLE001 - reconciliation must never block startup
            logger.exception("postgres settlement reconciliation failed at startup")

    gh = GitHubActionsClient(
        token=settings.GITHUB_TOKEN,
        repo=settings.GITHUB_REPO,
        workflow_file=settings.GITHUB_WORKFLOW_FILE,
        ref=settings.GITHUB_REF,
        timeout_seconds=settings.GITHUB_API_TIMEOUT_SECONDS,
        poll_interval_seconds=settings.GITHUB_POLL_INTERVAL_SECONDS,
        resolve_attempts=settings.GITHUB_RUN_RESOLVE_ATTEMPTS,
        strict=validate,
    )

    rpc = EthRpcClient(settings.INFURA_ETH_ENDPOINT)
    explorer = EtherscanClient(
        settings.ETHERSCAN_API_KEY,
        base_url=settings.ETHERSCAN_BASE_URL,
        strict=validate,
    )

    # Official x402 HTTP flow for the REST endpoint (payments-enabled only).
    # Built once per process and shares the adapter's already-initialized
    # x402ResourceServer (facilitator /supported cached at adapter startup),
    # so no extra startup round-trips. Indexers like x402scan hit
    # POST /api/audit without payment and receive the official 402 wire
    # format (PAYMENT-REQUIRED header + body quoting X402_REST_PRICE).
    x402_http = None
    if payment.enabled:
        from x402.http import PaymentOption, RouteConfig

        # Build one PaymentOption per accepted chain (primary first, then any
        # extra chains from X402_NETWORKS_JSON). Each carries its own asset
        # and pay_to so x402 clients can settle on Base, Arbitrum, Polygon,
        # or any other configured chain.
        def _primary_rest_price(settings: Any) -> str:
            """Advertised flat fee for the PRIMARY REST network. A testnet
            primary (X402_NETWORK == Base Sepolia) charges the nominal
            X402_TESTNET_PRICE instead of the real-money X402_REST_PRICE."""
            if str(settings.X402_NETWORK).strip() == str(settings.X402_NETWORK_TESTNET).strip():
                return settings.X402_TESTNET_PRICE
            return settings.X402_REST_PRICE

        def _payment_option(net: str, pay_to: str, asset: str, price: str | None = None) -> PaymentOption:
            extra = {"asset": asset} if asset else None
            # The EIP-712 domain name/version the frontend must sign with
            # must equal the values the SDK will verify against. The SDK
            # fills them from its asset registry (get_asset_info); mirror
            # that here so the 402 response carries the authoritative
            # domain (Base mainnet USDC is "USD Coin", Base Sepolia
            # testnet USDC is "USDC" - the frontend must never hardcode
            # either).
            if asset:
                try:
                    from x402.mechanisms.evm.utils import get_asset_info

                    info = get_asset_info(net, asset)
                    extra = {
                        **(extra or {}),
                        "name": info["name"],
                        "version": info.get("version", "2"),
                    }
                except Exception:  # noqa: BLE001 - asset not in registry: no domain info
                    pass
            return PaymentOption(
                scheme="exact",
                pay_to=pay_to,
                price=price or settings.X402_REST_PRICE,
                network=net,
                max_timeout_seconds=settings.X402_MAX_TIMEOUT_SECONDS,
                extra=extra,
            )

        rest_accepts: list[PaymentOption] = [
            _payment_option(
                payment.network,
                payment.pay_to,
                settings.X402_ASSET,
                _primary_rest_price(settings),
            )
        ]
        for net, terms in payment.extra_networks.items():
            rest_accepts.append(
                _payment_option(net, terms["pay_to"], terms["asset"], terms.get("price"))
            )

        x402_http = payment.http_resource_server(
            {
                f"POST {REST_AUDIT_PATH}": RouteConfig(
                    accepts=rest_accepts,
                    description="AI smart-contract risk audit dispatch (x402-paid)",
                    mime_type="application/json",
                    service_name="agentSAFE",
                    tags=["smart-contract-audit", "ai-audit", "base"],
                )
            }
        )

        def _canonical_request_url(request: Request) -> str:
            """The externally visible URL the SDK used to build the 402 terms
            (forwarded-proxy aware). A payment payload is only bound to THIS
            resource when its resource.url matches."""
            return StarletteRequestAdapter(request, parsed_body=None).get_url()

        def _validate_payment_binding(request: Request, result: Any) -> JSONResponse | None:
            """Step B binding checks on a facilitator-verified payment.

            Runs AFTER SDK verification (signature, facilitator policy) and
            BEFORE replay recording, so a rejected binding never consumes a
            payment fingerprint. Returns a 402/500 JSONResponse to reject, or
            None when every binding holds:

            1. protocol version — v2 only (this service speaks exactly one
               version; a v1 payload must never be silently upgraded);
            2. request/resource association — the signed payload must name
               THIS endpoint. The exact scheme signs only (from, to, value,
               window, nonce): without this check the same authorization
               bytes could be presented to a different x402 resource;
            3. server-side terms conformance — network/asset/recipient/scheme
               of the MATCHED requirements must equal the centralized network
               configuration. The matched requirements are server-built (the
               client echo is compared by the SDK), so a mismatch here is a
               server integrity failure -> fail closed with 500;
            4. authorization validity window — a local, cheap check that the
               signed window is currently open (the facilitator also verifies
               this; belt and braces with an actionable error).
            """
            from agentsafe.payment.networks import X402_PROTOCOL_VERSION

            payload = result.payment_payload
            reqs = result.payment_requirements

            # 1) protocol version
            if int(getattr(payload, "x402_version", 0)) != X402_PROTOCOL_VERSION:
                return JSONResponse(
                    {
                        "ok": False,
                        "error_code": "unsupported_protocol_version",
                        "error": (
                            "payment payload uses x402 protocol version "
                            f"{getattr(payload, 'x402_version', None)!r}; this "
                            f"service requires version {X402_PROTOCOL_VERSION}"
                        ),
                    },
                    status_code=402,
                )

            # 2) request/resource association
            resource = getattr(payload, "resource", None)
            resource_url = str(getattr(resource, "url", "") or "") if resource is not None else ""
            canonical = _canonical_request_url(request)
            if not resource_url:
                return JSONResponse(
                    {
                        "ok": False,
                        "error_code": "payment_resource_missing",
                        "error": (
                            "payment payload does not identify the paid resource; "
                            f"expected {canonical}"
                        ),
                    },
                    status_code=402,
                )
            if resource_url.rstrip("/") != canonical.rstrip("/"):
                return JSONResponse(
                    {
                        "ok": False,
                        "error_code": "payment_resource_mismatch",
                        "error": (
                            "payment payload was signed for a different resource "
                            f"({resource_url}); expected {canonical}"
                        ),
                    },
                    status_code=402,
                )

            # 3) server-side terms conformance (defense in depth)
            cfgs = {c.identifier: c for c in settings.payment_network_configs()}
            cfg = cfgs.get(str(getattr(reqs, "network", "")))
            if (
                cfg is None
                or str(getattr(reqs, "scheme", "")) not in ("exact",)
                or str(getattr(reqs, "pay_to", "")).lower() != cfg.pay_to.lower()
                or str(getattr(reqs, "asset", "")).lower() != cfg.usdc_address.lower()
            ):
                # The requirements were built by this server from its own
                # configuration; a divergence cannot be caused by the client.
                logger.error(
                    "payment binding integrity failure: network=%r pay_to=%r asset=%r",
                    getattr(reqs, "network", None),
                    getattr(reqs, "pay_to", None),
                    getattr(reqs, "asset", None),
                )
                return JSONResponse(
                    {
                        "ok": False,
                        "error_code": "payment_config_mismatch",
                        "error": "verified payment does not match the server's payment configuration",
                    },
                    status_code=500,
                )

            # 4) signed authorization validity window (seconds since epoch)
            inner = getattr(payload, "payload", None)
            auth = inner.get("authorization") or {} if isinstance(inner, dict) else {}
            now = int(time.time())

            def _to_int(name: str) -> int | None:
                raw = auth.get(name)
                if raw in (None, ""):
                    return None
                try:
                    return int(str(raw))
                except (TypeError, ValueError):
                    return None

            valid_before = _to_int("validBefore")
            valid_after = _to_int("validAfter")
            if valid_before is not None and now >= valid_before:
                return JSONResponse(
                    {
                        "ok": False,
                        "error_code": "payment_authorization_expired",
                        "error": "the signed payment authorization has expired; request new payment terms and retry",
                    },
                    status_code=402,
                )
            if valid_after is not None and now < valid_after:
                return JSONResponse(
                    {
                        "ok": False,
                        "error_code": "payment_authorization_not_yet_valid",
                        "error": "the signed payment authorization is not valid yet",
                    },
                    status_code=402,
                )
            return None

    @asynccontextmanager
    async def _startup_validation(server: FastMCP) -> AsyncIterator[None]:
        if not validate:
            # Cloud mode: env vars only exist at runtime, so fail fast HERE.
            validate_runtime_settings(Settings())
        yield None

    app = FastMCP(
        "agentSAFE",
        instructions=(
            "EVM smart-contract audit MCP (Ethereum Mainnet). AI-assisted risk "
            "screening, NOT a formal security audit. Findings require human "
            "verification before any action."
        ),
        lifespan=_startup_validation,
        # Production safety: clients never receive internal stack traces or
        # environment-derived error details from a crashing tool; full
        # details stay in the service logs.
        mask_error_details=True,
    )

    @app.tool
    async def health() -> dict[str, Any]:
        """Liveness/config probe. Safe, non-paid, and never returns secrets.

        Use this to verify a deployment (public endpoint reachability,
        tool discovery) without triggering an audit or a payment.
        """
        return {
            "ok": True,
            "service": "agentSAFE",
            "version": __version__,
            "chain": "ethereum-mainnet",
            "payments": {
                "enabled": payment.enabled,
                "network": settings.X402_NETWORK if payment.enabled else None,
                "pricing": pricing_summary(),
            },
            "task_store": getattr(settings, "TASK_STORE", "sqlite"),
            "audit_workflow": settings.GITHUB_WORKFLOW_FILE,
            "terms_of_service": "https://github.com/luka1968/agentsafe/blob/main/TERMS_OF_SERVICE.md",
            "web_pages": {
                "/": "landing",
                "/terms": "Terms of Service",
                "/privacy": "Privacy Policy",
                "/refund": "Refund Policy",
                "/openapi.json": "OpenAPI discovery document (x402scan indexing)",
                "/api/audit": "x402 REST audit dispatch (paid, see /openapi.json)",
            },
        }

    # ------------------------------------------------------- public web pages
    # Served by the HTTP transport (http_app): the legal Markdown files are
    # the same single source of truth linked from the health tool.

    @app.custom_route("/", methods=["GET"])
    async def _index(request: Request) -> HTMLResponse:
        # The landing page carries the inline wallet-signing JS. A stale
        # cached copy signs with outdated EIP-712 domain parameters and
        # fails server verification, so the page must never be cached.
        return HTMLResponse(
            INDEX_HTML, headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"}
        )

    @app.custom_route("/terms", methods=["GET"])
    async def _terms(request: Request) -> HTMLResponse:
        try:
            return HTMLResponse(legal_html("terms"))
        except LegalDocumentMissingError as exc:
            return PlainTextResponse(str(exc), status_code=500)

    @app.custom_route("/privacy", methods=["GET"])
    async def _privacy(request: Request) -> HTMLResponse:
        try:
            return HTMLResponse(legal_html("privacy"))
        except LegalDocumentMissingError as exc:
            return PlainTextResponse(str(exc), status_code=500)

    @app.custom_route("/refund", methods=["GET"])
    async def _refund(request: Request) -> HTMLResponse:
        try:
            return HTMLResponse(legal_html("refund"))
        except LegalDocumentMissingError as exc:
            return PlainTextResponse(str(exc), status_code=500)

    @app.custom_route("/static/x402-bridge.js", methods=["GET"])
    async def _x402_bridge(request: Request) -> Response:
        """Serve the browser bundle that bridges the landing page to the
        official @x402/evm exact scheme (EIP-3009 signing + payload assembly).
        Built from web/src/bridge.js via esbuild; committed to the repo so the
        serverless build needs no compile step. It must not be cached: a stale
        bundle may sign with outdated protocol details.
        """
        try:
            body = _X402_BRIDGE_PATH.read_bytes()
        except OSError as exc:
            logger.error("x402-bridge.js unavailable: %s", exc)
            return PlainTextResponse("payment module unavailable", status_code=500)
        return Response(
            body,
            media_type="application/javascript; charset=utf-8",
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                "Content-Length": str(len(body)),
            },
        )

    # ------------------------------------------------ x402 REST API (x402scan)

    @app.custom_route("/openapi.json", methods=["GET"])
    async def _openapi(request: Request) -> Response:
        """Machine-readable discovery document for x402 indexers."""
        try:
            spec = json.loads(_OPENAPI_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("openapi.json unavailable at %s: %s", _OPENAPI_FILE, exc)
            return PlainTextResponse(
                "openapi discovery document unavailable", status_code=500
            )
        return JSONResponse(spec)

    @app.custom_route("/.well-known/openapi.json", methods=["GET"])
    async def _openapi_wellknown(request: Request) -> Response:
        """Alias used by x402scan & discovery crawlers that probe the well-known
        path instead of the root OpenAPI file."""
        try:
            spec = json.loads(_OPENAPI_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("openapi.json unavailable at %s: %s", _OPENAPI_FILE, exc)
            return PlainTextResponse(
                "openapi discovery document unavailable", status_code=500
            )
        return JSONResponse(spec)

    @app.custom_route("/logo.png", methods=["GET"])
    async def _logo(request: Request) -> Response:
        """512x512 brand logotype for directory listings (x402scan
        'Logotype URL' field and similar) that prefer PNG over ICO."""
        try:
            data = _LOGO_FILE.read_bytes()
        except OSError as exc:
            logger.error("logo.png unavailable at %s: %s", _LOGO_FILE, exc)
            return PlainTextResponse("logo unavailable", status_code=404)
        return Response(
            content=data,
            media_type="image/png",
            headers={"cache-control": "public, max-age=3600"},
        )

    @app.custom_route("/favicon.ico", methods=["GET"])
    async def _favicon(request: Request) -> Response:
        """API-root icon surfaced by x402scan listings and browser tabs."""
        try:
            data = _FAVICON_FILE.read_bytes()
        except OSError as exc:
            logger.error("favicon.ico unavailable at %s: %s", _FAVICON_FILE, exc)
            return PlainTextResponse("favicon unavailable", status_code=404)
        return Response(
            content=data,
            media_type="image/x-icon",
            # Short TTL: lets icon updates propagate within an hour across
            # browser + CDN caches (x402scan hotlinks this URL directly).
            headers={"cache-control": "public, max-age=3600"},
        )

    @app.custom_route(REST_AUDIT_PATH, methods=["POST"])
    async def _api_audit(request: Request) -> Response:
        """x402-gated REST audit dispatch (documented in openapi.json).

        Fail-closed mirror of the MCP audit_contract flow:
          no payment     -> official x402 402 (PAYMENT-REQUIRED header + body)
          replay         -> 402, payload never accepted twice
          verified       -> source-size guard BEFORE settlement (flat-fee cap),
                            task dispatch, settlement AFTER successful dispatch
          dispatch fail  -> settlement NOT attempted (no funds ever move)
        Stage 11: per-IP rate limit + bounded body size before any parsing.
        """
        met = get_metrics()
        met.incr("http_requests")
        client_key = request.client.host if request.client else "unknown"
        if not limiter.allow(client_key):
            met.incr("http_rate_limited")
            return JSONResponse(
                {
                    "ok": False,
                    "error_code": "rate_limited",
                    "error": "too many requests; retry later",
                },
                status_code=429,
            )
        # Content-Length guard before reading (defends against oversized bodies).
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit():
            if int(content_length) > settings.HTTP_MAX_BODY_BYTES:
                met.incr("http_body_rejected")
                return JSONResponse(
                    {
                        "ok": False,
                        "error_code": "body_too_large",
                        "error": "request body exceeds the maximum allowed size",
                    },
                    status_code=413,
                )
        if x402_http is None:
            # Dev mode (payments disabled): free dispatch, mirrors free MCP tools.
            body_bytes = await request.body()
            if len(body_bytes) > settings.HTTP_MAX_BODY_BYTES:
                get_metrics().incr("http_body_rejected")
                return JSONResponse(
                    {
                        "ok": False,
                        "error_code": "body_too_large",
                        "error": "request body exceeds the maximum allowed size",
                    },
                    status_code=413,
                )
            try:
                parsed_body = json.loads(body_bytes) if body_bytes else None
            except json.JSONDecodeError:
                get_metrics().incr("http_bad_json")
                parsed_body = None
            return await _dispatch_audit_rest(request, None, parsed_body, None)
        try:
            from x402.http import HTTPRequestContext

            body_bytes = await request.body()
            if len(body_bytes) > settings.HTTP_MAX_BODY_BYTES:
                get_metrics().incr("http_body_rejected")
                return JSONResponse(
                    {
                        "ok": False,
                        "error_code": "body_too_large",
                        "error": "request body exceeds the maximum allowed size",
                    },
                    status_code=413,
                )
            try:
                parsed_body = json.loads(body_bytes) if body_bytes else None
            except json.JSONDecodeError:
                get_metrics().incr("http_bad_json")
                parsed_body = None
            ctx = HTTPRequestContext(
                adapter=StarletteRequestAdapter(request, parsed_body=parsed_body),
                path=REST_AUDIT_PATH,
                method="POST",
            )
            # Step B gate 0 — protocol version, BEFORE the SDK flow. The SDK
            # decodes a v1 payload into PaymentPayloadV1, which lacks the v2
            # fields and crashes inside find_matching_requirements
            # (AttributeError -> 500). Using the OFFICIAL decoder here turns a
            # cross-version payment into a clean 402 rejection. A payload that
            # fails to decode at all is left to the SDK's official
            # invalid-payload handling.
            payment_header = request.headers.get("payment-signature") or request.headers.get(
                "x-payment"
            )
            if payment_header:
                from x402.http.utils import decode_payment_signature_header
                from x402.schemas import PaymentPayloadV1

                try:
                    decoded_payment = decode_payment_signature_header(payment_header)
                except Exception:  # noqa: BLE001 - SDK owns malformed-payload errors
                    decoded_payment = None
                if isinstance(decoded_payment, PaymentPayloadV1):
                    logger.info("REST payment rejected: v1 payload on a v2-only service")
                    return JSONResponse(
                        {
                            "ok": False,
                            "error_code": "unsupported_protocol_version",
                            "error": (
                                "payment payload uses x402 protocol version 1; "
                                "this service requires version 2"
                            ),
                        },
                        status_code=402,
                    )
            try:
                result = await x402_http.process_http_request(ctx)
            except FacilitatorResponseError:
                # Fail closed: the facilitator answered with malformed /
                # schema-invalid data. Verification is INCONCLUSIVE, so the
                # payment is not accepted, nothing is dispatched, and the
                # client gets a clean upstream error (never a silent pass).
                logger.warning("REST payment rejected: facilitator malformed response")
                return JSONResponse(
                    {
                        "ok": False,
                        "error_code": "facilitator_malformed",
                        "error": "payment verification failed (facilitator returned malformed data)",
                    },
                    status_code=502,
                )
            except (httpx.TimeoutException, httpx.TransportError):
                # Fail closed: timeout / transport failure is an inconclusive
                # verification, not a payment success or a simple retry-able
                # 402 (the payload must be treated as consumed-pending until
                # proven otherwise).
                logger.warning("REST payment rejected: facilitator unreachable")
                return JSONResponse(
                    {
                        "ok": False,
                        "error_code": "facilitator_unreachable",
                        "error": "payment verification failed (facilitator unreachable)",
                    },
                    status_code=502,
                )
            if result.type == "payment-error":
                instr = result.response
                assert instr is not None  # SDK contract: error carries instructions
                headers = {
                    k: v for k, v in (instr.headers or {}).items() if k.lower() != "content-type"
                }
                # Resolve the machine-readable error body. The SDK usually
                # carries the full payment-required object ONLY in the base64
                # PAYMENT-REQUIRED header and leaves instructions.body empty,
                # so decode the header when the body is not already a dict.
                effective_body: dict | None = None
                if isinstance(instr.body, dict) and instr.body:
                    effective_body = instr.body
                else:
                    required_header = headers.get("PAYMENT-REQUIRED") or headers.get(
                        "payment-required"
                    )
                    if required_header:
                        try:
                            decoded = json.loads(base64.b64decode(required_header).decode("utf-8"))
                            if isinstance(decoded, dict):
                                effective_body = decoded
                        except Exception:  # noqa: BLE001 - fall back to minimal body
                            logger.warning(
                                "could not decode PAYMENT-REQUIRED header for body mirror"
                            )
                # Facilitator infrastructure failure (timeout / malformed /
                # HTTP error from the facilitator itself): the SDK folds the
                # exception into a generic payment-error 402, but an
                # INCONCLUSIVE verification must never be answered with
                # "please pay again" (double-payment risk). Map the guarded
                # marker to a fail-closed 502 before anything is dispatched.
                from agentsafe.payment.x402_adapter import _FACILITATOR_INFRA_PREFIX

                _err = str((effective_body or {}).get("error") or "")
                if _err.startswith(_FACILITATOR_INFRA_PREFIX):
                    infra_kind = _err[len(_FACILITATOR_INFRA_PREFIX):].split(":", 1)[0]
                    logger.warning(
                        "REST payment rejected: facilitator infrastructure failure (%s)",
                        infra_kind,
                    )
                    return JSONResponse(
                        {
                            "ok": False,
                            "error_code": (
                                "facilitator_unreachable"
                                if infra_kind == "unreachable"
                                else "facilitator_malformed"
                            ),
                            "error": (
                                "payment verification failed (facilitator "
                                f"{infra_kind}); retry after the facilitator recovers"
                            ),
                        },
                        status_code=502,
                    )
                # Diagnostic: log why payment was rejected (e.g.
                # invalid_exact_evm_signature) so the frontend's signed
                # domain can be reconciled with the facilitator's expectation.
                _log_payment_error(ctx, instr, body_bytes)
                # Official x402 v2 wire format carries the machine-readable
                # requirements in the base64 PAYMENT-REQUIRED header with an
                # empty body. Mirror the decoded JSON into the body as well:
                # the body is free-form per spec, and human/indexer fallback
                # parsers (x402scan variants) get the terms without having to
                # decode the header.
                body = effective_body if effective_body is not None else {"error": "Payment Required"}
                return JSONResponse(body, status_code=instr.status, headers=headers)
            if result.type != "payment-verified" or result.payment_payload is None:
                return JSONResponse(
                    {
                        "ok": False,
                        "error_code": "payment_required",
                        "error": "Payment Required",
                    },
                    status_code=402,
                )
            # Step B binding checks (protocol version, resource association,
            # server-side terms conformance, authorization validity window).
            # These run on the SDK-verified payload BEFORE replay recording so
            # a rejected binding never consumes a payment fingerprint.
            binding_error = _validate_payment_binding(request, result)
            if binding_error is not None:
                return binding_error
            ref = X402PaymentAdapter.payment_ref(result.payment_payload)
            # Postgres store: atomic, database-backed replay protection
            # (UNIQUE payload_ref). The in-memory ledger is only used by
            # memory/sqlite/redis stores - never the sole guard for Neon.
            payment_row: dict | None = None
            if hasattr(task_store, "reserve_payment"):
                try:
                    payment_row = task_store.reserve_payment(
                        ref,
                        payer=_payer_from_payload(result.payment_payload),
                        network=str(result.payment_requirements.network),
                        chain_id=_chain_id_from_network(str(result.payment_requirements.network)),
                        token_contract=str(result.payment_requirements.asset),
                        token_decimals=6,
                        amount=str(result.payment_requirements.amount),
                        recipient=str(result.payment_requirements.pay_to),
                        scheme=str(result.payment_requirements.scheme),
                        protocol_version=X402_PROTOCOL_VERSION,
                    )
                except InvalidPaymentTransition:
                    logger.error("REST payment reserve failed to register ref=%s", ref[:16])
                    return JSONResponse(
                        {"ok": False, "error_code": "internal_error",
                         "error": "payment could not be registered"},
                        status_code=500,
                    )
                if payment_row is None:
                    # Idempotent retry / duplicate submission (PROMPT 6 req 7):
                    # the same payload_ref was already consumed. Look up the
                    # existing payment: if it is already bound to a task, this
                    # is a retry of a COMPLETED/IN-FLIGHT payment - return the
                    # SAME task (no new billing, no re-dispatch). If it exists
                    # but has no task yet (a crash between verify and dispatch),
                    # resume the SAME payment row instead of charging again.
                    existing = task_store.get_payment_by_ref(ref)
                    if existing is not None and existing.get("task_id"):
                        tid = str(existing["task_id"])
                        logger.info(
                            "REST payment retry: idempotent return task=%s ref=%s",
                            tid, ref[:16],
                        )
                        return JSONResponse(
                            {
                                "ok": True,
                                "task_id": tid,
                                "state": "running",
                                "note": "this payment was already used for an audit; the same task is returned (no second charge)",
                            },
                            status_code=202,
                        )
                    if existing is not None and existing.get("status") == "verified":
                        # Interrupted between verify and dispatch: reuse the
                        # reserved payment row; the audit below dispatches for
                        # this exact entitlement without a second payment.
                        logger.warning(
                            "REST payment resume: verified but undispatched ref=%s",
                            ref[:16],
                        )
                        payment_row = existing
                    else:
                        logger.info("REST payment replay rejected ref=%s", ref[:16])
                        return JSONResponse(
                            {
                                "ok": False,
                                "error_code": "payment_replay",
                                "error": "Payment already used (replay rejected)",
                            },
                            status_code=402,
                        )
            else:
                if payment.replay_seen(ref):
                    logger.info("REST payment replay rejected ref=%s", ref[:16])
                    return JSONResponse(
                        {
                            "ok": False,
                            "error_code": "payment_replay",
                            "error": "Payment already used (replay rejected)",
                        },
                        status_code=402,
                    )
                payment.record_replay(ref)
            verified = VerifiedPayment(
                payload=result.payment_payload,
                requirements=result.payment_requirements,
                ref=ref,
            )
            return await _dispatch_audit_rest(
                request, verified, parsed_body, ctx, payment_row=payment_row
            )
        except Exception as exc:  # noqa: BLE001 - never leak internals to HTTP clients
            logger.exception("REST audit endpoint failed")
            # Surface the exception class + a short message (no traceback, no
            # secrets) so a 500 here is diagnosable from the response body
            # instead of a useless opaque "internal error".
            detail = f"{type(exc).__name__}: {str(exc)[:200]}"
            return JSONResponse(
                {"ok": False, "error_code": "internal_error", "error": "internal error", "detail": detail},
                status_code=500,
            )

    @app.custom_route("/api/audit/{task_id}/status", methods=["GET"])
    async def _api_audit_status(request: Request) -> Response:
        """Lightweight audit status probe (the MythX-style async pattern).

        The frontend polls THIS endpoint while an audit runs: it returns only
        the run state (one GitHub API call, no artifact download). When the
        state is completed the client fetches the report once. Free, read-
        only, never dispatches anything.
        """
        task_id = str(request.path_params.get("task_id", ""))
        if not task_id or len(task_id) > 64:
            return JSONResponse(
                {"ok": False, "error_code": "invalid_task_id",
                 "error": "task_id must be 1..64 chars"},
                status_code=400,
            )
        task = task_store.get(task_id)
        if task is None:
            return JSONResponse(
                {"ok": False, "error_code": "unknown_task",
                 "error": "no such task (it may have expired or never existed)"},
                status_code=404,
            )
        if task.run_id is None:
            return JSONResponse(
                {"ok": True, "task_id": task_id, "state": task.state.value},
                status_code=200,
            )
        try:
            run = await gh.get_run(task.run_id)
        except GitHubClientError:
            logger.exception("status endpoint: run lookup failed")
            return JSONResponse(
                {"ok": False, "error_code": "upstream_error", "error": "status lookup failed"},
                status_code=502,
            )
        mapped = gh.map_run_status(run)
        task_store.set_state(task_id, TaskState(mapped))
        if mapped == "completed":
            # Report is ready: deliver the single report-ready email if the
            # customer supplied an address at dispatch (idempotent).
            _maybe_notify_report_ready(task_store, task_id,
                                       _base_url_from_request(request))
        return JSONResponse(
            {"ok": True, "task_id": task_id, "state": mapped},
            status_code=200,
        )

    @app.custom_route("/api/audit/{task_id}/report", methods=["GET"])
    async def _api_report_html(request: Request) -> Response:
        """Customer-facing HTML report (Section 8). The task id acts as a
        bearer capability: unknown ids 404, unpaid tasks get fail-closed 402
        when payments are enabled."""
        return await _serve_rendered_report(request, "html")

    @app.custom_route("/api/audit/{task_id}/report.pdf", methods=["GET"])
    async def _api_report_pdf(request: Request) -> Response:
        """Customer-facing PDF report (Section 8). Optional dependency;
        503 when the PDF renderer is not installed."""
        return await _serve_rendered_report(request, "pdf")

    @app.custom_route("/api/audit/{task_id}/report.json", methods=["GET"])
    async def _api_report_json(request: Request) -> Response:
        """Machine-readable JSON report (Section 9). Same task-id capability,
        same fail-closed gate as HTML/PDF: never charges, never dispatches a
        second audit, never exposes storage paths or secrets."""
        return await _serve_rendered_report(request, "json")

    @app.custom_route("/api/audit/{task_id}/report.md", methods=["GET"])
    async def _api_report_markdown(request: Request) -> Response:
        """Markdown report (Stage 9) from the SAME validated report data as
        JSON/HTML/PDF — all formats agree by construction."""
        return await _serve_rendered_report(request, "md")

    async def _serve_rendered_report(request: Request, fmt: str) -> Response:
        """Shared renderer endpoint: resolves the task, enforces the payment
        binding (fail-closed), fetches the SAME validated report JSON the MCP
        tool serves, and renders HTML/PDF from it. Never re-computes findings
        and never leaks infrastructure internals."""
        met = get_metrics()
        met.incr("http_requests")
        client_key = request.client.host if request.client else "unknown"
        if not limiter.allow(client_key):
            met.incr("http_rate_limited")
            return JSONResponse(
                {
                    "ok": False,
                    "error_code": "rate_limited",
                    "error": "too many requests; retry later",
                },
                status_code=429,
            )
        task_id = str(request.path_params.get("task_id", ""))
        if not task_id or len(task_id) > 64:
            return JSONResponse(
                {"ok": False, "error_code": "invalid_task_id", "error": "task_id must be 1..64 chars"},  # noqa: E501
                status_code=400,
            )
        task = task_store.get(task_id)
        if task is None:
            return JSONResponse(
                {"ok": False, "error_code": "unknown_task", "error": "no such task (it may have expired or never existed)"},  # noqa: E501
                status_code=404,
            )
        if task.run_id is None:
            return JSONResponse(
                {"ok": False, "error_code": "not_ready", "state": task.state.value,
                 "error": "workflow dispatch pending or run not yet associated"},
                status_code=409,
            )
        try:
            run = await gh.get_run(task.run_id)
        except GitHubClientError:
            logger.exception("report endpoint: run lookup failed")
            return JSONResponse(
                {"ok": False, "error_code": "upstream_error", "error": "status lookup failed"},
                status_code=502,
            )
        mapped = gh.map_run_status(run)
        task_store.set_state(task_id, TaskState(mapped))
        if mapped != "completed":
            # Distinguish "still running" (keep waiting) from "failed"
            # (no report will ever exist; payment is preserved and the
            # credit/refund policy in REFUND_POLICY.md applies).
            if mapped == "failed":
                return JSONResponse(
                    {
                        "ok": False,
                        "error_code": "audit_failed",
                        "state": "failed",
                        "task_id": task_id,
                        "error": (
                            "the audit workflow failed before producing a report. "
                            "Your payment is preserved (settled) and the credit/refund "
                            "policy applies - see /refund. Re-run the audit to retry."
                        ),
                    },
                    status_code=409,
                )
            return JSONResponse(
                {"ok": False, "error_code": "not_ready", "state": mapped,
                 "error": "audit run is not completed yet"},
                status_code=409,
            )
        if payment.enabled and not task.paid:
            # Fail-closed: report withheld until a verified payment is bound.
            # Payment is taken at dispatch (POST /api/audit), so this branch
            # only fires on tampered/foreign tasks - point the client there.
            return JSONResponse(
                {"ok": False, "error_code": "payment_required",
                 "error": "report withheld: no verified payment is bound to this task",
                 "how_to_pay": f"POST {REST_AUDIT_PATH} with x402 payment to create a paid task",
                 "price": settings.X402_REST_PRICE},
                status_code=402,
            )
        try:
            report = await gh.fetch_report(task.run_id, task_id)
        except ArtifactExpiredError:
            task_store.set_state(task_id, TaskState.EXPIRED, error_code="artifact_expired")
            return JSONResponse(
                {"ok": False, "error_code": "artifact_expired", "error": "report artifact expired; re-run the audit"},  # noqa: E501
                status_code=410,
            )
        except GitHubClientError:
            logger.exception("report endpoint: artifact fetch failed")
            return JSONResponse(
                {"ok": False, "error_code": "upstream_error", "error": "report unavailable"},
                status_code=502,
            )
        except Exception:  # noqa: BLE001 - a non-standard fetch failure must be diagnosable
            logger.exception("report endpoint: artifact fetch raised unexpected error")
            return JSONResponse(
                {"ok": False, "error_code": "upstream_unexpected", "error": "report retrieval failed"},
                status_code=502,
            )
        try:
            validated = AuditReport.model_validate(report)
        except Exception:  # noqa: BLE001 - artifact content is not trusted
            logger.exception("report endpoint: artifact payload failed validation")
            return JSONResponse(
                {"ok": False, "error_code": "invalid_report", "error": "stored report failed validation"},  # noqa: E501
                status_code=502,
            )
        # Render stage: every format is wrapped so a render bug cannot leak a
        # bare 500 with no explanation. The full traceback goes to the service
        # log; the client gets a stable error_code so the incident is
        # diagnosable from the response body alone.
        try:
            if fmt == "html":
                return HTMLResponse(render_html(validated))
            if fmt == "md":
                md_text = render_markdown(validated)
                # Report is definitively served: single report-ready email
                # (links + attached markdown) for customers who opted in.
                _maybe_notify_report_ready(
                    task_store, task_id, _base_url_from_request(request),
                    report_markdown=md_text)
                return HTMLResponse(
                    md_text,
                    media_type="text/markdown; charset=utf-8",
                )
            if fmt == "json":
                return JSONResponse(validated.model_dump(mode="json"))
            try:
                pdf_bytes = render_pdf(validated)
            except ReportRenderError as exc:
                return JSONResponse(
                    {"ok": False, "error_code": "renderer_unavailable", "error": str(exc)},
                    status_code=503,
                )
            return Response(
                pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f'inline; filename="agentsafe-{task_id}.pdf"'},
            )
        except Exception:  # noqa: BLE001 - render must never 500 without detail
            logger.exception("report endpoint: render failed fmt=%s task_id=%s", fmt, task_id)
            return JSONResponse(
                {
                    "ok": False,
                    "error_code": "report_render_failed",
                    "error": f"report rendering failed for format {fmt!r}",
                },
                status_code=500,
            )

    def _payer_from_payload(payload: Any) -> str | None:
        """Best-effort payer address from the signed EIP-3009 authorization.
        The facilitator's verify has already recovered the signer; the
        authorization.from is signature-bound, so this is authoritative for
        the record."""
        try:
            inner = payload.payload
            if isinstance(inner, dict):
                auth = inner.get("authorization")
                if isinstance(auth, dict) and auth.get("from"):
                    return str(auth["from"])
        except Exception:  # noqa: BLE001 - payer is best-effort metadata
            return None
        return None

    def _chain_id_from_network(network: str) -> int | None:
        if network.startswith("eip155:"):
            try:
                return int(network.split(":", 1)[1])
            except (ValueError, IndexError):
                return None
        return None

    async def _dispatch_audit_rest(
        request: Request,
        verified: VerifiedPayment | None,
        parsed_body: Any,
        ctx: Any = None,
        payment_row: dict | None = None,
    ) -> Response:
        """Shared dispatch pipeline for POST /api/audit (x402-paid or free in
        dev mode). The source-size guard runs BEFORE any settlement, so a
        paid request that cannot be served at the flat fee never moves funds."""
        if not isinstance(parsed_body, dict):
            return JSONResponse(
                {
                    "ok": False,
                    "error_code": "invalid_json",
                    "error": "request body must be a JSON object with an 'address' field",
                },
                status_code=400,
            )
        try:
            addr = normalize_address(str(parsed_body.get("address", "")))
        except ValueError as exc:
            return JSONResponse(
                {"ok": False, "error_code": "invalid_address", "error": str(exc)},
                status_code=400,
            )
        try:
            email = _clean_email(parsed_body.get("email"))
        except ValueError as exc:
            return JSONResponse(
                {"ok": False, "error_code": "invalid_email", "error": str(exc)},
                status_code=400,
            )
        try:
            bundle = await explorer.get_verified_source(addr)
        except ContractNotVerifiedError:
            return JSONResponse(
                {
                    "ok": False,
                    "error_code": "source_not_verified",
                    "error": "audit requires verified source; no price can be quoted",
                },
                status_code=422,
            )
        except ExplorerError as exc:
            return JSONResponse(
                {
                    "ok": False,
                    "error_code": "pricing_failed",
                    "error": f"could not retrieve source for validation: {exc}",
                },
                status_code=422,
            )
        lines = count_source_lines(bundle)
        # Network-aware cap: mainnet keeps the flat-fee cap (commercial
        # tiering), testnet networks get the relaxed cap so larger contracts
        # can be audited on the free test channel.
        paid_network = None
        if verified is not None and verified.payload is not None:
            accepted = getattr(verified.payload, "accepted", None)
            paid_network = getattr(accepted, "network", None) or None
        max_lines = _rest_max_lines_for_network(settings, paid_network)
        if lines > max_lines:
            logger.info(
                "REST dispatch rejected: lines=%d exceeds cap=%d network=%s",
                lines, max_lines, paid_network or "-",
            )
            # Tiered (MCP) quotes for this contract, so the caller can see the
            # exact alternative price. Purely informational - the REST flat
            # fee still does NOT serve contracts over the cap, so it can never
            # undercut the MCP tiers.
            try:
                mcp_price: str | None = audit_price_for_lines(lines)
            except ContractTooLargeError:
                mcp_price = None
            return JSONResponse(
                {
                    "ok": False,
                    "error_code": "REST_FLAT_FEE_LINE_LIMIT",
                    "error": (
                        f"{lines} source lines exceed the {max_lines}-line "
                        "flat fee; use the MCP endpoint (audit_contract) for tiered "
                        "pricing"
                    ),
                    "source_lines": lines,
                    "flat_fee_max_lines": max_lines,
                    "mcp_tier_price": mcp_price,
                    "mcp_endpoint": "/mcp",
                    "mcp_tool": "audit_contract",
                    "charged": False,
                    "message": (
                        "No payment was taken: the flat-fee REST endpoint settles "
                        "only after an audit is accepted, so this over-limit "
                        "request moved no funds. Call the MCP tool "
                        "`audit_contract` with the same address to audit this "
                        "contract at tiered pricing"
                        + (f" ({mcp_price})." if mcp_price else ".")
                    ),
                },
                status_code=422,
            )

        task = task_store.create_task(addr, email=email)
        if verified is not None:
            task_store.mark_paid(task.task_id, verified.ref)
        task_store.set_state(task.task_id, TaskState.QUEUED)
        if payment_row is not None and hasattr(task_store, "link_payment_task"):
            # Bind the payment row to its service/audit id (entitlement tie).
            task_store.link_payment_task(payment_row["payment_id"], task.task_id)
        logger.info(
            "REST audit dispatch address=%s task_id=%s paid=%s",
            addr,
            task.task_id,
            verified is not None,
        )
        try:
            run_id = await gh.trigger_workflow(addr, task.task_id)
            task_store.link_run(task.task_id, run_id)
            task_store.set_state(task.task_id, TaskState.RUNNING)
            if payment_row is not None and hasattr(task_store, "transition_payment"):
                try:
                    task_store.transition_payment(payment_row["payment_id"], "resource_processing")
                except Exception:  # noqa: BLE001 - state bookkeeping; dispatch already succeeded
                    logger.exception("postgres payment transition failed (resource_processing)")
        except GitHubClientError as exc:
            # Dispatch failed: settlement is NOT attempted (verify-only so
            # far; the on-chain transfer never executes -> no funds move).
            task_store.set_state(task.task_id, TaskState.FAILED, error_code="dispatch_failed")
            if payment_row is not None and hasattr(task_store, "transition_payment"):
                try:
                    task_store.transition_payment(payment_row["payment_id"], "failed")
                except Exception:  # noqa: BLE001 - state bookkeeping must not mask the 502
                    logger.exception("postgres payment transition failed (dispatch)")
            return JSONResponse(
                {
                    "ok": False,
                    "task_id": task.task_id,
                    "error_code": "dispatch_failed",
                    "error": str(exc),
                },
                status_code=502,
            )

        headers: dict[str, str] = {}
        settlement_error: str | None = None
        payment_info: dict[str, Any] | None = None
        if verified is not None and x402_http is not None and ctx is not None:
            if payment_row is not None and hasattr(task_store, "transition_payment"):
                try:
                    task_store.transition_payment(payment_row["payment_id"], "settlement_pending")
                except Exception:  # noqa: BLE001 - bookkeeping only
                    logger.exception("postgres payment transition failed (settlement_pending)")
            settle = await x402_http.process_settlement(
                verified.payload,
                verified.requirements,
                context=ctx,
                phase="after-handler",
            )
            headers = {
                k: v for k, v in (settle.headers or {}).items() if k.lower() != "content-type"
            }
            if not settle.success:
                # Settlement failure does not stop the dispatched audit; it
                # is surfaced to the payer (mirrors the MCP after-handler flow).
                logger.error(
                    "REST settlement failed ref=%s reason=%s",
                    verified.ref[:16],
                    settle.error_reason,
                )
                settlement_error = (
                    f"payment settlement failed: {settle.error_reason or 'unknown failure'}"
                )
            # Persist the settlement outcome atomically (PROMPT 5): status
            # SETTLED (with the on-chain transaction hash) or FAILED, plus the
            # facilitator response for reconciliation. Never fabricated.
            if payment_row is not None and hasattr(task_store, "record_settlement"):
                try:
                    task_store.record_settlement(
                        payment_row["payment_id"],
                        success=settle.success,
                        transaction_hash=getattr(settle, "transaction", None) or None,
                        facilitator_response={"error_reason": settle.error_reason} if not settle.success else {},
                        error_reason=settle.error_reason if not settle.success else None,
                    )
                except Exception:  # noqa: BLE001 - settlement already confirmed; do not 500
                    logger.exception("postgres settlement record failed")
            # Step E structured payment record. The payer is the facilitator's
            # recovered signer when settlement reported it, else the signed
            # authorization's from (signature-bound, facilitator-verified).
            # The transaction hash is present ONLY when the settlement
            # operation itself succeeded - never fabricated.
            payer = ""
            try:
                inner = verified.payload.payload
                if isinstance(inner, dict):
                    payer = str((inner.get("authorization") or {}).get("from") or "")
            except Exception:  # noqa: BLE001 - payer is best-effort metadata
                payer = ""
            payment_info = {
                "status": "settled" if settle.success else "settlement_failed",
                "network": verified.requirements.network,
                "payer": (settle.payer if settle.success and settle.payer else payer) or "",
                "payment_ref": verified.ref,
                "service_ref": task.task_id,
            }
            if settle.success and settle.transaction:
                payment_info["transaction"] = settle.transaction
        body: dict[str, Any] = {
            "ok": True,
            "task_id": task.task_id,
            "address": addr,
            "state": "running",
            "run_id": run_id,
            "note": "report retrieval via the agentSAFE MCP tool check_audit_status",
        }
        if payment_info is not None:
            body["payment"] = payment_info
        if settlement_error:
            body["settlement_error"] = settlement_error
        return JSONResponse(body, status_code=202, headers=headers)

    @app.tool
    async def audit_contract(address: str, ctx: Context) -> dict[str, Any] | ToolResult:
        """Start an audit for a Mainnet contract address. Returns a task_id.

        The audit runs on a GitHub Actions worker; poll check_audit_status.

        When payments are enabled, this tool is x402-gated: an unpaid call
        returns the official 402 payment-required body and never dispatches.
        """
        try:
            addr = normalize_address(address)
        except ValueError as exc:
            return {"ok": False, "error_code": "invalid_address", "error": str(exc)}

        verified: VerifiedPayment | None = None
        if payment.enabled:
            # Tiered pricing: quote from the verified source size BEFORE any
            # payment challenge, so the advertised amount always matches the
            # real audit cost. The client cannot influence the quoted tier.
            try:
                bundle = await explorer.get_verified_source(addr)
            except ContractNotVerifiedError:
                return {
                    "ok": False,
                    "error_code": "source_not_verified",
                    "error": "audit requires verified source; no price can be quoted",
                }
            except ExplorerError as exc:
                return {
                    "ok": False,
                    "error_code": "pricing_failed",
                    "error": f"could not retrieve source for pricing: {exc}",
                }
            lines = count_source_lines(bundle)
            try:
                price = audit_price_for_lines(lines)
            except ContractTooLargeError:
                # Enterprise interception: reject BEFORE any payment is
                # initiated or expensive processing starts. Never truncate
                # the input or split it into billable requests.
                return {
                    "ok": False,
                    "error_code": "ENTERPRISE_INQUIRY_REQUIRED",
                    "error": "ENTERPRISE_INQUIRY_REQUIRED",
                    "message": (
                        "Your project exceeds the standard 5,000-line limit. "
                        "Please contact us to discuss enterprise processing."
                    ),
                    "inquiryUrl": CUSTOM_PRICING_CONTACT_URL,
                }
            tier_requirements = payment.requirements_for_price(price)
            # Official SDK flow: verify BEFORE execution. Unverified requests
            # receive the payment-required result quoting the tier price and
            # no dispatch happens.
            verified, deny = await payment.verify(
                ctx, "audit_contract", requirements=tier_requirements
            )
            if deny is not None:
                return deny
            logger.info("audit_contract quoted tier price=%s lines=%d", price, lines)

        task = task_store.create_task(addr)
        if verified is not None:
            # Bind the verified payment to this task; report retrieval for
            # this task is released only when this flag is set.
            task_store.mark_paid(task.task_id, verified.ref)
        task_store.set_state(task.task_id, TaskState.QUEUED)
        logger.info("audit_contract address=%s task_id=%s", addr, task.task_id)
        try:
            run_id = await gh.trigger_workflow(addr, task.task_id)
            task_store.link_run(task.task_id, run_id)
            task_store.set_state(task.task_id, TaskState.RUNNING)
        except RunAssociationError as exc:
            settled = await _settle_payment(verified, "audit_contract")
            if settled is not None:
                return settled
            return {
                "ok": True,
                "task_id": task.task_id,
                "address": addr,
                "note": (
                    "workflow dispatched but run not yet visible; retry check_audit_status shortly"
                ),
                "detail": str(exc),
            }
        except GitHubClientError as exc:
            # Dispatch failed: settlement is NOT attempted (verify-only so far,
            # the on-chain transfer never executes -> no funds collected).
            # No refund is owed or promised.
            task_store.set_state(task.task_id, TaskState.FAILED, error_code="dispatch_failed")
            return {
                "ok": False,
                "task_id": task.task_id,
                "error_code": "dispatch_failed",
                "error": str(exc),
            }
        settled = await _settle_payment(verified, "audit_contract")
        if settled is not None:
            return settled
        return {
            "ok": True,
            "task_id": task.task_id,
            "address": addr,
            "run_id": run_id,
            "state": "running",
        }

    async def _settle_payment(
        verified: VerifiedPayment | None, tool_name: str
    ) -> ToolResult | None:
        """Settle AFTER successful execution (official after-handler phase).

        Returns the settlement-failed error result on failure, else None.
        A settlement failure does not stop the dispatched audit; it is
        surfaced to the payer. No automatic refunds exist in the exact-EVM
        scheme.
        """
        if verified is None:
            return None
        try:
            settle_result = await payment.settle(verified)
        except Exception as exc:
            logger.error("settlement failed tool=%s ref=%s: %s", tool_name, verified.ref, exc)
            return await payment.settlement_failed_result(
                tool_name, str(exc), requirements=[verified.requirements]
            )
        if not settle_result.success:
            logger.error(
                "settlement rejected tool=%s ref=%s reason=%s",
                tool_name,
                verified.ref,
                settle_result.error_reason,
            )
            return await payment.settlement_failed_result(
                tool_name,
                settle_result.error_reason or "unknown settlement failure",
                requirements=[verified.requirements],
            )
        logger.info(
            "payment settled tool=%s ref=%s tx=%s",
            tool_name,
            verified.ref[:16],
            settle_result.transaction,
        )
        return None

    @app.tool
    async def check_audit_status(task_id: str) -> dict[str, Any]:
        """Check audit progress; returns the report once the run completes."""
        if not task_id or len(task_id) > 64:
            return {
                "ok": False,
                "error_code": "invalid_task_id",
                "error": "task_id must be 1..64 chars",
            }
        task = task_store.get(task_id)
        if task is None:
            return {
                "ok": False,
                "error_code": "unknown_task",
                "error": "no such task (it may have expired or never existed)",
            }

        if task.run_id is None:
            return {
                "ok": True,
                "task_id": task_id,
                "state": task.state.value,
                "detail": "workflow dispatch pending or run not yet associated",
            }

        try:
            run = await gh.get_run(task.run_id)
        except GitHubClientError as exc:
            return {
                "ok": True,
                "task_id": task_id,
                "state": task.state.value,
                "error": f"status lookup failed: {exc}",
            }

        mapped = gh.map_run_status(run)
        task_store.set_state(task_id, TaskState(mapped))

        if mapped == "completed":
            if payment.enabled and not task.paid:
                # Payment binding: a task that never passed payment
                # verification must not release a paid report.
                return {
                    "ok": False,
                    "task_id": task_id,
                    "state": mapped,
                    "error_code": "payment_required",
                    "error": "report withheld: no verified payment is bound to this task",
                }
            try:
                report = await gh.fetch_report(task.run_id, task_id)
            except ArtifactExpiredError:
                task_store.set_state(task_id, TaskState.EXPIRED, error_code="artifact_expired")
                return {
                    "ok": True,
                    "task_id": task_id,
                    "state": "expired",
                    "error": "report artifact expired; re-run the audit",
                }
            except GitHubClientError as exc:
                return {
                    "ok": True,
                    "task_id": task_id,
                    "state": mapped,
                    "error": f"report unavailable: {exc}",
                }
            task_store.set_state(task_id, TaskState.COMPLETED)
            return {
                "ok": True,
                "task_id": task_id,
                "state": "completed",
                "report": _clip_report(report),
            }
        if mapped == "failed":
            task_store.set_state(
                task_id, TaskState.FAILED, error_code=f"run_conclusion:{run.get('conclusion')}"
            )
        return {
            "ok": True,
            "task_id": task_id,
            "state": mapped,
            "run_conclusion": run.get("conclusion"),
        }

    @app.tool
    async def get_contract_info(address: str) -> dict[str, Any]:
        """On-chain snapshot: is contract, bytecode size, verified source?"""
        try:
            addr = normalize_address(address)
        except ValueError as exc:
            return {"ok": False, "error_code": "invalid_address", "error": str(exc)}
        info: dict[str, Any] = {"address": addr}
        try:
            code = await rpc.get_code(addr)
            info["is_contract"] = len(code) > 2
            info["bytecode_size_bytes"] = (len(code) - 2) // 2
        except Exception as exc:
            info["rpc_error"] = str(exc)
        try:
            await explorer.get_verified_source(addr)
            info["verified_source"] = True
        except ContractNotVerifiedError:
            info["verified_source"] = False
        except Exception as exc:
            info["etherscan_error"] = str(exc)
        return {"ok": True, **info}

    @app.tool
    async def get_source_code(address: str, ctx: Context) -> dict[str, Any] | ToolResult:
        """Standalone verified-source retrieval at a flat $0.01 USDC (Section 10).

        Priced and fail-closed exactly like the other paid MCP tools. When the
        same source was already fetched internally as part of a paid audit, no
        additional standalone charge applies (the audit tier already covers it)
        - this tool is for clients that want ONLY the source text. In dev mode
        (PAYMENTS_ENABLED=false) it is free, mirroring the other tools.

        Returns the verified source file(s) verbatim, never a placeholder
        filename, plus metadata already present on-chain (network, address).
        No secrets, no storage paths, no compiler configuration internals.
        """
        try:
            addr = normalize_address(address)
        except ValueError as exc:
            return {"ok": False, "error_code": "invalid_address", "error": str(exc)}

        verified: VerifiedPayment | None = None
        if payment.enabled:
            # Flat standalone price (Section 10: $0.01 USDC), quoted before any
            # work so the advertised amount is fixed and non-influenceable.
            requirements = payment.requirements_for_price(settings.X402_SOURCE_RETRIEVAL_PRICE)
            verified, deny = await payment.verify(
                ctx, "get_source_code", requirements=requirements
            )
            if deny is not None:
                return deny

        try:
            bundle = await explorer.get_verified_source(addr)
        except ContractNotVerifiedError:
            return {
                "ok": False,
                "error_code": "source_not_verified",
                "error": "no verified source is available for this address",
            }
        except ExplorerError as exc:
            return {
                "ok": False,
                "error_code": "source_retrieval_failed",
                "error": f"could not retrieve source: {exc}",
            }

        files = [
            {"path": sf.path, "content": sf.content} for sf in bundle.files
        ]
        return {
            "ok": True,
            "address": addr,
            "network": "ethereum-mainnet",
            "contract_name": bundle.contract_name,
            "compiler_version": bundle.compiler_version,
            "files": files,
            "price_paid": settings.X402_SOURCE_RETRIEVAL_PRICE,
        }

    @app.tool
    async def retrieve_knowledge(query: str, ctx: Context, limit: int = 3,
                                 focus: str = "") -> dict[str, Any] | ToolResult:
        """Standalone security-knowledge retrieval at a flat $0.01 USDC
        (PROMPT 6 req 9: the knowledge base is charged only when accessed
        standalone; the SAME retrieval inside a paid audit remains free - the
        audit tier already covers it).

        Returns matched historical knowledge records (id, category, title,
        summary, remediation, source URL). Never returns embeddings, internal
        storage paths, or secrets. In dev mode (PAYMENTS_ENABLED=false) it is
        free, mirroring the other paid tools.
        """
        query = (query or "").strip()
        if not query:
            return {"ok": False, "error_code": "empty_query", "error": "query must not be empty"}
        if limit < 1 or limit > 20:
            return {"ok": False, "error_code": "invalid_limit", "error": "limit must be 1..20"}

        verified: VerifiedPayment | None = None
        if payment.enabled:
            # Flat standalone price, quoted before any work so the advertised
            # amount is fixed and non-influenceable. Same $0.01 as source
            # retrieval; the pricing model is unchanged.
            requirements = payment.requirements_for_price(settings.X402_SOURCE_RETRIEVAL_PRICE)
            verified, deny = await payment.verify(
                ctx, "retrieve_knowledge", requirements=requirements
            )
            if deny is not None:
                return deny

        try:
            from agentsafe.knowledge import KnowledgeBase

            kb = KnowledgeBase.load_default()
            records = kb.search(query, focus=focus, limit=limit)
        except Exception as exc:
            return {
                "ok": False,
                "error_code": "knowledge_unavailable",
                "error": f"knowledge base unavailable: {exc}",
            }

        out = []
        for r in records:
            out.append(
                {
                    "id": r.get("id"),
                    "category": r.get("category"),
                    "mechanism": r.get("mechanism"),
                    "root_cause": r.get("root_cause"),
                    "impact": r.get("impact"),
                    "remediation": r.get("remediation"),
                    "source": r.get("source"),
                    "url": r.get("url"),
                }
            )
        return {
            "ok": True,
            "query": query,
            "count": len(out),
            "results": out,
            "price_paid": settings.X402_SOURCE_RETRIEVAL_PRICE,
        }

    return app


def _clip_report(report: dict[str, Any]) -> dict[str, Any]:
    """Sanity-clip the report payload returned through MCP."""
    if not isinstance(report, dict):
        return {"raw": str(report)[:1000]}
    findings = report.get("findings")
    if isinstance(findings, list) and len(findings) > 100:
        report = dict(report)
        report["findings"] = findings[:100]
        report["findings_truncated"] = True
    try:
        AuditReport.model_validate(report)  # validate shape when possible
    except Exception:
        return {"raw": str(report)[:4000]}
    return report


def create_app() -> FastMCP:
    """Zero-arg factory for FastMCP Cloud / Prefect Horizon deployments.

    Entrypoint: agentsafe.server:create_app (env vars supply all settings).
    Cloud builds inspect the server WITHOUT env vars, so validation is
    deferred to runtime startup (see build_server validate=False).
    """
    return build_server(Settings(), validate=False)


def main() -> None:
    """Entry point: python -m agentsafe.server [--transport stdio|http]"""
    import argparse

    parser = argparse.ArgumentParser(description="agentSAFE MCP server")
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    settings = Settings()
    _setup_logging(settings.LOG_LEVEL)
    global mcp
    mcp = build_server(settings)
    logger.info(
        "agentSAFE MCP v%s starting (transport=%s, payments=%s)",
        __version__,
        args.transport,
        settings.PAYMENTS_ENABLED,
    )
    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        # HTTP transport: serve the app with the access-log middleware
        # (visitor IP + time, 30-day retention - see PRIVACY_POLICY.md).
        import uvicorn
        from starlette.middleware import Middleware as StarletteMiddleware

        from agentsafe.web import AccessLogMiddleware, AccessLogStore

        store = AccessLogStore(settings.ACCESS_LOG_DB_PATH)
        purged = store.purge()
        logger.info(
            "access log db=%s purged=%d (retention 30 days)",
            settings.ACCESS_LOG_DB_PATH,
            purged,
        )
        app = mcp.http_app(middleware=[StarletteMiddleware(AccessLogMiddleware, store=store)])
        uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
