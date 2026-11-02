"""x402 payment adapter (Phase 12) built on the PINNED official SDK: x402==2.25.0.

Implementation notes (all API surface verified against the installed
x402 2.25.0 package):

- Core components come from the SDK: ``x402ResourceServer`` (server.py),
  ``HTTPFacilitatorClient``/``FacilitatorConfig`` (x402.http), and
  ``ExactEvmServerScheme`` (x402.mechanisms.evm.exact, needs the
  ``x402[evm]`` extra).
- The SDK ships an MCP wrapper (``x402.mcp.create_payment_wrapper``) whose
  handler glue targets the ``mcp`` 1.x package (``mcp.server.fastmcp``).
  This service runs FastMCP 4.x on ``mcp`` 2.x, where that import no longer
  exists, so this adapter mirrors the wrapper's DOCUMENTED flow and wire
  formats directly against the SDK core:

  1. payment payload is read from the tool-call request ``_meta`` under the
     SDK constant ``MCP_PAYMENT_META_KEY`` ("x402/payment");
  2. unpaid / mismatched / unverified requests receive an ``isError`` tool
     result whose ``structuredContent`` is the official ``PaymentRequired``
     body (``x402Version``/``accepts``/``error``/``resource``) - the exact
     shape produced by the SDK wrapper and parsed by the official x402 MCP
     client (``extract_payment_required_from_result``);
  3. verification happens BEFORE tool execution; settlement runs AFTER
     successful execution (the SDK wrapper's "after-handler" phase). A
     dispatch failure therefore never settles - no funds move.
  4. settlement metadata is returned under
     ``MCP_PAYMENT_RESPONSE_META_KEY`` ("x402/payment-response").

- Payment-to-resource binding: the client payment payload must match the
  server-advertised requirements for this tool (scheme/network/asset/amount/
  pay_to) via ``x402ResourceServer.find_matching_requirements``; the price
  and recipient come from settings, never from the client. A local replay
  ledger additionally rejects a reused payment payload even if the
  facilitator would still accept it.

Refunds: the exact-EVM scheme provides no refund mechanism. If dispatch
fails after verification, settlement is NOT attempted (the on-chain
transfer never executes), so no funds are collected; no refund promise is
made anywhere. If settlement itself fails after a successful dispatch,
the error is surfaced and the audit keeps running.

The adapter stays fail-closed: constructing it with ``enabled=True`` and a
pinned SDK that is absent or version-mismatched raises at startup.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from fastmcp import Context
    from fastmcp.tools import ToolResult

logger = logging.getLogger("agentSAFE.payment")

PINNED_X402_VERSION = "2.25.0"


# The Vercel Python runtime rotates the asyncio event loop between warm
# invocations of the same process (see api/index.py header). The SDK's
# HTTPFacilitatorClient caches an httpx.AsyncClient bound to the loop it
# was created on; reusing it from a rotated (now-closed) loop raises
# RuntimeError("Event loop is closed") on the very next warm request.
# Patch _get_async_client to rebuild the client whenever the running loop
# differs from the loop it was created on. Called idempotently from the
# adapter constructor; harmless on single-loop runtimes (uvicorn CLI).
def _patch_loop_safe_facilitator_client() -> None:
    import asyncio

    from x402.http.facilitator_client import HTTPFacilitatorClient

    _BOUND_LOOP = "__agentSAFE_bound_loop__"
    _PATCHED = "__agentSAFE_loop_safe_patched__"
    if getattr(HTTPFacilitatorClient._get_async_client, _PATCHED, False):
        return

    def _get_async_client(self: Any) -> Any:
        loop = asyncio.get_running_loop()
        bound = getattr(self, _BOUND_LOOP, None)
        if bound is not loop:
            # First use on this loop, or the loop rotated since the cached
            # client was built. A client created on a previous (now-closed)
            # loop must be dropped, not closed (closing would raise on the
            # dead loop); a caller-supplied client with no bound-loop
            # marker is left untouched (the caller manages its lifecycle).
            if self._http_client is not None and bound is not None:
                self._http_client = None
            if self._http_client is None:
                import httpx

                self._http_client = httpx.AsyncClient(
                    timeout=self._timeout, follow_redirects=True
                )
            setattr(self, _BOUND_LOOP, loop)
        return self._http_client

    _get_async_client.__agentSAFE_loop_safe_patched__ = True
    HTTPFacilitatorClient._get_async_client = _get_async_client


class PaymentsNotEnabledError(RuntimeError):
    """Raised when a paid operation is requested while payments are disabled."""


class X402NotIntegratedError(RuntimeError):
    """Raised when payments are enabled but the pinned-SDK adapter is unavailable."""


@dataclass(slots=True)
class VerifiedPayment:
    """A payment that passed official SDK verification; awaiting settlement."""

    payload: Any  # x402.schemas.PaymentPayload
    requirements: Any  # x402.schemas.PaymentRequirements
    ref: str  # canonical fingerprint (replay ledger key / task binding)


class X402PaymentAdapter:
    """Payment gate for paid tools. Disabled -> dev no-op; enabled -> real
    verify-before-execution / settle-after-execution flow via the pinned SDK."""

    def __init__(
        self,
        *,
        enabled: bool,
        sdk_version: str = "",
        network: str = "eip155:84532",
        pay_to: str = "",
        facilitator_url: str = "https://x402.org/facilitator",
        price: str = "$0.01",
        asset: str = "",
        max_timeout_seconds: int = 300,
        extra_networks: dict[str, dict[str, str]] | None = None,
    ) -> None:
        self.enabled = enabled
        self.network = network
        self.pay_to = pay_to
        self._asset = asset.strip()
        self._max_timeout_seconds = max_timeout_seconds
        self._base_price = price
        # Extra chains: CAIP-2 network -> {asset, pay_to}. The primary
        # network (X402_NETWORK) always comes first in the advertised
        # accepts list; extras extend it so x402 clients can pay on any of
        # the listed chains.
        self._extra_networks = {
            net: {
                "asset": str(t.get("asset", "")).strip(),
                "pay_to": str(t.get("pay_to", "")).strip(),
                **({"price": str(t["price"]).strip()} if t.get("price") else {}),
            }
            for net, t in (extra_networks or {}).items()
            if t.get("asset") and t.get("pay_to")
        }
        if not enabled:
            logger.info("payments DISABLED (dev mode); paid gating is inactive")
            return

        if not sdk_version.strip():
            raise X402NotIntegratedError(
                "PAYMENTS_ENABLED=true requires X402_SDK_VERSION pinned to the "
                "official SDK release used by this adapter"
            )
        try:
            import x402  # noqa: PLC0415
            from x402.http import FacilitatorConfig, HTTPFacilitatorClient
            from x402.mechanisms.evm.exact import ExactEvmServerScheme
        except ImportError as exc:  # pragma: no cover - env-specific
            raise X402NotIntegratedError(
                f"PAYMENTS_ENABLED=true requires the pinned x402 SDK "
                f"(pip install 'x402[evm]=={PINNED_X402_VERSION}'): {exc}"
            ) from exc

        if x402.__version__ != sdk_version.strip():
            raise X402NotIntegratedError(
                f"X402_SDK_VERSION={sdk_version!r} does not match installed "
                f"x402=={x402.__version__!r}; pin and installed version must agree"
            )

        from x402 import x402ResourceServer

        self._x402 = x402
        _patch_loop_safe_facilitator_client()
        facilitator = HTTPFacilitatorClient(FacilitatorConfig(url=facilitator_url))
        self._server = x402ResourceServer(facilitator)
        # Register the primary chain plus every extra chain with the same
        # exact EIP-3009 scheme (the SDK picks the scheme server per
        # accepted network at verify/settle time).
        self._server.register(network, ExactEvmServerScheme())
        for extra_net in self._extra_networks:
            self._server.register(extra_net, ExactEvmServerScheme())
        # Sync network call (facilitator /supported) - acceptable at startup.
        self._server.initialize()

        self._accepts = self._build_requirements(price)
        self._replay_ledger: set[str] = set()
        logger.info(
            "payments ENABLED (x402==%s, primary=%s, extra_chains=%s, pay_to=%s, "
            "base price=%s, accepts=%d)",
            x402.__version__,
            network,
            sorted(self._extra_networks),
            pay_to,
            price,
            len(self._accepts),
        )

    def _build_requirements(self, price: str) -> list[Any]:
        """Advertised payment requirements for `price` (no network I/O;
        uses the supported-responses cache filled by initialize()).

        The primary chain's requirements come first; extra chains follow in
        X402_NETWORKS_JSON order. Each entry carries its own asset/pay_to so
        x402 clients can choose which chain to pay on."""
        from x402.schemas import ResourceConfig

        # The advertised price for the *primary* chain. Extra chains can
        # override it with their own per-chain price (e.g. a testnet).
        _price = price

        def build_one(net: str, pay_to: str, asset: str, price: str | None = None) -> list[Any]:
            extra: dict[str, Any] = {}
            if asset:
                extra["asset"] = asset
            reqs = self._server.build_payment_requirements(
                ResourceConfig(
                    scheme="exact",
                    network=net,
                    pay_to=pay_to,
                    price=price if price else _price,
                    max_timeout_seconds=self._max_timeout_seconds,
                    extra=extra or None,
                )
            )
            if not reqs:  # pragma: no cover - facilitator contract
                raise X402NotIntegratedError(
                    f"facilitator returned no payment requirements for network "
                    f"{net!r} at price {price!r}"
                )
            return reqs

        all_reqs: list[Any] = []
        all_reqs.extend(build_one(self.network, self.pay_to, self._asset))
        for net, terms in self._extra_networks.items():
            # Per-chain price override (e.g. a testnet at a token amount).
            chain_price = terms.get("price") or _price
            all_reqs.extend(
                build_one(net, terms["pay_to"], terms["asset"], price=chain_price)
            )
        return all_reqs

    def requirements_for_price(self, price: str) -> list[Any]:
        """Advertised requirements for a dynamic (tiered) price."""
        if not self.enabled:
            raise PaymentsNotEnabledError("tiered pricing requires payments to be enabled")
        return self._build_requirements(price)

    def http_resource_server(self, routes: dict[str, Any]) -> Any:
        """Official SDK HTTP resource server for REST endpoints (x402 v2 wire
        format: PAYMENT-SIGNATURE request header, PAYMENT-REQUIRED 402 header,
        PAYMENT-RESPONSE settlement header).

        ``routes`` maps "METHOD /path" patterns to x402.http.RouteConfig;
        the underlying x402ResourceServer (already initialized against the
        facilitator) is shared, so no extra network round-trips occur here.
        Only callable when payments are enabled.
        """
        if not self.enabled:
            raise PaymentsNotEnabledError("REST x402 gating requires payments to be enabled")
        from x402.http import x402HTTPResourceServer

        return x402HTTPResourceServer(self._server, routes)

    # ------------------------------------------------------- replay ledger

    def replay_seen(self, ref: str) -> bool:
        """True when this payment fingerprint was already consumed."""
        return not self.enabled or ref in self._replay_ledger

    def record_replay(self, ref: str) -> None:
        """Consume a payment fingerprint after successful verification."""
        if self.enabled:
            self._replay_ledger.add(ref)

    def seed_replay_ledger(self, refs: set[str]) -> None:
        """Re-arm replay protection after a restart with payment fingerprints
        already bound to tasks (persisted by the task store). Without this,
        a restart would forget which payloads were already consumed."""
        if not self.enabled:
            return
        self._replay_ledger.update(refs)
        logger.info("replay ledger seeded with %d persisted payment refs", len(refs))

    @property
    def accepts(self) -> list[Any]:
        """Advertised payment requirements (first entry is the active one)."""
        return list(self._accepts)

    @property
    def extra_networks(self) -> dict[str, dict[str, str]]:
        """Extra chains -> {asset, pay_to} (excluding the primary network)."""
        return dict(self._extra_networks)

    # ------------------------------------------------------------ wire format

    def _resource_info(self, tool_name: str) -> Any:
        from x402.schemas import ResourceInfo

        return ResourceInfo(
            url=f"mcp://tool/{tool_name}",
            description=f"Tool: {tool_name}",
            mime_type="application/json",
        )

    async def payment_required_result(
        self, tool_name: str, error: str, requirements: list[Any] | None = None
    ) -> ToolResult:
        """Official x402 PaymentRequired body as a fastmcp error ToolResult.

        Mirrors x402.mcp.server._create_payment_required_result: the
        structuredContent carries the x402Version-2 payment-required object
        that x402-aware clients parse to build a payment. `requirements`
        overrides the default (startup-price) advertised terms - used for
        dynamic tiered pricing where the 402 body must quote the tier price.
        """
        from fastmcp.tools import ToolResult

        accepts = requirements if requirements is not None else self._accepts
        payment_required = await self._server.create_payment_required_response(
            accepts, self._resource_info(tool_name), error
        )
        body = payment_required.model_dump(by_alias=True, exclude_none=True)
        return ToolResult(structured_content=body, is_error=True)

    async def settlement_failed_result(
        self, tool_name: str, error: str, *, requirements: list[Any] | None = None
    ) -> ToolResult:
        """Mirrors x402.mcp.server._create_settlement_failed_result."""
        from fastmcp.tools import ToolResult
        from x402.mcp.types import MCP_PAYMENT_RESPONSE_META_KEY

        accepts = requirements if requirements is not None else self._accepts
        accepts_dicts = [r.model_dump(by_alias=True, exclude_none=True) for r in accepts]
        error_data: dict[str, Any] = {
            "x402Version": 2,
            "accepts": accepts_dicts,
            "error": f"Payment settlement failed: {error}",
            "resource": {
                "url": f"mcp://tool/{tool_name}",
                "description": f"Tool: {tool_name}",
                "mimeType": "application/json",
            },
            MCP_PAYMENT_RESPONSE_META_KEY: {
                "success": False,
                "errorReason": error,
                "transaction": "",
                "network": accepts[0].network,
            },
        }
        return ToolResult(structured_content=error_data, is_error=True)

    # ------------------------------------------------------------------ flow

    @staticmethod
    def extract_payment_data(ctx: Context | None) -> dict[str, Any] | None:
        """Read the x402 payment payload from the MCP request ``_meta``.

        The SDK wrapper reads ``meta.model_extra`` (mcp 1.x pydantic Meta);
        under mcp 2.x ``request_context.meta`` is a plain dict, so both
        layouts are handled. Key name comes from the SDK constant
        ``MCP_PAYMENT_META_KEY`` ("x402/payment").
        """
        if ctx is None:
            return None
        from x402.mcp.types import MCP_PAYMENT_META_KEY

        try:
            meta = ctx.request_context.meta
        except (AttributeError, ValueError):  # pragma: no cover - no request in scope
            return None
        if isinstance(meta, dict):
            data = meta.get(MCP_PAYMENT_META_KEY)
        else:  # mcp 1.x style pydantic Meta
            extra = getattr(meta, "model_extra", None)
            data = extra.get(MCP_PAYMENT_META_KEY) if extra else None
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                return None
        return data if isinstance(data, dict) else None

    @staticmethod
    def payment_ref(payload: Any) -> str:
        """Canonical fingerprint of a payment payload (replay ledger key)."""
        canonical = json.dumps(payload.model_dump(by_alias=True, exclude_none=True), sort_keys=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    async def verify(
        self,
        ctx: Context | None,
        tool_name: str,
        *,
        requirements: list[Any] | None = None,
    ) -> tuple[VerifiedPayment | None, ToolResult | None]:
        """Verify a payment BEFORE tool execution (official wrapper order).

        Returns (verified, None) to proceed, or (None, deny_result) where the
        deny result is the official payment-required error the client must
        answer with a payment. `requirements` is the advertised-terms list the
        payment must match (dynamic tiered pricing); None uses the
        startup-price default.
        """
        accepts = requirements if requirements is not None else self._accepts
        data = self.extract_payment_data(ctx)
        if data is None:
            return None, await self.payment_required_result(
                tool_name, "Payment Required", requirements=accepts
            )

        from x402.schemas import PaymentPayload

        try:
            payload = PaymentPayload.model_validate(data)
        except Exception as exc:
            return None, await self.payment_required_result(
                tool_name, f"Invalid payment payload: {exc}", requirements=accepts
            )

        ref = self.payment_ref(payload)
        if ref in self._replay_ledger:
            return None, await self.payment_required_result(
                tool_name, "Payment already used (replay rejected)", requirements=accepts
            )

        matched = self._server.find_matching_requirements(accepts, payload)
        if matched is None:
            return None, await self.payment_required_result(
                tool_name,
                "No matching payment requirements found (check amount/network/asset)",
                requirements=accepts,
            )

        try:
            result = await self._server.verify_payment(payload, matched)
        except Exception as exc:
            return None, await self.payment_required_result(
                tool_name, str(exc), requirements=accepts
            )
        if not result.is_valid:
            return None, await self.payment_required_result(
                tool_name,
                result.invalid_reason or "Payment verification failed",
                requirements=accepts,
            )

        # Consume on verify: a payload verified once is never accepted again,
        # even if the tool then fails and settlement never happens (in that
        # case no funds move, because settle executes the transfer).
        self._replay_ledger.add(ref)
        logger.info("payment verified tool=%s ref=%s payer=%s", tool_name, ref[:16], result.payer)
        return VerifiedPayment(payload=payload, requirements=matched, ref=ref), None

    async def settle(self, verified: VerifiedPayment) -> Any:
        """Settle AFTER successful tool execution (official "after-handler"
        phase). Returns the SDK SettleResponse."""
        return await self._server.settle_payment(
            verified.payload, verified.requirements, phase="after-handler"
        )

    # -------------------------------------------------------- legacy dev mode

    def require_payment(self, resource: str) -> None:
        """Dev-mode no-op kept for compatibility. When payments are enabled
        the server uses verify()/settle() instead; this method never runs."""
        if not self.enabled:
            return  # dev mode: tools run free; the service never pretends to charge
        raise X402NotIntegratedError(  # pragma: no cover - server never calls this
            f"payment handling for {resource!r} must go through verify()/settle()"
        )


class StarletteRequestAdapter:
    """x402 SDK ``HTTPAdapter`` implementation for a Starlette ``Request``.

    Used by the REST x402 endpoint (POST /api/audit) to feed the official
    ``x402HTTPResourceServer`` middleware flow. The request body must be
    pre-read (Starlette reads are async; the SDK protocol is sync), so the
    parsed JSON is injected at construction time.
    """

    def __init__(self, request: Any, parsed_body: Any = None) -> None:
        self._request = request
        self._body = parsed_body

    def get_header(self, name: str) -> str | None:
        value = self._request.headers.get(name)
        if value is None:
            # Some x402 browser wallets/payment modals emit the V1 legacy
            # "X-PAYMENT" header (case-insensitive) instead of the V2
            # "PAYMENT-SIGNATURE" header. Accept either spelling so the
            # landing-page payment flow works with those clients.
            lowered = name.lower()
            if lowered == "payment-signature":
                value = self._request.headers.get("x-payment")
        return value

    def get_method(self) -> str:
        return self._request.method

    def get_path(self) -> str:
        return self._request.url.path

    def get_url(self) -> str:
        """Canonical public URL for x402 resource identification.

        Behind reverse proxies (Vercel / local tunnel) the advertised
        resource must be the externally visible URL, so forwarded headers
        take precedence over the internal request URL.
        """
        req = self._request
        proto = req.headers.get("x-forwarded-proto") or req.url.scheme
        host = (
            req.headers.get("x-forwarded-host")
            or req.headers.get("host")
            or req.url.netloc
        )
        return f"{proto}://{host}{req.url.path}"

    def get_accept_header(self) -> str:
        return self._request.headers.get("accept", "")

    def get_user_agent(self) -> str:
        return self._request.headers.get("user-agent", "")

    def get_query_params(self) -> dict[str, str] | None:
        return dict(self._request.query_params) or None

    def get_query_param(self, name: str) -> str | list[str] | None:
        return self._request.query_params.get(name)

    def get_body(self) -> Any:
        return self._body
