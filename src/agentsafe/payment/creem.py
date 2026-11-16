"""Creem hosted-checkout integration (card payments via creem.io).

Creem (https://creem.io) is a Merchant of Record: it collects card /
Apple Pay / Google Pay payments, handles VAT/GST compliance, and reports
the outcome via signed webhooks. This module is an ADDITIONAL payment
channel - the x402 crypto flow is unchanged and stays the primary one.

Trust model (fail-closed):

- The ONLY trusted payment confirmation is the webhook, authenticated by
  HMAC-SHA256 over the RAW request body (hex digest in the
  ``creem-signature`` header, key = CREEM_WEBHOOK_SECRET).
- The browser return redirect is NOT trusted: the dispatch endpoint only
  releases an audit after the webhook marked the task paid in the task
  store.
- Webhook deliveries are idempotent: Creem retries the same event (same
  event id) and a manual dashboard resend gets a new event id with the
  same order - binding is therefore keyed on the ORDER id
  (``creem:<order_id>`` payment ref), never on the event id.

Checkout binding: the server creates a Creem checkout session with
``request_id`` = agentSAFE task_id and ``success_url`` pointing back at
the landing page; the webhook correlates through ``request_id``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Final

import httpx

DEFAULT_API_BASE: Final = "https://api.creem.io"


class CreemError(RuntimeError):
    """Raised when the Creem API call fails or returns an unusable body."""


def verify_signature(raw_body: bytes, signature: str | None, secret: str) -> bool:
    """Verify the ``creem-signature`` header (HMAC-SHA256 hex of the RAW body).

    Constant-time comparison; False on a missing/malformed signature or a
    wrong secret. The raw bytes must be exactly what was received - any
    re-serialization breaks the digest, so callers pass ``await
    request.body()`` unchanged.
    """
    if not signature or not secret:
        return False
    expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature.strip().lower())


def parse_event(raw_body: bytes) -> dict[str, Any]:
    """Parse and shape-check a webhook payload. Raises ValueError on garbage.

    Shape: {"id": str, "eventType": str, "created_at": int, "object": {...}}.
    """
    try:
        data = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"webhook body is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("object"), dict):
        raise ValueError("webhook body must be an object with an 'object' field")
    if not isinstance(data.get("eventType"), str):
        raise ValueError("webhook body must carry an 'eventType' string")
    return data


def checkout_request_id(event_object: dict[str, Any]) -> str | None:
    """The agentSAFE task_id bound at checkout creation (``request_id``)."""
    rid = str(event_object.get("request_id") or "").strip()
    return rid or None


def checkout_product_id(event_object: dict[str, Any]) -> str | None:
    """Purchased product id (object.product.id, falling back to the order's)."""
    product = event_object.get("product")
    if isinstance(product, dict):
        pid = str(product.get("id") or "").strip()
        if pid:
            return pid
    order = event_object.get("order")
    if isinstance(order, dict):
        pid = str(order.get("product") or "").strip()
        if pid:
            return pid
    return None


def checkout_order_id(event_object: dict[str, Any]) -> str | None:
    """Order id (``ord_...``) - the idempotency key for payment binding."""
    order = event_object.get("order")
    if isinstance(order, dict):
        oid = str(order.get("id") or "").strip()
        if oid:
            return oid
    return None


def checkout_customer_email(event_object: dict[str, Any]) -> str | None:
    """Customer email collected by the hosted checkout (report delivery)."""
    customer = event_object.get("customer")
    if isinstance(customer, dict):
        email = str(customer.get("email") or "").strip()
        if email:
            return email
    return None


def checkout_is_completed(event_object: dict[str, Any]) -> bool:
    """Whether the checkout session reached the completed/paid state."""
    status = str(event_object.get("status") or "").strip().lower()
    if status == "completed":
        return True
    order = event_object.get("order")
    return isinstance(order, dict) and str(order.get("status") or "").lower() == "paid"


def checkout_amount(event_object: dict[str, Any]) -> str:
    """Amount actually charged, in minor units as a string (for the ledger)."""
    order = event_object.get("order")
    if isinstance(order, dict):
        amount = order.get("amount_paid")
        if amount is None:
            amount = order.get("amount_due")
        if amount is None:
            amount = order.get("amount")
        if amount is not None:
            return str(amount)
    return "0"


class CreemClient:
    """Minimal async client for the Creem checkout-creation API.

    Only one endpoint is needed: POST /v1/checkouts (auth: ``x-api-key``
    header). Webhook verification is local (HMAC) and needs no client.
    """

    def __init__(
        self,
        api_key: str,
        *,
        api_base: str = DEFAULT_API_BASE,
        timeout_seconds: float = 15.0,
    ) -> None:
        self._api_key = api_key
        self._base = (api_base or DEFAULT_API_BASE).rstrip("/")
        self._timeout = timeout_seconds

    async def create_checkout(
        self,
        *,
        product_id: str,
        request_id: str,
        success_url: str,
        metadata: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Create a hosted checkout session. Returns {"id", "checkout_url"}.

        Raises CreemError on transport errors, non-2xx responses, or a
        response without a usable checkout_url - callers must never send a
        customer to a URL they have not actually received from the API.
        """
        payload: dict[str, Any] = {
            "product_id": product_id,
            "request_id": request_id,
            "success_url": success_url,
        }
        if metadata:
            payload["metadata"] = metadata
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                res = await client.post(
                    f"{self._base}/v1/checkouts",
                    headers={
                        "x-api-key": self._api_key,
                        "content-type": "application/json",
                    },
                    json=payload,
                )
        except httpx.HTTPError as exc:
            raise CreemError(f"creem api unreachable: {exc}") from exc
        if res.status_code >= 400:
            raise CreemError(f"creem api error {res.status_code}: {res.text[:200]}")
        try:
            data = res.json()
        except ValueError as exc:
            raise CreemError("creem api returned a non-JSON body") from exc
        url = str((data or {}).get("checkout_url") or "").strip()
        if not url.startswith(("https://", "http://")):
            raise CreemError("creem api response has no checkout_url")
        return {"id": str((data or {}).get("id") or ""), "checkout_url": url}
