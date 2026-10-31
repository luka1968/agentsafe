"""LLM router: OpenAI-compatible providers with rotation, RPM limits, budgets.

Honest limits (documented, not hidden):
- The GLOBAL RPM limit is enforced inside THIS PROCESS ONLY. Multi-replica
  deployments need a shared limiter or a single-replica deployment; the MCP
  service here assumes a single process.
- Free-provider RPMs are NOT summed into a capacity promise; actual model IDs,
  quotas and limits are whatever the deployed accounts actually allow.
- API keys never appear in logs or exceptions.

Response validation is STRICT: JSON parsed and validated against a pydantic
model; parse failures get at most `max_retries` repair attempts, never a
lenient regex fallback.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections import deque
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel

from agentsafe.llm.repair import repair_json

logger = logging.getLogger("agentSAFE.llm")

COOLDOWN_RATE_LIMIT_SECONDS = 60.0
COOLDOWN_SERVER_ERROR_SECONDS = 15.0

# P0-3a: exponential backoff between provider-retry attempts on transient
# failures (transport / 429 / 5xx). Base doubles each retry, capped, with
# small jitter to avoid thundering-herd self-synchronization.
BACKOFF_BASE_SECONDS = 0.5
BACKOFF_MAX_SECONDS = 8.0
BACKOFF_JITTER = 0.2


def _backoff_delay(attempt: int) -> float:
    """Exponential backoff (with jitter) for the attempt-th retry."""
    import random as _random

    delay = min(BACKOFF_BASE_SECONDS * (2 ** max(0, attempt - 1)), BACKOFF_MAX_SECONDS)
    jitter = delay * BACKOFF_JITTER * (_random.random() * 2.0 - 1.0)
    return max(0.0, delay + jitter)


class LLMRouterError(RuntimeError):
    pass


class BudgetExhaustedError(LLMRouterError):
    """Per-audit call budget or deadline exceeded - stop calling, don't retry."""


class ProviderUnavailableError(LLMRouterError):
    """No healthy provider within the audit deadline."""


class SchemaValidationError(LLMRouterError):
    """LLM output failed strict JSON/schema validation after limited retries."""


# Output-failure taxonomy (Section 6). Categories are stable strings so
# reports/logs can aggregate WHY structured output failed.
VC_EMPTY = "empty_response"
VC_INVALID_JSON = "invalid_json"
VC_SCHEMA = "schema_violation"


@dataclass
class ValidationFailure:
    """Categorized structured-output failure (never a fabricated result)."""

    category: str
    detail: str

    def __str__(self) -> str:
        return f"{self.category}: {self.detail}"


@dataclass
class LLMCallResult:
    content: str
    provider: str
    model: str
    duration_seconds: float
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


@dataclass
class _ProviderRuntime:
    name: str
    base_url: str
    api_key: str
    model: str
    rpm_limit: int
    max_output_tokens: int | None
    json_mode: bool = False
    cooldown_until: float = 0.0
    permanent_failure: str | None = None
    window: deque = field(default_factory=deque)
    calls: int = 0
    failures: int = 0


class _SlidingWindowLimiter:
    """Process-local sliding-window RPM limiter, correct under concurrency."""

    def __init__(self, rpm: int, clock: Callable[[], float]) -> None:
        self._window_seconds = 60.0
        self._rpm = max(1, rpm)
        self._clock = clock
        self._events: deque = deque()
        self._lock = asyncio.Lock()

    async def acquire(
        self, sleeper: Callable[[float], Awaitable[None]], deadline: float | None
    ) -> None:
        while True:
            async with self._lock:
                now = self._clock()
                while self._events and now - self._events[0] >= self._window_seconds:
                    self._events.popleft()
                if len(self._events) < self._rpm:
                    self._events.append(now)
                    return
                wait = self._window_seconds - (now - self._events[0]) + 0.01
                if deadline is not None and now + wait > deadline:
                    raise BudgetExhaustedError(
                        f"rate limit wait {wait:.1f}s would exceed audit deadline"
                    )
            await sleeper(wait)


@dataclass
class AuditBudget:
    """Per-audit hard budget: max calls + total deadline + token accounting."""

    max_calls: int
    deadline: float
    clock: Callable[[], float]
    calls_made: int = 0
    failed_calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    providers_used: set = field(default_factory=set)
    models_used: set = field(default_factory=set)

    def check(self) -> None:
        if self.calls_made >= self.max_calls:
            raise BudgetExhaustedError(
                f"LLM budget exhausted: {self.calls_made}/{self.max_calls} calls used"
            )
        if self.clock() > self.deadline:
            raise BudgetExhaustedError("LLM audit deadline exceeded")

    def record_call(self) -> None:
        self.calls_made += 1

    def record_tokens(self, result: LLMCallResult) -> None:
        """Token accounting for any HTTP-200 attempt, successful or not:
        tokens are consumed by the provider even when validation later fails."""
        if result.prompt_tokens is not None:
            self.prompt_tokens += result.prompt_tokens
        if result.completion_tokens is not None:
            self.completion_tokens += result.completion_tokens

    def record_success(self, result: LLMCallResult) -> None:
        self.providers_used.add(result.provider)
        self.models_used.add(result.model)

    def record_failure(self) -> None:
        self.failed_calls += 1

    def usage_summary(self) -> dict[str, Any]:
        return {
            "total_calls": self.calls_made,
            "failed_calls": self.failed_calls,
            "prompt_tokens": self.prompt_tokens or None,
            "completion_tokens": self.completion_tokens or None,
            "providers_used": sorted(self.providers_used),
            "models_used": sorted(self.models_used),
        }


class LLMRouter:
    """Routes bounded LLM calls across configured providers.

    Per-call flow: budget check -> provider selection (healthy first) ->
    per-provider RPM + global RPM acquire -> HTTP with timeout -> strict
    schema validation with limited repair retries -> accounting.
    """

    def __init__(
        self,
        providers: Sequence[Any],
        *,
        global_rpm: int = 10,
        request_timeout_seconds: float = 90.0,
        max_retries_per_call: int = 2,
        default_max_output_tokens: int = 3000,
        max_concurrent_calls: int = 4,
        http_client: httpx.AsyncClient | None = None,
        sleeper: Callable[[float], Awaitable[None]] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if not providers:
            raise ValueError("LLMRouter requires at least one provider")
        self._providers = [
            _ProviderRuntime(
                name=p.name,
                base_url=p.base_url,
                api_key=p.api_key,
                model=p.model,
                rpm_limit=p.rpm_limit,
                max_output_tokens=p.max_output_tokens,
                json_mode=bool(getattr(p, "json_mode", False)),
            )
            for p in providers
        ]
        self._request_timeout = request_timeout_seconds
        self._max_retries = max_retries_per_call
        self._default_tokens = default_max_output_tokens
        self._sleeper = sleeper or asyncio.sleep
        self._clock = clock or time.monotonic
        self._global_limiter = _SlidingWindowLimiter(global_rpm, self._clock)
        self._provider_limiters = {
            p.name: _SlidingWindowLimiter(p.rpm_limit, self._clock) for p in self._providers
        }
        self._client = http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(request_timeout_seconds, connect=request_timeout_seconds),
        )
        self._semaphore = asyncio.Semaphore(max(1, max_concurrent_calls))

    async def aclose(self) -> None:
        await self._client.aclose()

    def start_audit(self, *, max_calls: int, deadline_seconds: float) -> AuditBudget:
        return AuditBudget(
            max_calls=max_calls,
            deadline=self._clock() + deadline_seconds,
            clock=self._clock,
        )

    def _healthy(self) -> list[_ProviderRuntime]:
        now = self._clock()
        return [
            p for p in self._providers if p.permanent_failure is None and now >= p.cooldown_until
        ]

    def _cooldown(self, p: _ProviderRuntime, seconds: float, reason: str) -> None:
        p.cooldown_until = max(p.cooldown_until, self._clock() + seconds)
        p.failures += 1
        logger.warning("llm provider=%s cooling down %.0fs (%s)", p.name, seconds, reason)

    async def _backoff(self, budget: AuditBudget, attempt: int) -> None:
        """Exponential-backoff sleep before retrying a transient provider
        failure. Skips the wait when the audit deadline is too close, so a
        slow transient never burns the whole deadline."""
        delay = _backoff_delay(attempt)
        if self._clock() + delay <= budget.deadline:
            await self._sleeper(delay)

    async def complete_json(
        self,
        budget: AuditBudget,
        messages: Sequence[dict[str, str]],
        schema_model: type[BaseModelT],
        *,
        max_output_tokens: int | None = None,
    ) -> tuple[BaseModelT, LLMCallResult]:
        """One logical call (against the audit budget) with strict validation.

        Provider-level failures rotate to the next provider; the whole logical
        call gets at most `1 + max_retries_per_call` HTTP attempts total.
        """
        budget.check()
        budget.record_call()

        attempts = 0
        max_attempts = 1 + self._max_retries
        last_error: Exception | str | None = None
        current_messages = list(messages)
        repair_provider: _ProviderRuntime | None = None

        while attempts < max_attempts:
            providers = self._healthy()
            if not providers:
                waiters = [p for p in self._providers if p.permanent_failure is None]
                if not waiters:
                    raise ProviderUnavailableError("all LLM providers are permanently failed")
                soonest = min(p.cooldown_until for p in waiters)
                wait = soonest - self._clock()
                if wait > 0 and self._clock() + wait <= budget.deadline:
                    logger.info("all providers cooling down; waiting %.1fs", wait)
                    await self._sleeper(wait)
                    continue
                raise ProviderUnavailableError(
                    f"no healthy provider within audit deadline (cooldown {wait:.0f}s)"
                )

            if repair_provider is not None:
                # schema-repair retry stays on the same provider: the failure
                # was output formatting, not provider health.
                p = repair_provider
                repair_provider = None
            else:
                p = providers[attempts % len(providers)]
            tokens = max_output_tokens or p.max_output_tokens or self._default_tokens
            payload = {
                "model": p.model,
                "messages": current_messages,
                "max_tokens": tokens,
                "temperature": 0,
            }
            # Structured-output mode (Section 6): only for providers configured
            # with json_mode=True; unknown fields break some OpenAI-compatible
            # endpoints, so this is strictly opt-in per provider.
            if p.json_mode:
                payload["response_format"] = {"type": "json_object"}
            await self._provider_limiters[p.name].acquire(self._sleeper, budget.deadline)
            await self._global_limiter.acquire(self._sleeper, budget.deadline)

            started = self._clock()
            try:
                async with self._semaphore:
                    resp = await self._client.post(
                        f"{p.base_url}/chat/completions",
                        json=payload,
                        headers={"Authorization": f"Bearer {p.api_key}"},
                    )
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                self._cooldown(p, COOLDOWN_SERVER_ERROR_SECONDS, f"transport: {exc}")
                last_error = exc
                attempts += 1
                await self._backoff(budget, attempts)
                continue

            duration = self._clock() - started
            if resp.status_code == 429:
                self._cooldown(p, COOLDOWN_RATE_LIMIT_SECONDS, "HTTP 429")
                last_error = LLMRouterError(f"{p.name}: 429")
                attempts += 1
                await self._backoff(budget, attempts)
                continue
            if resp.status_code >= 500:
                self._cooldown(p, COOLDOWN_SERVER_ERROR_SECONDS, f"HTTP {resp.status_code}")
                last_error = LLMRouterError(f"{p.name}: HTTP {resp.status_code}")
                attempts += 1
                await self._backoff(budget, attempts)
                continue
            if resp.status_code >= 400:
                # 400/401/403/404: permanent for this provider (bad key/model/payload)
                p.permanent_failure = f"HTTP {resp.status_code}"
                logger.error(
                    "llm provider=%s permanently failed: HTTP %d (body not logged)",
                    p.name,
                    resp.status_code,
                )
                last_error = LLMRouterError(f"{p.name}: HTTP {resp.status_code}")
                attempts += 1
                continue

            try:
                data = resp.json()
                msg = data["choices"][0]["message"]
                content = msg.get("content") or ""
                # Some providers (reasoning models) return their answer in
                # `reasoning_content` with an empty `content` when the prompt is
                # long. Fall back to the reasoning output so the audit isn't
                # lost to an empty_response (mirrors AgentLISA's approach of
                # using whatever the model actually produced).
                if not content.strip():
                    content = msg.get("reasoning_content") or ""
                usage = data.get("usage") or {}
            except (ValueError, KeyError, TypeError, IndexError):
                self._cooldown(p, COOLDOWN_SERVER_ERROR_SECONDS, "malformed response body")
                last_error = LLMRouterError(f"{p.name}: malformed response")
                attempts += 1
                await self._backoff(budget, attempts)
                continue

            result = LLMCallResult(
                content=content,
                provider=p.name,
                model=p.model,
                duration_seconds=duration,
                prompt_tokens=usage.get("prompt_tokens"),
                completion_tokens=usage.get("completion_tokens"),
            )
            # Usage accounting is preserved for EVERY HTTP-200 attempt, even
            # when structured-output validation subsequently fails.
            budget.record_tokens(result)
            p.calls += 1
            from agentsafe.metrics import get_metrics

            get_metrics().incr("llm_calls")
            if result.prompt_tokens is not None:
                get_metrics().incr("llm_tokens_in", result.prompt_tokens)
            if result.completion_tokens is not None:
                get_metrics().incr("llm_tokens_out", result.completion_tokens)
            logger.info(
                "llm ok provider=%s model=%s duration=%.2fs prompt_tokens=%s completion_tokens=%s",
                p.name,
                p.model,
                duration,
                result.prompt_tokens,
                result.completion_tokens,
            )

            validated, failure = _validate_json_strict(content, schema_model)
            if validated is not None:
                get_metrics().incr("llm_success")
                budget.record_success(result)
                return validated, result
            # Strict validation failed: repair attempts reuse the same provider
            # slot budget; if retries are exhausted the call fails loudly and
            # categorically - malformed output is NEVER turned into findings.
            last_error = failure
            logger.warning(
                "llm provider=%s output validation failed (%s); attempt=%d/%d",
                p.name,
                failure,
                attempts + 1,
                max_attempts,
            )
            if attempts + 1 >= max_attempts:
                break
            current_messages = [
                *messages,
                {"role": "assistant", "content": content},
                {
                    "role": "user",
                    "content": (
                        "You returned an EMPTY response."
                        if failure.category == VC_EMPTY
                        else
                        "Your previous reply was NOT valid JSON for the required schema."
                    )
                    + f" (problem: {failure.detail}). Respond again with ONLY a valid "
                    "JSON object matching the schema. No markdown, no commentary.",
                },
            ]
            repair_provider = p
            attempts += 1

        budget.record_failure()
        from agentsafe.metrics import get_metrics

        get_metrics().incr("llm_failed")
        if isinstance(last_error, SchemaValidationError):
            raise last_error
        if isinstance(last_error, ValidationFailure):
            raise SchemaValidationError(
                f"structured output failed after {max_attempts} attempts "
                f"({last_error.category}): {last_error.detail}"
            )
        raise ProviderUnavailableError(
            f"LLM call failed after {max_attempts} attempts: {last_error}"
        )


BaseModelT = TypeVar("BaseModelT", bound=BaseModel)


def _extract_balanced(text: str) -> str | None:
    """Locate the FIRST balanced JSON object/array in arbitrary text
    (string-aware, escape-aware). Extraction only: bytes between the outermost
    brackets are never modified, so no content is invented or repaired away."""
    start = -1
    for i, ch in enumerate(text):
        if ch in "{[":
            start = i
            break
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for j in range(start, len(text)):
        ch = text[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
            if depth == 0:
                return text[start : j + 1]
    return None




def _sanitize_id_fields(obj):
    """Recursively normalize swc_id/cwe_id values that LLMs often pad with a
    parenthetical label (e.g. 'SWC-107 (Reentrancy)'). Keeps the strict
    SWC-xxxx/CWE-xxxx token; never fabricates an id when none is present."""
    if isinstance(obj, dict):
        for k in ("swc_id", "cwe_id"):
            v = obj.get(k)
            if isinstance(v, str):
                m = re.search(r"(SWC-\d+|CWE-\d+)", v)
                obj[k] = m.group(1) if m else v[:16]
        for v in obj.values():
            _sanitize_id_fields(v)
    elif isinstance(obj, list):
        for it in obj:
            _sanitize_id_fields(it)

def _validate_json_strict(
    content: str, schema_model: type[BaseModelT]
) -> tuple[BaseModelT | None, ValidationFailure | None]:
    """Strict structured-output validation with categorized failures.

    Pipeline: empty check -> fenced ```json unwrapping (standard LLM
    formatting) -> direct parse -> balanced-object extraction (for JSON
    embedded in prose) -> pydantic schema validation. A failure returns a
    ValidationFailure with a stable category; content is never guessed into
    findings and no lenient regex repair is attempted.
    """
    text = (content or "").strip()
    if not text:
        return None, ValidationFailure(VC_EMPTY, "empty response (0 usable chars)")
    if text.startswith("```"):
        first_newline = text.find("\n")
        if first_newline != -1:
            text = text[first_newline + 1 :]
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
        text = text.strip()
    parsed = None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        # Deterministic mechanical repair (single quotes, unquoted keys,
        # trailing commas, stray prose) BEFORE an expensive re-prompt.
        repaired = repair_json(text)
        if repaired is not None:
            try:
                parsed = json.loads(repaired)
            except json.JSONDecodeError:
                parsed = None
        if parsed is None:
            candidate = _extract_balanced(text)
            if candidate is not None:
                try:
                    parsed = json.loads(candidate)
                except json.JSONDecodeError:
                    parsed = None
    if parsed is None:
        detail = text[:120].replace("\n", " ")
        return None, ValidationFailure(VC_INVALID_JSON, f"no parsable JSON object: {detail!r}")
    _sanitize_id_fields(parsed)
    try:
        return schema_model.model_validate(parsed), None
    except Exception as exc:
        return None, ValidationFailure(VC_SCHEMA, str(exc)[:300])
