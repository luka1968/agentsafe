"""Vercel Serverless Function for agentSAFE MCP server (ASGI entrypoint).

The Vercel Python runtime requires a top-level ``app`` variable that is an
ASGI callable. FastMCP's ``http_app()`` provides it, with two serverless
adaptations applied here:

1. ``stateless_http=True, json_response=True`` - no session affinity and no
   SSE streaming, both of which are serverless-hostile (cold starts kill
   sessions; function/proxy layers may buffer streams). Spec-compliant: the
   streamable-HTTP transport lets the server choose JSON responses.

2. ``_ServerlessLifespanBootstrap`` - Vercel never emits ASGI ``lifespan``
   events, but FastMCP only starts its streamable-HTTP session manager
   inside the lifespan. Without this bootstrap every ``/mcp`` request fails
   with "Task group is not initialized" -> HTTP 500 (observed in
   production). The bootstrap runs the real lifespan in a dedicated holder
   task on the serving event loop - the uvicorn model: a lifespan task
   separate from request tasks. Enter, suspension and exit all happen in the
   holder task's own context, which keeps anyio task groups and fastmcp's
   ContextVar tokens consistent. Real ASGI servers (uvicorn CLI) DO emit
   lifespan, so the pass-through branch keeps local behavior unchanged.

Configuration errors degrade to a plain-text 500 responder instead of
crashing the function, mirroring the FastMCP Cloud path in DEPLOYMENT.md.
"""

import asyncio
import sys
from pathlib import Path

import anyio

# Add src directory to path so agentsafe package imports work.
# Vercel runs from the repo root; keep this explicit for local runs too.
_src = Path(__file__).resolve().parent.parent / "src"
_src_str = str(_src)
if _src_str not in sys.path:
    sys.path.insert(0, _src_str)


async def _send_text_error(send, message: str) -> None:
    """Emit a plain-text HTTP 500 with a safe error description."""
    body = f"agentSAFE configuration error: {message}\n".encode()
    await send(
        {
            "type": "http.response.start",
            "status": 500,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _error_app(message: str):
    """Minimal ASGI app that surfaces configuration errors as HTTP 500."""

    async def _asgi(scope, receive, send):
        if scope["type"] != "http":
            return
        await _send_text_error(send, message)

    return _asgi


class _ServerlessLifespanBootstrap:
    """Run the wrapped app's lifespan when the host never emits it.

    The lifespan is entered and held by a dedicated background task on the
    serving event loop (never exited unless :meth:`aclose` is called).
    Entering/exiting from the SAME task keeps anyio cancel scopes and
    fastmcp's ContextVar tokens consistent - the uvicorn model.

    Idempotent and concurrency-safe: a single holder task per warm instance,
    guarded by a lock and flags. Startup failures are captured and re-served
    as clear 500 text instead of crashing repeatedly.
    """

    def __init__(self, asgi_app) -> None:
        self._app = asgi_app
        self._started = False
        self._failed = False
        self._error = ""
        self._lock = anyio.Lock()  # anyio 4.x: safe to create outside a loop
        self._holder_task: asyncio.Task | None = None
        self._shutdown_event: asyncio.Event | None = None

    async def _hold_lifespan(self, started: asyncio.Event, shutdown: asyncio.Event) -> None:
        """Enter the lifespan and hold it until ``shutdown`` is set.

        The ``yield`` suspension point of the lifespan generator, the
        session manager's task group and every ContextVar token live inside
        this task - so a later exit (``shutdown`` or loop teardown) resets
        tokens in the very context that created them.
        """
        try:
            async with self._app.router.lifespan_context(self._app):
                self._started = True
                started.set()
                await shutdown.wait()
        except Exception as exc:  # noqa: BLE001 - fail closed with detail
            self._failed = True
            self._error = str(exc)
        finally:
            started.set()

    async def _ensure_started(self) -> None:
        if self._started or self._failed:
            return
        async with self._lock:
            if self._started or self._failed:
                return
            loop = asyncio.get_running_loop()
            started = asyncio.Event()
            shutdown = asyncio.Event()
            self._shutdown_event = shutdown
            self._holder_task = loop.create_task(self._hold_lifespan(started, shutdown))
            await started.wait()

    async def aclose(self) -> None:
        """Orderly shutdown: the holder task exits the lifespan inside its
        own context (task groups unwind, ContextVar tokens reset correctly).
        Idempotent; safe to call even when never started."""
        task, self._holder_task = self._holder_task, None
        if task is None or task.done():
            return
        if self._shutdown_event is not None:
            self._shutdown_event.set()
        try:
            await task
        except Exception:  # noqa: BLE001 - shutdown must never raise upstream
            pass

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            # Real ASGI server (local uvicorn): let Starlette run its own
            # lifespan, then never bootstrap on top of it.
            await self._app(scope, receive, send)
            self._started = True
            return
        if scope["type"] == "http":
            await self._ensure_started()
            if self._failed:
                await _send_text_error(send, self._error)
                return
        await self._app(scope, receive, send)


def _build_app():
    """Build the serverless ASGI app, degrading to a clear 500 on failure.

    Uses validate=False (matching create_app / FastMCP Cloud) so import-time
    env-var inspection never crashes the module; the deferred lifespan
    validation still refuses to serve when configuration is incomplete.
    """
    try:
        from agentsafe.config import Settings
        from agentsafe.server import build_server

        settings = Settings()
        server = build_server(settings, validate=False)
        asgi = server.http_app(stateless_http=True, json_response=True)
        return _ServerlessLifespanBootstrap(asgi)
    except Exception as exc:  # noqa: BLE001 - entrypoint must always resolve
        return _error_app(str(exc))


# Vercel Python runtime entrypoint (ASGI).
app = _build_app()
