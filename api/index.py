"""Vercel Serverless Function for agentSAFE MCP server (ASGI entrypoint).

The Vercel Python runtime requires a top-level ``app`` variable that is an
ASGI callable (scope, receive, send) -> awaitable. FastMCP's ``http_app()``
returns a Starlette ASGI application, exposed here directly.

Two failure classes are handled so the module ALWAYS imports successfully and
Vercel can reliably detect the ``app`` entrypoint:

1. Missing dependencies / import errors -> surfaced as HTTP 500 with a hint.
2. Missing / invalid environment config -> deferred to runtime (validate=False)
   and surfaced as HTTP 500 instead of crashing the function at build time.

This mirrors the FastMCP Cloud path documented in DEPLOYMENT.md: build-time
inspection runs without env vars; a misconfigured deployment refuses to serve
at runtime rather than failing to build.
"""

import sys
from pathlib import Path

# Add src directory to path so agentsafe package imports work.
# Vercel runs from the repo root; keep this explicit for local runs too.
_src = Path(__file__).resolve().parent.parent / "src"
_src_str = str(_src)
if _src_str not in sys.path:
    sys.path.insert(0, _src_str)


def _error_app(message: str):
    """Minimal ASGI app that surfaces configuration errors as HTTP 500."""

    async def _asgi(scope, receive, send):
        if scope["type"] != "http":
            return
        body = f"agentSAFE configuration error: {message}\n".encode()
        await send(
            {
                "type": "http.response.start",
                "status": 500,
                "headers": [(b"content-type", b"text/plain; charset=utf-8")],
            }
        )
        await send({"type": "http.response.body", "body": body})

    return _asgi


def _build_app():
    """Build the real ASGI app, degrading to a clear 500 on any failure.

    Uses validate=False (matching create_app / FastMCP Cloud) so import-time
    env-var inspection never crashes the module; a misconfigured deployment
    serves HTTP 500 with the underlying error message instead.
    """
    try:
        from agentsafe.config import Settings
        from agentsafe.server import build_server

        settings = Settings()
        server = build_server(settings, validate=False)
        asgi = server.http_app()
        return asgi
    except Exception as exc:  # noqa: BLE001 - entrypoint must always resolve
        return _error_app(str(exc))


# Vercel Python runtime entrypoint (ASGI).
app = _build_app()