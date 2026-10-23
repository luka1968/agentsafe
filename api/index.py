"""Vercel Serverless Function for agentSAFE MCP server (ASGI entrypoint).

The Vercel Python runtime requires a top-level ASGI ``app`` variable.
FastMCP's ``http_app()`` returns a Starlette ASGI application, which is
exposed here directly. Configuration problems degrade to a plain-text
500 responder instead of crashing the function.
"""

import sys
from pathlib import Path

# Add src directory to path so agentsafe package imports work
src_path = Path(__file__).resolve().parent.parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))


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
    try:
        from agentsafe.config import Settings
        from agentsafe.server import build_server

        return build_server(Settings(), validate=True).http_app()
    except Exception as exc:
        return _error_app(str(exc))


app = _build_app()
