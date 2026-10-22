"""Vercel Serverless Function for agentSAFE MCP server."""

import os
import sys
from pathlib import Path

# Add src directory to path so agentsafe package imports work
src_path = Path(__file__).resolve().parent.parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# Build the FastMCP server at module load time
# (cached across requests within same instance)
_mcp_app = None


def _get_mcp_app():
    """Lazy-initialize the MCP server app."""
    global _mcp_app
    if _mcp_app is not None:
        return _mcp_app
    
    from agentsafe.server import build_server
    from agentsafe.config import Settings
    
    settings = Settings()
    
    try:
        mcp = build_server(settings, validate=True)
        _mcp_app = mcp.http_app()
    except Exception as e:
        # Return error response if configuration is invalid
        from starlette.responses import PlainTextResponse
        
        def error_app(request):
            return PlainTextResponse(
                f"agentSAFE configuration error: {e}\n",
                status_code=500
            )
        _mcp_app = error_app
    
    return _mcp_app


# Vercel expects a `handler` function with signature handler(request)
def handler(request):
    """Vercel Serverless entry point - delegates to FastMCP HTTP app."""
    app = _get_mcp_app()
    # Starlette apps implement call(request) -> response
    return app.handle_request(request)

