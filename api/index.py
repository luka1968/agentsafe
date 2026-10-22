# Vercel Serverless Function entry point for agentSAFE MCP server
# This handles all HTTP traffic and routes through FastMCP's HTTP transport

from agentsafe.server import build_server
from agentsafe.settings import Settings

# Load environment variables (set in Vercel dashboard)
settings = Settings()

# Build the MCP server instance with configuration validation
mcp = build_server(settings, validate=True)

# Get the Starlette/ASGI app from FastMCP's HTTP transport
app = mcp.http_app()

