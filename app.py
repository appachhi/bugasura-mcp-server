"""FastMCP instance + ASGI applications for both transports."""
from starlette.responses import JSONResponse
from starlette.routing import Route

from fastmcp import FastMCP

from config import API_BASE, MCP_SERVER_NAME, logger


mcp = FastMCP(MCP_SERVER_NAME)


def health_check(request):
    """
    Health check endpoint for monitoring server status.

    Returns JSON with:
    - status: "ok" if server is running
    - service: Service name
    - version: Current version
    - api_base: Configured Bugasura API URL

    Used by load balancers, monitoring tools, and manual testing.
    """
    return JSONResponse({
        "status": "ok",
        "service": "Bugasura MCP Server",
        "version": "2.0.0",
        "api_base": API_BASE
    })


def sse_migration(request):
    """
    Tell legacy SSE clients that the transport has moved to streamable HTTP at /mcp.

    Returns 410 Gone with a JSON body so clients (and humans hitting the URL in
    a browser) get an actionable migration message instead of a bare 404.
    """
    new_endpoint = str(request.url.replace(path="/mcp"))
    logger.info(f"Legacy SSE request from {request.client.host if request.client else 'unknown'} -> 410 (migrate to /mcp)")
    return JSONResponse(
        {
            "status": "gone",
            "error": "The SSE transport has been removed.",
            "migrate_to": "/mcp",
            "transport": "streamable-http",
            "new_endpoint": new_endpoint,
            "message": (
                "Bugasura MCP no longer supports SSE. Update your MCP client "
                f"configuration to point at {new_endpoint} (streamable-HTTP)."
            ),
        },
        status_code=410,
    )


# ASGI application for streamable HTTP transport (per mcp_best_practices.md).
# /sse returns a 410 Gone with migration guidance for legacy 1.x clients.
mcp._additional_http_routes = [
    Route("/health", health_check),
    Route("/sse", sse_migration),
]
app = mcp.http_app(path="/mcp", transport="streamable-http")
