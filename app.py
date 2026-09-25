"""FastMCP instance + ASGI application for the streamable-HTTP transport."""
from starlette.requests import Request
from starlette.responses import JSONResponse

from fastmcp import FastMCP
from mcp.types import Icon

from config import API_BASE, MCP_SERVER_ICON_URL, MCP_SERVER_NAME, logger
from oauth import build_auth_provider


# OAuth front door when configured (HTTP deployments); None for STDIO / local dev.
# mcp.run(transport="stdio") ignores auth, so one process serves both transports.
auth = build_auth_provider()

# name, icon and website brand FastMCP's consent interstitial (the page shown before Bugasura's own login).
mcp = FastMCP(
    MCP_SERVER_NAME,
    auth=auth,
    website_url="https://bugasura.io",
    icons=[Icon(src=MCP_SERVER_ICON_URL, mimeType="image/png", sizes=["300x300"])],
)


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request):
    """
    Health check endpoint for monitoring server status.

    Returns JSON with:
    - status: "ok" if server is running
    - service: Service name
    - version: Current version
    - server_name: Configured MCP server name (tells instances apart)
    - api_base: Configured Bugasura API URL
    - auth: "oauth" when the sign-in flow is enabled, "none" otherwise

    Used by load balancers, monitoring tools, and manual testing. Not authenticated.
    """
    return JSONResponse({
        "status": "ok",
        "service": "Bugasura MCP Server",
        "version": "3.0.0",
        "server_name": MCP_SERVER_NAME,
        "api_base": API_BASE,
        "auth": "oauth" if auth else "none",
    })


@mcp.custom_route("/sse", methods=["GET", "POST"])
async def sse_migration(request: Request):
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


# ASGI application. With auth set, FastMCP also mounts the OAuth routes at the root:
# /.well-known/oauth-authorization-server, /.well-known/oauth-protected-resource/mcp,
# /authorize, /token, /register, /revoke, /auth/callback and /consent. Only /mcp itself
# requires a bearer token; /health and /sse stay public.
app = mcp.http_app(path="/mcp", transport="streamable-http")
