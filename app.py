"""FastMCP instance + ASGI application for the streamable-HTTP transport."""
from html import escape
from urllib.parse import urlsplit

from starlette.middleware import Middleware as ASGIMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse

from fastmcp import FastMCP
from fastmcp.server.middleware import Middleware, MiddlewareContext
from mcp_types import Icon

from config import (
    API_BASE, BUGASURA_WEBSITE_URL, ERROR_STATUSES, MCP_CONNECT_URL, MCP_PUBLIC_BASE_URL,
    MCP_SERVER_ICON_SVG_URL, MCP_SERVER_ICON_URL, MCP_SERVER_NAME, OPENAI_APPS_CHALLENGE_TOKEN, logger,
)
from oauth import build_auth_provider


# OAuth front door when configured (HTTP deployments); None for STDIO / local dev.
# mcp.run(transport="stdio") ignores auth, so one process serves both transports.
auth = build_auth_provider()

# Reported by /health and by server/discover (serverInfo.version)
SERVER_VERSION = "3.1.0"

# Returned by server/discover; how an assistant should drive the tools.
SERVER_INSTRUCTIONS = """\
Bugasura is a test management and bug tracking platform. Data is scoped team -> project -> \
items (issues, sprints, test cases, requirements, test runs, knowledge base, TestPert).

- team_id / project_id accept numeric IDs or names; issue identifiers also accept keys such as \
ISS09. When context is missing a tool returns status "selection_required" with "options": show \
them to the user, then call the same tool again with the chosen value. Don't guess IDs.
- List tools are paginated: pass start_at and max_results, and follow has_more / next_offset.
- Results carry a "status" field: OK, selection_required, failed (see error / error_type), or \
api_key_required. On api_key_required, follow its "action" text: never ask the user for an API key.
- Confirm with the user before calling delete_* tools; deletions cannot be undone.
- Report tool results without speculating about Bugasura's internals, code or schema; do pass on \
warnings or partial failures a result reports.
"""

# name, icon and website brand FastMCP's consent interstitial (the page shown before Bugasura's own login).
mcp = FastMCP(
    MCP_SERVER_NAME,
    instructions=SERVER_INSTRUCTIONS,
    version=SERVER_VERSION,
    auth=auth,
    website_url=BUGASURA_WEBSITE_URL,
    icons=[
        Icon(src=MCP_SERVER_ICON_SVG_URL, mime_type="image/svg+xml", sizes=["any"]),
        # no sizes: MCP_SERVER_ICON_URL may point at any PNG
        Icon(src=MCP_SERVER_ICON_URL, mime_type="image/png"),
    ],
    # Lists, resources and discover are identical for all users (no per-user or per-deployment
    # secrets in any resource), so clients may share a 5-minute cache
    cache_ttl=300,
    cache_scope="public",
    # Uncaught exceptions reach the client as a generic error; details stay in the server log
    mask_error_details=True,
)


class ToolErrorFlagMiddleware(Middleware):
    """Report a tool payload whose status is in ERROR_STATUSES as an MCP tool error."""

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        result = await call_next(context)
        payload = result.structured_content or {}
        # FastMCP wraps dict returns as {"result": {...}}
        payload = payload.get("result", payload) if isinstance(payload, dict) else {}
        status = payload.get("status") if isinstance(payload, dict) else None
        if isinstance(status, str) and status.lower() in ERROR_STATUSES:
            result.is_error = True
        return result


mcp.add_middleware(ToolErrorFlagMiddleware())


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request):
    """
    Health check endpoint for monitoring server status.

    Returns JSON with:
    - status: "ok" if server is running
    - service: Service name
    - version: Current version
    - server_name: Configured MCP server name (tells tenant instances apart)
    - api_base: Configured Bugasura API URL
    - auth: "oauth" when the sign-in flow is enabled, "none" otherwise

    Used by load balancers, monitoring tools, and manual testing. Not authenticated.
    """
    return JSONResponse({
        "status": "ok",
        "service": "Bugasura MCP Server",
        "version": SERVER_VERSION,
        "server_name": MCP_SERVER_NAME,
        "api_base": API_BASE,
        "auth": "oauth" if auth else "none",
    })


@mcp.custom_route("/.well-known/openai-apps-challenge", methods=["GET"])
async def openai_apps_challenge(request: Request):
    """ChatGPT app domain verification: the bare token as plain text, 404 when not configured."""
    if not OPENAI_APPS_CHALLENGE_TOKEN:
        return PlainTextResponse("Not Found", status_code=404)
    return PlainTextResponse(OPENAI_APPS_CHALLENGE_TOKEN)


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


class BrowserVisitMiddleware:
    """Answer a browser tab opening /mcp with a readable 400 page instead of an empty 401."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["method"] == "GET" and scope["path"].rstrip("/") == "/mcp":
            headers = Request(scope).headers
            # MCP clients never ask for text/html; a signed-in request always carries a token
            if "text/html" in headers.get("accept", "") and "authorization" not in headers:
                await _browser_page(scope)(scope, receive, send)
                return
        await self.app(scope, receive, send)


def _browser_page(scope) -> HTMLResponse:
    url = escape(MCP_CONNECT_URL if MCP_PUBLIC_BASE_URL else f"{str(Request(scope).base_url).rstrip('/')}/mcp")
    site = escape(BUGASURA_WEBSITE_URL)
    return HTMLResponse(status_code=400, content=f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>400 Bad Request · {escape(MCP_SERVER_NAME)}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;color:#222;line-height:1.5}}
code{{background:#f2f2f2;padding:.1rem .35rem;border-radius:4px}}</style></head>
<body><h1>400 Bad Request</h1>
<p>This is the Bugasura MCP server endpoint. It is used by AI assistants, not opened in a browser.</p>
<p>Add <code>{url}</code> as a custom connector or MCP server in Claude, Cursor, VS Code, ChatGPT or another
MCP client; it will open the Bugasura sign-in when it connects.</p>
<p><a href="{site}">{escape(urlsplit(BUGASURA_WEBSITE_URL).netloc)}</a></p></body></html>""")


# ASGI application. With auth set, FastMCP also mounts the OAuth routes at the root:
# /.well-known/oauth-authorization-server, /.well-known/oauth-protected-resource/mcp,
# /authorize, /token, /register, /revoke, /auth/callback and /consent. Only /mcp itself
# requires a bearer token; /health, /sse and /.well-known/openai-apps-challenge stay public.
# Rejects a foreign Origin with 403 and an unknown Host with 421 (DNS rebinding); loopback is always allowed.
app = mcp.http_app(
    path="/mcp",
    transport="streamable-http",
    host_origin_protection=True,
    allowed_hosts=[urlsplit(MCP_PUBLIC_BASE_URL).netloc] if MCP_PUBLIC_BASE_URL else None,
    allowed_origins=[MCP_PUBLIC_BASE_URL] if MCP_PUBLIC_BASE_URL else None,
    middleware=[ASGIMiddleware(BrowserVisitMiddleware)],
)
