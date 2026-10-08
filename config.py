"""Shared configuration: environment variables + logging setup."""
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from dotenv import load_dotenv

# Per-tenant dotenv selection. MCP_ENV_FILE must come from the real process
# environment (systemd `Environment=`), since it is read before any dotenv file
# is loaded. Unset -> ".env", identical to the single-tenant behaviour.
# A missing file is fatal on purpose: falling back to ".env" would silently
# serve the production backend under a tenant's hostname.
_env_name = os.getenv("MCP_ENV_FILE", "").strip()
_env_path = Path(_env_name) if _env_name else Path(".env")
if not _env_path.is_absolute():
    _env_path = Path(__file__).resolve().parent / _env_path
if _env_name and not _env_path.is_file():
    raise RuntimeError(f"MCP_ENV_FILE points at a missing file: {_env_path}")

load_dotenv(_env_path)

logger = logging.getLogger('bugasura_mcp')
logger.setLevel(logging.INFO)

_formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
if not logger.handlers:
    _console = logging.StreamHandler()
    _console.setLevel(logging.DEBUG)
    _console.setFormatter(_formatter)
    logger.addHandler(_console)

    _log_path = os.getenv("LOG_PATH")
    if _log_path:
        os.makedirs(_log_path, exist_ok=True)
        _log_date = datetime.now().strftime("%Y-%m-%d")
        _log_prefix = os.getenv("LOG_FILE_PREFIX", "bugasura-mcp-server")
        _dated_log_file = os.path.join(_log_path, f"{_log_prefix}.{_log_date}.log")
        _file_handler = logging.FileHandler(_dated_log_file)
        _file_handler.setLevel(logging.INFO)
        _file_handler.setFormatter(_formatter)
        logger.addHandler(_file_handler)
        logger.info(f"File logging enabled: {_dated_log_file}")

logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)

API_BASE = os.getenv("API_BASE_URL", "https://api.bugasura.io")
MCP_SERVER_NAME = os.getenv("MCP_SERVER_NAME", "bugasura_mcp")
# Legacy API key. Used only by the STDIO transport, where no OAuth sign-in is possible.
BUGASURA_API_KEY = os.getenv("BUGASURA_API_KEY", "")


# API host -> customer-facing web app base URL.
# Set WEB_BASE_URL in .env to override for deployments not listed here.
_KNOWN_WEB_BASES = {
    "api.bugasura.io": "https://my.bugasura.io/",
}


def _derive_web_base(api_base: str) -> str:
    """Return the customer-facing web app base URL derived from an API base URL."""
    try:
        p = urlparse(api_base)
        host = p.netloc.split('@')[-1].split(':')[0]
        if host in _KNOWN_WEB_BASES:
            return _KNOWN_WEB_BASES[host]
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}/"
    except Exception:
        pass
    return ""


# API host -> CDN base that serves stored files.
# Uploaded files are public objects under this base, so `CDN_BASE_URL + <file path>` is a
# working download link. Set CDN_BASE_URL in .env for deployments not listed here — the CDN
# is a separate CloudFront/S3 host, so unlike the web base it can never be guessed from the
# API host.
_KNOWN_CDN_BASES = {
    "api.bugasura.io": "https://dp891r6qeu0kb.cloudfront.net/",
}


def _derive_cdn_base(api_base: str) -> str:
    """Return the CDN base URL for a known API host, or '' when it is not known."""
    try:
        host = urlparse(api_base).netloc.split('@')[-1].split(':')[0]
        return _KNOWN_CDN_BASES.get(host, "")
    except Exception:
        return ""


WEB_BASE_URL = os.getenv("WEB_BASE_URL", "").strip() or _derive_web_base(API_BASE)
if WEB_BASE_URL and not WEB_BASE_URL.endswith("/"):
    WEB_BASE_URL += "/"

CDN_BASE_URL = os.getenv("CDN_BASE_URL", "").strip() or _derive_cdn_base(API_BASE)
if CDN_BASE_URL and not CDN_BASE_URL.endswith("/"):
    CDN_BASE_URL += "/"


# --- OAuth 2.0 sign-in (streamable-HTTP transport only) ---------------------------------
# The MCP server fronts Bugasura's authorization server with FastMCP's OAuthProxy. These are
# per-deployment (and per-tenant dotenv) values; the first three are required in HTTP mode.
MCP_PUBLIC_BASE_URL = os.getenv("MCP_PUBLIC_BASE_URL", "").strip().rstrip("/")
BUGASURA_OAUTH_CLIENT_ID = os.getenv("BUGASURA_OAUTH_CLIENT_ID", "").strip()
BUGASURA_OAUTH_CLIENT_SECRET = os.getenv("BUGASURA_OAUTH_CLIENT_SECRET", "").strip()
MCP_JWT_SIGNING_KEY = os.getenv("MCP_JWT_SIGNING_KEY", "").strip()
OAUTH_STORAGE_PATH = os.getenv("OAUTH_STORAGE_PATH", "").strip()
OAUTH_ALLOWED_REDIRECT_URIS = os.getenv("OAUTH_ALLOWED_REDIRECT_URIS", "").strip()
# Seconds a positive token introspection is cached (also bounds how long a revoked session keeps working)
DEFAULT_OAUTH_INTROSPECTION_CACHE_TTL = 60
OAUTH_INTROSPECTION_CACHE_TTL = int(
    os.getenv("OAUTH_INTROSPECTION_CACHE_TTL", "").strip() or DEFAULT_OAUTH_INTROSPECTION_CACHE_TTL
)
OAUTH_INTROSPECTION_TIMEOUT_SECONDS = 10.0
# Introspection cache size that triggers pruning of expired entries
OAUTH_INTROSPECTION_CACHE_MAX_ENTRIES = 5000
# Lifetime of the token issued to MCP clients when Bugasura omits expires_in (matches its 1-hour access tokens)
OAUTH_FALLBACK_TOKEN_EXPIRY_SECONDS = 3600
# Show FastMCP's own consent interstitial before handing off to Bugasura's login. Off by default:
# users then see only Bugasura's login + consent page. See README "About the consent pages".
OAUTH_REQUIRE_CONSENT = os.getenv("OAUTH_REQUIRE_CONSENT", "false").strip().lower() in ("1", "true", "yes")

# Redirect URIs MCP clients may use, for DCR and CIMD alike. Scheme, host and port are matched
# separately: the host must be exact or "*.domain", '*' in the path matches '/', loopback any port.
DEFAULT_ALLOWED_REDIRECT_URIS = [
    # Loopback: Claude Code, Cline, Roo Code, MCP Inspector, fastmcp Client and Cursor CLI take a
    # random port; VS Code registers "http://127.0.0.1/" and picks the port at authorize time (RFC 8252).
    "http://localhost:*",
    "http://localhost/*",
    "http://127.0.0.1:*",
    "http://127.0.0.1/*",
    # Claude Desktop / claude.ai custom connectors
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
    # VS Code (Copilot) stable and Insiders, browser and app-scheme callbacks; Cline and Roo Code run
    # inside VS Code and use its vscode:// scheme
    "https://vscode.dev/redirect",
    "https://insiders.vscode.dev/redirect",
    "vscode://vscode.github-authentication/*",
    "vscode-insiders://vscode.github-authentication/*",
    # Cursor and Windsurf desktop apps (app-scheme callbacks); Cursor web / background agents use a fixed https callback
    "cursor://anysphere.cursor-mcp/*",
    "cursor://anysphere.cursor-retrieval/*",
    "https://www.cursor.com/agents/mcp/oauth/callback",
    "windsurf://codeium.windsurf/*",
    # Google Antigravity
    "https://antigravity.google/oauth-callback",
    # ChatGPT connectors (also what Codex registers through); the last segment is a per-connector ID
    "https://chatgpt.com/connector/oauth/*",
]

# Upstream endpoints. Derived from the web/API bases; override only for unusual deployments.
BUGASURA_OAUTH_AUTHORIZE_URL = os.getenv("BUGASURA_OAUTH_AUTHORIZE_URL", "").strip() or f"{WEB_BASE_URL}oauth/authorize"
BUGASURA_OAUTH_TOKEN_URL = os.getenv("BUGASURA_OAUTH_TOKEN_URL", "").strip() or f"{API_BASE}/v1/oauth/token"
BUGASURA_OAUTH_INTROSPECT_URL = os.getenv("BUGASURA_OAUTH_INTROSPECT_URL", "").strip() or f"{API_BASE}/v1/oauth/introspect"
BUGASURA_OAUTH_REVOKE_URL = os.getenv("BUGASURA_OAUTH_REVOKE_URL", "").strip() or f"{API_BASE}/v1/oauth/revoke"


# Logo shown on the OAuth consent page (and offered to MCP clients as the server icon, with the SVG).
MCP_SERVER_ICON_URL = os.getenv("MCP_SERVER_ICON_URL", "").strip() or "https://bugasura.io/bugasura_icon_1024.png"
MCP_SERVER_ICON_SVG_URL = os.getenv("MCP_SERVER_ICON_SVG_URL", "").strip() or "https://bugasura.io/bugasura_icon_512.svg"

# ChatGPT app domain-verification token, served at /.well-known/openai-apps-challenge (404 when unset).
OPENAI_APPS_CHALLENGE_TOKEN = os.getenv("OPENAI_APPS_CHALLENGE_TOKEN", "").strip()

# How long a user's teams/projects context is cached per credential (auth.fetch_user_context).
USER_CONTEXT_TTL_SECONDS = 300  # 5 minutes

# Tool payload statuses reported as an MCP tool error (isError); the Bugasura API itself answers errors with "ERROR".
# Compared lower-cased.
ERROR_STATUSES = {"failed", "error", "api_key_required"}

# Test case platform types the API accepts. The agents are platform bound:
# the Browser Agent runs only Desktop Web, the Mobile Agent only the mobile types.
TestCasePlatformType = Literal["DESKTOP_WEB", "ANDROID", "ANDROID_MOBILE_WEB", "IOS", "IOS_MOBILE_WEB", "MULTI_PLATFORM"]
BROWSER_AGENT_PLATFORM_TYPES = {"DESKTOP_WEB"}
MOBILE_AGENT_PLATFORM_TYPES = {"ANDROID", "ANDROID_MOBILE_WEB", "IOS", "IOS_MOBILE_WEB"}

# Credential keys masked out of tool responses; the KB import endpoints echo connection secrets back. Compared lower-cased.
SECRET_RESPONSE_KEYS = {"accesstoken", "password", "apitoken", "api_key", "coda_api_key", "client_secret"}

# Public product site, linked from server metadata and the browser page on /mcp.
BUGASURA_WEBSITE_URL = os.getenv("BUGASURA_WEBSITE_URL", "").strip().rstrip("/") or "https://bugasura.io"

# MCP URL users add to their client: this instance's own endpoint, or the hosted one under STDIO.
MCP_CONNECT_URL = f"{MCP_PUBLIC_BASE_URL or 'https://mcp.bugasura.io'}/mcp"


def oauth_configured() -> bool:
    """True when the values required to run the OAuth front door are all present."""
    return bool(MCP_PUBLIC_BASE_URL and BUGASURA_OAUTH_CLIENT_ID and BUGASURA_OAUTH_CLIENT_SECRET)

logger.info(f"MCP Server: {MCP_SERVER_NAME}")
