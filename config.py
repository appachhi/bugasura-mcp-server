"""Shared configuration: environment variables + logging setup."""
import logging
import os
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

# Per-instance dotenv selection. MCP_ENV_FILE must come from the real process
# environment, since it is read before any dotenv file is loaded.
# Unset -> ".env", identical to the single-instance behaviour.
# A missing file is fatal on purpose: falling back to ".env" would silently
# point the instance at the wrong backend.
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
# is a separate host, so unlike the web base it can never be guessed from the API host.
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
# per-deployment (and per-instance dotenv) values; the first three are required in HTTP mode.
MCP_PUBLIC_BASE_URL = os.getenv("MCP_PUBLIC_BASE_URL", "").strip().rstrip("/")
BUGASURA_OAUTH_CLIENT_ID = os.getenv("BUGASURA_OAUTH_CLIENT_ID", "").strip()
BUGASURA_OAUTH_CLIENT_SECRET = os.getenv("BUGASURA_OAUTH_CLIENT_SECRET", "").strip()
MCP_JWT_SIGNING_KEY = os.getenv("MCP_JWT_SIGNING_KEY", "").strip()
OAUTH_STORAGE_PATH = os.getenv("OAUTH_STORAGE_PATH", "").strip()
OAUTH_ALLOWED_REDIRECT_URIS = os.getenv("OAUTH_ALLOWED_REDIRECT_URIS", "").strip()
OAUTH_INTROSPECTION_CACHE_TTL = int(os.getenv("OAUTH_INTROSPECTION_CACHE_TTL", "60") or 60)
# Show FastMCP's own consent interstitial before handing off to Bugasura's login. Off by default:
# users then see only Bugasura's login + consent page. See README "About the consent pages".
OAUTH_REQUIRE_CONSENT = os.getenv("OAUTH_REQUIRE_CONSENT", "false").strip().lower() in ("1", "true", "yes")

# Upstream endpoints. Derived from the web/API bases; override only for unusual deployments.
BUGASURA_OAUTH_AUTHORIZE_URL = os.getenv("BUGASURA_OAUTH_AUTHORIZE_URL", "").strip() or f"{WEB_BASE_URL}oauth/authorize"
BUGASURA_OAUTH_TOKEN_URL = os.getenv("BUGASURA_OAUTH_TOKEN_URL", "").strip() or f"{API_BASE}/v1/oauth/token"
BUGASURA_OAUTH_INTROSPECT_URL = os.getenv("BUGASURA_OAUTH_INTROSPECT_URL", "").strip() or f"{API_BASE}/v1/oauth/introspect"
BUGASURA_OAUTH_REVOKE_URL = os.getenv("BUGASURA_OAUTH_REVOKE_URL", "").strip() or f"{API_BASE}/v1/oauth/revoke"


# Logo shown on the OAuth consent page (and offered to MCP clients as the server icon).
MCP_SERVER_ICON_URL = os.getenv("MCP_SERVER_ICON_URL", "").strip() or f"{WEB_BASE_URL}assets/img/bugasura/bugasura_icon300.png"


def oauth_configured() -> bool:
    """True when the values required to run the OAuth front door are all present."""
    return bool(MCP_PUBLIC_BASE_URL and BUGASURA_OAUTH_CLIENT_ID and BUGASURA_OAUTH_CLIENT_SECRET)

logger.info(f"MCP Server: {MCP_SERVER_NAME}")
