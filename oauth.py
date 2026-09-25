"""OAuth 2.0 front door: FastMCP's OAuthProxy in front of Bugasura's authorization server.

MCP clients (Claude Desktop, claude.ai, Claude Code, Cursor, VS Code, Antigravity, ChatGPT/Codex,
Inspector) register themselves with this server via Dynamic Client Registration and run PKCE
against it. The proxy holds Bugasura's single pre-registered client and does the upstream code
exchange at ``<MCP_PUBLIC_BASE_URL>/auth/callback``. Bugasura's own token is never handed to the
MCP client; the proxy issues its own JWT and swaps it for the upstream token on every request.
"""
import hashlib
import time
from typing import Any, Optional

from urllib.parse import urlencode

import httpx
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse
from fastmcp.server.auth import AccessToken, OAuthProxy, TokenVerifier
from fastmcp.server.auth.redirect_validation import validate_redirect_uri
from mcp.server.auth.provider import RegistrationError
from mcp.shared.auth import OAuthClientInformationFull

from client import ACCESS_TOKEN_PREFIX
from config import (
    BUGASURA_OAUTH_AUTHORIZE_URL, BUGASURA_OAUTH_CLIENT_ID, BUGASURA_OAUTH_CLIENT_SECRET,
    BUGASURA_OAUTH_INTROSPECT_URL, BUGASURA_OAUTH_REVOKE_URL, BUGASURA_OAUTH_TOKEN_URL,
    MCP_JWT_SIGNING_KEY, MCP_PUBLIC_BASE_URL, OAUTH_ALLOWED_REDIRECT_URIS,
    OAUTH_INTROSPECTION_CACHE_TTL, OAUTH_REQUIRE_CONSENT, OAUTH_STORAGE_PATH, WEB_BASE_URL,
    logger, oauth_configured,
)


# Redirect URIs MCP clients may register via DCR (fnmatch patterns; '*' also matches '/').
# FastMCP's consent screen is the real guard against a rogue client; this list is belt and braces.
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
    "vscode://*",
    "vscode-insiders://*",
    # Cursor and Windsurf desktop apps (app-scheme callbacks)
    "cursor://*",
    "windsurf://*",
    # Google Antigravity
    "https://antigravity.google/oauth-callback",
    # ChatGPT connectors (also what Codex registers through); the last segment is a per-connector ID
    "https://chatgpt.com/connector/oauth/*",
]


class BugasuraTokenVerifier(TokenVerifier):
    """
    Validate a Bugasura access token with RFC 7662 introspection (client_secret_post).

    OAuthProxy calls this on every MCP request, so positive results are cached for a short
    time (never past the token's own expiry). The returned AccessToken.token is the upstream
    Bugasura token, which is what tools read back through get_access_token().
    """

    def __init__(self, *, introspection_url: str, client_id: str, client_secret: str,
                 cache_ttl: int = 60, timeout: float = 10.0):
        super().__init__(base_url=MCP_PUBLIC_BASE_URL)
        self._url = introspection_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._ttl = max(0, int(cache_ttl))
        self._timeout = timeout
        self._cache: dict[str, tuple[float, AccessToken]] = {}

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        if not token.startswith(ACCESS_TOKEN_PREFIX):
            return None
        key = self._key(token)
        now = time.monotonic()
        hit = self._cache.get(key)
        if hit and hit[0] > now and (hit[1].expires_at is None or hit[1].expires_at > time.time()):
            return hit[1]

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as http:
                resp = await http.post(
                    self._url,
                    data={"token": token, "token_type_hint": "access_token",
                          "client_id": self._client_id, "client_secret": self._client_secret},
                    headers={"Accept": "application/json"},
                )
        except httpx.HTTPError as e:
            logger.warning(f"OAuth introspection request failed: {e}")
            self._cache.pop(key, None)
            return None
        if resp.status_code != 200:
            logger.debug(f"OAuth introspection HTTP {resp.status_code}")
            self._cache.pop(key, None)
            return None

        try:
            data: dict[str, Any] = resp.json()
        except ValueError:
            self._cache.pop(key, None)
            return None
        if not isinstance(data, dict) or not data.get("active"):
            self._cache.pop(key, None)
            return None
        exp = data.get("exp")
        try:
            exp = int(exp) if exp is not None else None
        except (TypeError, ValueError):
            exp = None
        if exp is not None and exp < time.time():
            self._cache.pop(key, None)
            return None

        scope = data.get("scope") or ""
        scopes = scope.split() if isinstance(scope, str) else list(scope)
        access = AccessToken(
            token=token,
            client_id=str(data.get("client_id") or self._client_id),
            scopes=scopes,
            expires_at=exp,
            claims={"sub": data.get("sub"), "email": data.get("email"), "name": data.get("name")},
        )
        ttl = self._ttl if exp is None else min(self._ttl, max(0, exp - int(time.time())))
        self._cache[key] = (now + ttl, access)
        if len(self._cache) > 5000:
            self._cache = {k: v for k, v in self._cache.items() if v[0] > now}
        return access


class BugasuraOAuthProxy(OAuthProxy):
    """
    OAuthProxy that enforces the redirect-URI allow-list at registration.

    FastMCP 2.14 treats `allowed_client_redirect_uris` as a soft check: a callback that
    misses every pattern still passes because the client registered it for itself. With
    the consent interstitial off, that would let a rogue client register its own callback
    and receive a user's Bugasura session. Rejecting such registrations up front closes it.

    It also gives clients that register without a `scope` (ChatGPT, Antigravity) the server's
    valid scopes. FastMCP otherwise stores them with an empty scope, and their authorize request
    for `scope=api` then fails with invalid_scope.
    """

    def _default_client_scope(self) -> str:
        return " ".join(self.client_registration_options.valid_scopes or [])

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        client = await super().get_client(client_id)
        # Clients stored before the default above existed still have an empty scope
        if client is not None and not client.scope:
            client.scope = self._default_client_scope()
        return client

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if not client_info.scope:
            client_info.scope = self._default_client_scope()
        patterns = self._allowed_client_redirect_uris
        for uri in client_info.redirect_uris or []:
            if not validate_redirect_uri(uri, patterns):
                logger.warning(f"Rejected client registration with redirect_uri {uri} "
                               f"(client_name={getattr(client_info, 'client_name', None)!r})")
                raise RegistrationError(
                    error="invalid_redirect_uri",
                    error_description=(f"redirect_uri {uri} is not allowed by this server. "
                                       "Set OAUTH_ALLOWED_REDIRECT_URIS on the server to permit it."),
                )
        await super().register_client(client_info)

    async def _handle_idp_callback(self, request: Request) -> HTMLResponse | RedirectResponse:
        """
        When Bugasura answers with an OAuth error (the user clicked Deny, or the request was
        rejected), pass it to the MCP client on its own redirect URI with its original state,
        as RFC 6749 §4.1.2.1 requires; the client then shows its own "declined" state. FastMCP
        would otherwise stop here and render a generic page. Successful callbacks are unchanged.
        A callback whose transaction is unknown (expired or replayed) has no client to return
        to, so the browser is sent to the Bugasura web app's error page.
        """
        error = request.query_params.get("error")
        if not error:
            return await super()._handle_idp_callback(request)

        description = request.query_params.get("error_description") or ""
        txn_id = request.query_params.get("state") or ""
        transaction = await self._transaction_store.get(key=txn_id) if txn_id else None
        logger.info(f"Upstream OAuth error forwarded to client: {error} ({description or 'no description'})")

        if transaction is None:
            return RedirectResponse(url=f"{WEB_BASE_URL}oauth/error", status_code=302)

        await self._transaction_store.delete(key=txn_id)
        params = {"error": error}
        if description:
            params["error_description"] = description
        if transaction.client_state:
            params["state"] = transaction.client_state
        separator = "&" if "?" in transaction.client_redirect_uri else "?"
        return RedirectResponse(url=f"{transaction.client_redirect_uri}{separator}{urlencode(params)}", status_code=302)


def _build_client_storage():
    """Persistent, encrypted OAuth state when OAUTH_STORAGE_PATH is set; in-memory otherwise."""
    if not OAUTH_STORAGE_PATH:
        from key_value.aio.stores.memory import MemoryStore
        logger.warning("OAUTH_STORAGE_PATH is not set: OAuth sessions live in memory and every "
                       "MCP client must sign in again after a restart")
        return MemoryStore()

    from cryptography.fernet import Fernet
    from fastmcp.server.auth.jwt_issuer import derive_jwt_key
    from key_value.aio.stores.disk import DiskStore
    from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

    # OAuthProxy only encrypts the store it creates itself, so wrap ours explicitly.
    material = MCP_JWT_SIGNING_KEY or BUGASURA_OAUTH_CLIENT_SECRET
    fernet_key = derive_jwt_key(high_entropy_material=material,
                                salt="bugasura-mcp-oauth-storage-encryption")
    return FernetEncryptionWrapper(key_value=DiskStore(directory=OAUTH_STORAGE_PATH),
                                   fernet=Fernet(fernet_key))


def build_auth_provider() -> Optional[OAuthProxy]:
    """Return the configured OAuthProxy, or None when the OAuth env vars are absent (STDIO/dev)."""
    if not oauth_configured():
        return None

    verifier = BugasuraTokenVerifier(
        introspection_url=BUGASURA_OAUTH_INTROSPECT_URL,
        client_id=BUGASURA_OAUTH_CLIENT_ID,
        client_secret=BUGASURA_OAUTH_CLIENT_SECRET,
        cache_ttl=OAUTH_INTROSPECTION_CACHE_TTL,
    )

    allowed = list(DEFAULT_ALLOWED_REDIRECT_URIS)
    if OAUTH_ALLOWED_REDIRECT_URIS:
        allowed += [p.strip() for p in OAUTH_ALLOWED_REDIRECT_URIS.split(",") if p.strip()]

    proxy = BugasuraOAuthProxy(
        upstream_authorization_endpoint=BUGASURA_OAUTH_AUTHORIZE_URL,
        upstream_token_endpoint=BUGASURA_OAUTH_TOKEN_URL,
        upstream_revocation_endpoint=BUGASURA_OAUTH_REVOKE_URL,
        upstream_client_id=BUGASURA_OAUTH_CLIENT_ID,
        upstream_client_secret=BUGASURA_OAUTH_CLIENT_SECRET,
        token_verifier=verifier,
        base_url=MCP_PUBLIC_BASE_URL,
        redirect_path="/auth/callback",
        allowed_client_redirect_uris=allowed,
        valid_scopes=["api"],
        forward_pkce=True,
        token_endpoint_auth_method="client_secret_post",
        client_storage=_build_client_storage(),
        jwt_signing_key=MCP_JWT_SIGNING_KEY or None,
        # Off by default so users only see Bugasura's own login + consent. The redirect-URI
        # allow-list above is then the only check on which MCP client receives the session.
        require_authorization_consent=OAUTH_REQUIRE_CONSENT,
        fallback_access_token_expiry_seconds=3600,
    )
    logger.info(f"OAuth sign-in enabled: issuer={MCP_PUBLIC_BASE_URL} "
                f"authorize={BUGASURA_OAUTH_AUTHORIZE_URL} token={BUGASURA_OAUTH_TOKEN_URL}")
    return proxy
