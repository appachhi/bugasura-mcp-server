"""OAuth 2.0 front door: FastMCP's OAuthProxy in front of Bugasura's authorization server.

MCP clients (Claude Desktop, claude.ai, Claude Code, Cursor, VS Code, Antigravity, ChatGPT/Codex,
Inspector) register themselves with this server via Dynamic Client Registration or a Client ID
Metadata Document (CIMD) and run PKCE against it. The proxy holds Bugasura's single pre-registered
client and does the upstream code exchange at ``<MCP_PUBLIC_BASE_URL>/auth/callback``. Bugasura's own token is never handed to the
MCP client; the proxy issues its own JWT and swaps it for the upstream token on every request.
"""
import hashlib
import time
from typing import Any, Optional

import httpx
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse
from fastmcp.server.auth import AccessToken, OAuthProxy, TokenVerifier
from mcp.server.auth.provider import RegistrationError
from mcp.shared.auth import OAuthClientInformationFull

from client import ACCESS_TOKEN_PREFIX
from config import (
    BUGASURA_OAUTH_AUTHORIZE_URL, BUGASURA_OAUTH_CLIENT_ID, BUGASURA_OAUTH_CLIENT_SECRET,
    BUGASURA_OAUTH_INTROSPECT_URL, BUGASURA_OAUTH_REVOKE_URL, BUGASURA_OAUTH_TOKEN_URL,
    DEFAULT_ALLOWED_REDIRECT_URIS, MCP_JWT_SIGNING_KEY, MCP_PUBLIC_BASE_URL,
    OAUTH_ALLOWED_REDIRECT_URIS, OAUTH_FALLBACK_TOKEN_EXPIRY_SECONDS,
    OAUTH_INTROSPECTION_CACHE_MAX_ENTRIES, OAUTH_INTROSPECTION_CACHE_TTL,
    OAUTH_INTROSPECTION_TIMEOUT_SECONDS, OAUTH_REQUIRE_CONSENT, OAUTH_STORAGE_PATH, WEB_BASE_URL,
    logger, oauth_configured,
)


class BugasuraTokenVerifier(TokenVerifier):
    """
    Validate a Bugasura access token with RFC 7662 introspection (client_secret_post).

    OAuthProxy calls this on every MCP request, so positive results are cached for a short
    time (never past the token's own expiry). The returned AccessToken.token is the upstream
    Bugasura token, which is what tools read back through get_access_token().
    """

    def __init__(self, *, introspection_url: str, client_id: str, client_secret: str,
                 cache_ttl: int = OAUTH_INTROSPECTION_CACHE_TTL,
                 timeout: float = OAUTH_INTROSPECTION_TIMEOUT_SECONDS):
        # Every Bugasura token carries `api`; requiring it makes FastMCP challenge with scope="api"
        # on 401 and answer a token without it with 403 insufficient_scope.
        super().__init__(base_url=MCP_PUBLIC_BASE_URL, required_scopes=["api"])
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
        if len(self._cache) > OAUTH_INTROSPECTION_CACHE_MAX_ENTRIES:
            self._cache = {k: v for k, v in self._cache.items() if v[0] > now}
        return access


class BugasuraOAuthProxy(OAuthProxy):
    """
    OAuthProxy with two Bugasura touches. FastMCP 4 already enforces the redirect-URI
    allow-list, fills a default scope and forwards upstream errors to the client.
    """

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        # Log rejected callbacks so a new MCP client's URI can be added to the allow-list
        try:
            await super().register_client(client_info)
        except RegistrationError:
            logger.warning(f"Rejected client registration with redirect_uris {client_info.redirect_uris} "
                           f"(client_name={getattr(client_info, 'client_name', None)!r})")
            raise

    async def _handle_idp_callback(self, request: Request) -> HTMLResponse | RedirectResponse:
        """
        An upstream error whose transaction is unknown (expired or replayed) has no client to
        return to, so send the browser to the Bugasura web app's error page instead of
        FastMCP's generic one. Everything else, including forwarding errors to a known
        client with its state and `iss`, is FastMCP's own handling.
        """
        error = request.query_params.get("error")
        txn_id = request.query_params.get("state") or ""
        if error and (not txn_id or await self._transaction_store.get(key=txn_id) is None):
            logger.info(f"Upstream OAuth error with unknown transaction: {error}")
            return RedirectResponse(url=f"{WEB_BASE_URL}oauth/error", status_code=302)
        if error:
            logger.info(f"Upstream OAuth error forwarded to client: {error} "
                        f"({request.query_params.get('error_description') or 'no description'})")
        return await super()._handle_idp_callback(request)


def _build_client_storage():
    """Persistent, encrypted OAuth state when OAUTH_STORAGE_PATH is set; in-memory otherwise."""
    if not OAUTH_STORAGE_PATH:
        from key_value.aio.stores.memory import MemoryStore
        logger.warning("OAUTH_STORAGE_PATH is not set: OAuth sessions live in memory and every "
                       "MCP client must sign in again after a restart")
        return MemoryStore()

    from pathlib import Path

    from cryptography.fernet import Fernet
    from fastmcp.server.auth.jwt_issuer import derive_jwt_key
    from key_value.aio.stores.filetree import (
        FileTreeStore, FileTreeV1CollectionSanitizationStrategy, FileTreeV1KeySanitizationStrategy,
    )
    from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

    # OAuthProxy only encrypts the store it creates itself, so wrap ours explicitly.
    material = MCP_JWT_SIGNING_KEY or BUGASURA_OAUTH_CLIENT_SECRET
    fernet_key = derive_jwt_key(high_entropy_material=material,
                                salt="bugasura-mcp-oauth-storage-encryption")
    # One JSON file per entry (FastMCP's own default); replaces the pickle-based DiskStore (CVE-2025-69872)
    storage_dir = Path(OAUTH_STORAGE_PATH)
    storage_dir.mkdir(parents=True, exist_ok=True)
    file_store = FileTreeStore(
        data_directory=storage_dir,
        key_sanitization_strategy=FileTreeV1KeySanitizationStrategy(storage_dir),
        collection_sanitization_strategy=FileTreeV1CollectionSanitizationStrategy(storage_dir),
    )
    # An entry that no longer decrypts (key changed) reads as missing, so that client signs in again
    return FernetEncryptionWrapper(key_value=file_store, fernet=Fernet(fernet_key),
                                   raise_on_decryption_error=False)


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
        # Pinned so the metadata issuer and the RFC 9207 `iss` on redirects are the same string
        issuer_url=MCP_PUBLIC_BASE_URL,
        redirect_path="/auth/callback",
        allowed_client_redirect_uris=allowed,
        valid_scopes=["api"],
        forward_pkce=True,
        token_endpoint_auth_method="client_secret_post",
        client_storage=_build_client_storage(),
        jwt_signing_key=MCP_JWT_SIGNING_KEY or None,
        # Off by default ("external"): users only see Bugasura's own login + consent. The redirect-URI
        # allow-list above is then the only check on which MCP client receives the session.
        require_authorization_consent=True if OAUTH_REQUIRE_CONSENT else "external",
        fallback_access_token_expiry_seconds=OAUTH_FALLBACK_TOKEN_EXPIRY_SECONDS,
    )
    logger.info(f"OAuth sign-in enabled: issuer={MCP_PUBLIC_BASE_URL} "
                f"authorize={BUGASURA_OAUTH_AUTHORIZE_URL} token={BUGASURA_OAUTH_TOKEN_URL}")
    return proxy
