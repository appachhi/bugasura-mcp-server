"""Credential resolution, validation, and user-context caching."""
import hashlib
import time as _time
from typing import Optional

from fastmcp.server.dependencies import get_access_token

from client import auth_required_payload, display_team_name, in_http_request, logger, make_api_request
from config import BUGASURA_API_KEY, USER_CONTEXT_TTL_SECONDS


_user_context_cache: dict = {}


def get_api_key(api_key: str = "") -> str:
    """
    Resolve the credential used for the upstream Bugasura call.

      1. Streamable-HTTP: the OAuth access token FastMCP already validated for this
         request (`get_access_token().token`, a `bgs_at_…` string). The MCP client
         obtained it by signing in to Bugasura in the browser; it never reaches the
         assistant. There is no fallback to the env var over HTTP.
      2. STDIO: `BUGASURA_API_KEY` from the MCP client's `env` block, the `.env` file,
         or the shell. STDIO has no browser hand-off, so the legacy key stays for it.
      3. Empty string — the caller (`validate_api_key`) turns this into a
         `status: 'api_key_required'` response.

    The `api_key` argument is ignored. It survives so the 100+ call sites keep their
    `api_key = get_api_key(api_key)` shape; tools no longer expose an api_key input.
    """
    if in_http_request():
        token = get_access_token()
        if token and token.token:
            logger.debug("get_api_key: using OAuth access token from the request")
            return token.token
        logger.debug("get_api_key: HTTP request without a validated access token")
        return ""

    env_key = BUGASURA_API_KEY.strip()
    if env_key:
        logger.debug("get_api_key: using key from BUGASURA_API_KEY env var (STDIO)")
    else:
        logger.debug("get_api_key: no credential (STDIO without BUGASURA_API_KEY)")
    return env_key


def current_user_id() -> str:
    """The signed-in Bugasura user id (introspection `sub`) for this HTTP request; "" under STDIO."""
    if not in_http_request():
        return ""
    token = get_access_token()
    return str((token.claims or {}).get("sub") or "") if token else ""


async def validate_api_key(api_key: str) -> dict:
    """
    Validate the resolved credential. Over HTTP the token is already verified by oauth.py;
    under STDIO the env key is checked with a lightweight call to the Bugasura API.

    Args:
        api_key: Ignored; the credential is re-resolved with `get_api_key()`.

    Returns:
        dict: Validation result
            Success: {'valid': True, 'status': 'OK'}
            Failure: {'valid': False, 'status': 'api_key_required' | 'failed', ...}
    """
    api_key = get_api_key(api_key)

    if not api_key or not isinstance(api_key, str) or len(api_key.strip()) == 0:
        return {'valid': False, **auth_required_payload()}

    # Over HTTP the token was already introspected by BugasuraTokenVerifier before the tool ran
    if in_http_request():
        return {'valid': True, 'status': 'OK', 'resolved_key': api_key}

    # STDIO: make a lightweight API call to validate the credential
    # /v1/teams/get scans only the teams table; source=MCP is required, or the
    # endpoint rejects the call for a missing team_id.
    response = await make_api_request('GET', '/v1/teams/get', api_key, params={'source': 'MCP'})

    # Handle case where API might return a list instead of dict
    if isinstance(response, list):
        return {
            'valid': False,
            'status': 'failed',
            'error': 'Unexpected API response format (received list instead of dict)',
            'error_type': 'ResponseFormatError',
            'response_preview': str(response[:2]) if len(response) > 0 else 'Empty list'
        }

    if response.get('status') == 'OK':
        return {'valid': True, 'status': 'OK', 'resolved_key': api_key}
    if response.get('status') == 'api_key_required':
        return {'valid': False, **response}
    return {
        'valid': False,
        'status': 'failed',
        'error': response.get('error', 'Authentication failed'),
        'error_type': response.get('error_type', 'AuthenticationError'),
        'message': ('Sign in to Bugasura again from your MCP client (HTTP), or check '
                    'BUGASURA_API_KEY (STDIO).')
    }


def invalidate_user_context_cache(api_key: Optional[str] = None) -> None:
    """
    Drop cached user-context entries. Called after write operations that can
    change team/project structure (create/update/delete project, add/remove
    team members). If api_key is None, flushes the entire cache.
    """
    if api_key is None:
        _user_context_cache.clear()
        return
    key_hash = hashlib.sha256(api_key.encode('utf-8')).hexdigest()
    _user_context_cache.pop(key_hash, None)


async def fetch_user_context(api_key: str) -> dict:
    """
    Internal helper function to fetch user context.
    This is NOT an MCP tool, so it can be called from other Python functions.
    Results are cached per credential for USER_CONTEXT_TTL_SECONDS. OAuth access
    tokens rotate hourly, so a stale entry costs at most one extra pair of calls.
    """
    key_hash = hashlib.sha256(api_key.encode('utf-8')).hexdigest()
    now = _time.monotonic()
    cached = _user_context_cache.get(key_hash)
    if cached and cached[0] > now:
        logger.debug("fetch_user_context: cache hit")
        return cached[1]

    # Teams come from /v1/teams/get, which is driven off the teams table. The
    # older /teams/getApps is driven off the apps table, so it silently drops any
    # team that has no active project. Filters match bugasura_list_teams.
    full_response = await make_api_request('GET', '/v1/teams/get', api_key, params={
        'source': 'MCP',
        'isActive': 1,
        'isOnlyVerifiedTeams': 1,
        'isGetSampleTeams': 1,
    })

    # Handle case where API might return a list instead of dict
    if isinstance(full_response, list):
        return {
            'status': 'failed',
            'error': 'Unexpected API response format (received list instead of dict)',
            'error_type': 'ResponseFormatError',
            'response_preview': str(full_response[:2]) if len(full_response) > 0 else 'Empty list'
        }

    # Check if API call was successful
    if full_response.get('status') != 'OK':
        return full_response

    # Projects still come from getApps, which nests them under each team.
    apps_response = await make_api_request('GET', '/v1/teams/getApps', api_key)

    if isinstance(apps_response, list):
        return {
            'status': 'failed',
            'error': 'Unexpected API response format (received list instead of dict)',
            'error_type': 'ResponseFormatError',
            'response_preview': str(apps_response[:2]) if len(apps_response) > 0 else 'Empty list'
        }

    if apps_response.get('status') != 'OK':
        return apps_response

    # Key by str() — the two endpoints need not agree on int vs str team_id.
    projects_by_team = {
        str(team.get('team_id')): [{
            'project_id': project.get('app_id'),
            'project_name': project.get('app_name'),
            'platform': project.get('platform', ''),
            'platform_type': project.get('platform_type', '')
        } for project in team.get('appsDetails', [])]
        for team in apps_response.get('userTeamsProjectsDetails', [])
    }

    structured_teams = [{
        'team_id': team.get('team_id'),
        'team_name': display_team_name(team),
        'role': 'Admin' if team.get('is_admin') else 'Member',
        'is_expired': team.get('is_expired'),
        'projects': projects_by_team.get(str(team.get('team_id')), [])
    } for team in full_response.get('teamDetails', [])]

    result = {
        'status': 'OK',
        'teams': structured_teams,
        'message': 'Use team_id and project_id from this response in other tool calls'
    }
    _user_context_cache[key_hash] = (now + USER_CONTEXT_TTL_SECONDS, result)
    return result
