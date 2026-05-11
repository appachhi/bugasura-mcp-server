"""API key resolution, validation, and user-context caching."""
import hashlib
import time as _time
from typing import Any, Optional

from fastmcp.server.dependencies import get_http_headers

from client import logger, make_api_request
from config import BUGASURA_API_KEY


_USER_CONTEXT_TTL_SECONDS = 300  # 5 minutes
_user_context_cache: dict = {}


def _extract_key_from_http_headers() -> str:
    """
    Pull the API key from the active HTTP request's headers, if any.

    Returns empty string in STDIO mode (no active request) or when neither
    supported header is present. `get_http_headers()` returns lowercase keys
    and never raises.

    Headers checked, in order:
      1. `X-Bugasura-API-Key: <key>` — explicit, won't collide with proxies.
      2. `Authorization: Basic <key>` — token after `Basic ` is treated as
         the raw API key, matching the Bugasura backend's own convention
         (RequestHandler.php splits on whitespace, looks up the second token
         verbatim with no base64 decoding). This means the same header that
         works against `api.bugasura.io` works against the MCP server.
    """
    try:
        headers = get_http_headers()
    except Exception as e:
        logger.debug(f"_get_api_key: get_http_headers raised unexpectedly: {e}")
        return ""

    custom = headers.get("x-bugasura-api-key", "").strip()
    if custom:
        return custom

    auth = headers.get("authorization", "").strip()
    if auth.lower().startswith("basic "):
        token = auth[6:].strip()
        if token:
            return token

    return ""


def _get_api_key(api_key: str = "") -> str:
    """
    Resolve the API key in priority order:

      1. Tool-call argument (`api_key` parameter passed by the MCP client at
         call-time — typically a key the AI assistant collected from the user
         mid-conversation, or a per-tool override).
      2. HTTP request header `X-Bugasura-API-Key` (streamable-HTTP transport
         only — STDIO has no active HTTP request, so this silently no-ops).
      3. HTTP `Authorization: Basic <key>` header (streamable-HTTP only).
         `<key>` is the raw API key — same format the Bugasura backend
         expects, no base64 decoding.
      4. `BUGASURA_API_KEY` environment variable. This covers all configured
         sources: the `env` block in the MCP client config (Claude Desktop /
         Cursor / Claude Code STDIO), `EnvironmentFile=` on systemd units,
         the `.env` file loaded by python-dotenv, or a plain shell export.
      5. Empty string — caller (`validate_api_key`) converts this to a
         `status: 'api_key_required'` response that instructs the assistant
         to ask the user.
    """
    if api_key and api_key.strip():
        logger.debug("_get_api_key: using key from tool-call argument")
        return api_key.strip()

    header_key = _extract_key_from_http_headers()
    if header_key:
        logger.debug("_get_api_key: using key from HTTP request header")
        return header_key

    env_key = BUGASURA_API_KEY.strip()
    if env_key:
        logger.debug("_get_api_key: using key from BUGASURA_API_KEY env var")
    else:
        logger.debug("_get_api_key: no key found in argument, header, or env — caller will prompt user")
    return env_key


async def validate_api_key(api_key: str) -> dict:
    """
    Validate API key by making a test request to the Bugasura API.

    This function checks if the provided API key is valid by attempting
    to fetch the user's teams. This is a lightweight operation that confirms
    authentication without retrieving large amounts of data.

    Args:
        api_key: User's Bugasura API key to validate

    Returns:
        dict: Validation result
            Success: {'valid': True, 'status': 'OK'}
            Failure: {'valid': False, 'status': 'failed', 'error': 'error message', ...}

    Note:
        This function is called by all tools except list_teams to ensure
        API key is valid before executing operations.
    """
    # Resolve API key: use provided value or fall back to environment variable
    api_key = _get_api_key(api_key)

    # Validate API key format
    if not api_key or not isinstance(api_key, str) or len(api_key.strip()) == 0:
        return {
            'valid': False,
            'status': 'api_key_required',
            'error': 'No API key found. Please provide your Bugasura API key.',
            'error_type': 'ApiKeyMissing',
            'action': 'Please ask the user for their Bugasura API key. Once they provide it, retry the same tool call with the api_key parameter.',
            'help': 'To get your API key:\n'
                   '1. Go to https://bugasura.io\n'
                   '2. Navigate to User Settings → API Key\n'
                   '3. Copy your API key and provide it here'
        }

    # Check for placeholder/template API keys
    placeholder_patterns = ['$BUGASURA_API_KEY', '${BUGASURA_API_KEY}', '<api_key>',
                           'YOUR_API_KEY', 'BUGASURA_API_KEY', 'your-api-key-here']
    if any(pattern in api_key for pattern in placeholder_patterns):
        return {
            'valid': False,
            'status': 'failed',
            'error': 'Please provide your Bugasura API key.',
            'error_type': 'ValidationError',
            'detected_placeholder': api_key,
            'help': 'To get your API key:\n'
                   '1. Go to https://bugasura.io\n'
                   '2. Navigate to User Settings → API Key\n'
                   '3. Copy your API key and use it instead of the placeholder'
        }

    # Make a lightweight API call to validate the key
    # We use the teams endpoint as it's fast and confirms authentication
    response = await make_api_request('GET', '/v1/teams/getApps', api_key)

    # Handle case where API might return a list instead of dict
    if isinstance(response, list):
        return {
            'valid': False,
            'status': 'failed',
            'error': 'Unexpected API response format (received list instead of dict)',
            'error_type': 'ResponseFormatError',
            'response_preview': str(response[:2]) if len(response) > 0 else 'Empty list'
        }

    # Check if the API call was successful
    if response.get('status') == 'OK':
        return {'valid': True, 'status': 'OK', 'resolved_key': api_key}
    else:
        # Return the error details from the API
        return {
            'valid': False,
            'status': 'failed',
            'error': response.get('error', 'Invalid API key or authentication failed'),
            'error_type': response.get('error_type', 'AuthenticationError'),
            'message': 'Please check your API key and try again. Get your API key from Bugasura → User Settings → API Key'
        }


def _invalidate_user_context_cache(api_key: Optional[str] = None) -> None:
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


async def _fetch_user_context(api_key: str) -> dict:
    """
    Internal helper function to fetch user context.
    This is NOT an MCP tool, so it can be called from other Python functions.
    Results are cached per-api_key for _USER_CONTEXT_TTL_SECONDS.
    """
    key_hash = hashlib.sha256(api_key.encode('utf-8')).hexdigest()
    now = _time.monotonic()
    cached = _user_context_cache.get(key_hash)
    if cached and cached[0] > now:
        logger.debug("_fetch_user_context: cache hit")
        return cached[1]

    # Call Bugasura API to fetch user's teams and projects
    full_response = await make_api_request('GET', '/v1/teams/getApps', api_key)

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

    # Extract and structure the response
    teams_data = full_response.get('userTeamsProjectsDetails', [])

    structured_teams = []
    for team in teams_data:
        team_info = {
            'team_id': team.get('team_id'),
            'team_name': team.get('team_name'),
            'role': 'Admin' if team.get('is_admin') else 'Member',
            'projects': []
        }

        # Add project details
        # Backend returns 'appsDetails' not 'projectsDetails'
        for project in team.get('appsDetails', []):
            team_info['projects'].append({
                'project_id': project.get('app_id'),
                'project_name': project.get('app_name'),
                'platform': project.get('platform', ''),
                'platform_type': project.get('platform_type', '')
            })

        structured_teams.append(team_info)

    result = {
        'status': 'OK',
        'teams': structured_teams,
        'message': 'Use team_id and project_id from this response in other tool calls'
    }
    _user_context_cache[key_hash] = (now + _USER_CONTEXT_TTL_SECONDS, result)
    return result
