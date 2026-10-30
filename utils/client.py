"""Async HTTP client for the Bugasura API, plus the auth envelope and ID helpers."""
import json, httpx
from typing import Any, Optional

from fastmcp.server.dependencies import get_http_request

from config.config import API_BASE, UPLOAD_TIMEOUT_SECONDS, logger


# Bugasura-issued OAuth access tokens carry this prefix; anything else is a legacy API key.
ACCESS_TOKEN_PREFIX = "bgs_at_"


def in_http_request() -> bool:
    """True while serving a streamable-HTTP request, False under STDIO."""
    try:
        get_http_request()
        return True
    except RuntimeError:
        return False


def auth_required_payload(reason: str = "missing") -> dict:
    """
    The `api_key_required` envelope. The status value is kept so callers that branch on it
    keep working, but the guidance no longer asks the assistant to collect a key: over HTTP
    the user reconnects the OAuth session, under STDIO they set BUGASURA_API_KEY.
    """
    if in_http_request():
        expired = reason == "expired"
        return {
            'status': 'api_key_required',
            'error': ('Your Bugasura session has expired or was revoked.' if expired
                      else 'Not signed in to Bugasura.'),
            'error_type': 'AuthenticationError' if expired else 'AuthenticationRequired',
            'action': ('Tell the user to sign in to Bugasura again from their MCP client '
                       '(Claude Code: /mcp -> Bugasura -> Authenticate; Claude Desktop / claude.ai: '
                       'Settings -> Connectors -> Bugasura -> Reconnect). Do not ask for an API key; '
                       'tools no longer accept one.'),
        }
    return {
        'status': 'api_key_required',
        'error': 'BUGASURA_API_KEY is not set.',
        'error_type': 'ApiKeyMissing',
        'action': ('Tell the user to set BUGASURA_API_KEY in the MCP server "env" block '
                   '(Bugasura -> User Settings -> API Key) and restart the client. '
                   'Do not ask for the key in chat; tools no longer accept one.'),
    }


# Lazy-initialized shared AsyncClient for connection pooling (one per event loop).
_http_client: Optional[httpx.AsyncClient] = None


def validate_id(value: Any, param_name: str) -> int:
    """
    Validate and convert ID parameters to integers.

    Ensures all ID parameters (team_id, project_id, etc.) are valid integers.
    This catches type errors early and provides clear error messages.

    Args:
        value: The value to validate (should be int or convertible to int)
        param_name: Name of the parameter (for error messages)

    Returns:
        int: Validated integer value

    Raises:
        ValueError: If value cannot be converted to integer

    Example:
        team_id = validate_id(team_id, "team_id")
    """
    try:
        # Convert to int if it's not already
        # This handles string numbers like "123" -> 123
        int_value = int(value)

        # Ensure the value is positive (IDs are always positive)
        if int_value <= 0:
            raise ValueError(f"{param_name} must be a positive integer, got {int_value}")

        return int_value
    except (ValueError, TypeError):
        raise ValueError(f"Invalid {param_name}: expected integer, got {type(value).__name__} ({value})")


def _prepare_post_params(params: dict) -> dict:
    """
    Prepare parameters for POST requests by converting IDs to strings.

    Bugasura API requires all IDs in POST requests to be strings.
    This function handles the conversion consistently.

    Args:
        params: Dictionary of parameters with integer IDs

    Returns:
        dict: Parameters with IDs converted to strings

    Example:
        payload = _prepare_post_params({
            "team_id": 123,
            "sprint_id": 456,
            "summary": "Bug title"
        })
        # Returns: {"team_id": "123", "sprint_id": "456", "summary": "Bug title"}
    """
    result = {}

    # IDs that need string conversion for POST requests
    id_fields = {
        'team_id',
        'project_id',
        'sprint_id',
        'app_id',
        'report_id',
        'testcase_id',
        'issue_key',
        'folder_id',
        'testrun_id'
    }

    for key, value in params.items():
        if value is None:
            # Skip None values
            continue
        elif key in id_fields:
            # Convert ID fields to strings
            result[key] = str(value)
        else:
            # Keep other values as-is
            result[key] = value

    return result


# Per-request timeout for posting files (`timeout=UPLOAD_TIMEOUT`); the connect timeout stays short
UPLOAD_TIMEOUT = httpx.Timeout(UPLOAD_TIMEOUT_SECONDS, connect=10.0)


def get_http_client() -> httpx.AsyncClient:
    """Return a process-shared AsyncClient with a sensible default timeout."""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0))
    return _http_client


async def make_api_request(method: str, endpoint: str, api_key: str, **kwargs) -> dict:
    """
    Make an authenticated HTTP request to the Bugasura API.

    This is the central function for all API communication. It handles:
    - URL construction
    - Authentication: Bearer for OAuth access tokens, Basic for legacy API keys
    - Parameter type conversion (POST requests require string IDs)
    - Comprehensive error handling with detailed diagnostics
    - Response parsing

    Args:
        method: HTTP method (GET, POST, PUT, DELETE)
        endpoint: API endpoint path (e.g., '/v1/issues/list')
        api_key: Credential for authentication — the OAuth access token resolved for
                 this request (HTTP) or the legacy BUGASURA_API_KEY (STDIO)
        **kwargs: Additional arguments passed to httpx.AsyncClient.request()
                  - params: Query parameters for GET (integers OK)
                  - data: Form data for POST (IDs auto-converted to strings)
                  - json: JSON body for POST (IDs auto-converted to strings)

    Returns:
        dict: Parsed JSON response from API on success, or detailed error dict on failure

    Success Response:
        Depends on the API endpoint (varies by operation)

    Error Response Formats:

        HTTP Error (4xx/5xx):
        {
            "error": "error message",
            "status": "failed",
            "error_type": "HTTPError",
            "status_code": 404,
            "method": "GET",
            "endpoint": "/v1/issues/get",
            "response_body": {...}  # Parsed JSON if available
            # OR
            "response_text": "..."  # Raw text if not JSON
        }

        Connection Error:
        {
            "error": "error message",
            "status": "failed",
            "error_type": "ConnectionError",
            "message": "Failed to connect to Bugasura API...",
            "api_base": "https://api.bugasura.io"
        }

        Timeout Error:
        {
            "error": "error message",
            "status": "failed",
            "error_type": "Timeout",
            "message": "Request to Bugasura API timed out...",
            "endpoint": "/v1/issues/add"
        }

        Other Errors:
        {
            "error": "error message",
            "status": "failed",
            "error_type": "RequestException",
            "message": "Unexpected error occurred..."
        }

    Error Handling Strategy:
        Tools should check response["status"] == "failed" to detect errors.
        The error_type field helps categorize the failure for appropriate handling.
        Detailed fields (status_code, response_body) assist with debugging.

    Example Usage:
        # Success
        result = make_api_request('GET', '/v1/teams/list', api_key)
        if result.get('status') != 'failed':
            teams = result['teams']

        # Error handling
        if result.get('status') == 'failed':
            if result.get('error_type') == 'HTTPError':
                print(f"HTTP {result['status_code']}: {result['error']}")
            elif result.get('error_type') == 'ConnectionError':
                print(f"Cannot reach API: {result['message']}")
    """
    # Construct full API URL by combining base URL with endpoint
    url = f"{API_BASE}{endpoint}"

    # No credential resolved: OAuth session missing (HTTP) or env var unset (STDIO)
    if not api_key or not api_key.strip():
        return auth_required_payload()

    # Log API request (without sensitive data)
    # SECURITY: Never log the full credential, only a hint for debugging
    api_key_hint = f"{api_key[:10]}..." if len(api_key) > 10 else "***"
    logger.info(f"API Request: {method} {endpoint}")
    logger.debug(f"API Key hint: {api_key_hint}")

    # Extract headers from kwargs if present, or create empty dict
    headers = kwargs.pop('headers', {})

    # OAuth access tokens (bgs_at_...) go as Bearer; a legacy API key keeps the backend's
    # raw "Basic <key>" convention (no base64).
    if api_key.startswith(ACCESS_TOKEN_PREFIX):
        headers['Authorization'] = f'Bearer {api_key}'
    else:
        headers['Authorization'] = f'Basic {api_key}'

    # Convert ID parameters to strings for POST requests
    # GET requests can use integers (auto-converted to strings in URL)
    if method.upper() in ('POST', 'PUT', 'PATCH'):
        # Handle form-encoded data (data parameter)
        if 'data' in kwargs and kwargs['data']:
            kwargs['data'] = _prepare_post_params(kwargs['data'])
            logger.debug(f"POST data prepared: {len(kwargs['data'])} fields")

        # Handle JSON data (json parameter)
        if 'json' in kwargs and kwargs['json']:
            kwargs['json'] = _prepare_post_params(kwargs['json'])
            logger.debug(f"JSON data prepared: {len(kwargs['json'])} fields")

    # Log request parameters (safe to log, no sensitive data)
    if 'params' in kwargs and kwargs['params']:
        # Filter out potentially sensitive params before logging
        safe_params = {k: v for k, v in kwargs['params'].items() if k not in ['api_key', 'password', 'token']}
        logger.debug(f"Request params: {safe_params}")

    client = get_http_client()
    try:
        # Make the HTTP request with constructed URL and headers
        logger.debug(f"Sending {method} request to {url}")
        try:
            response = await client.request(method, url, headers=headers, **kwargs)
        except (httpx.RemoteProtocolError, httpx.ReadError) as e:
            # A pooled connection the API already closed fails at once; only a GET is safe to send again
            if method.upper() != 'GET':
                raise
            logger.warning(f"Retrying {method} {endpoint} once after {type(e).__name__}: {e}")
            response = await client.request(method, url, headers=headers, **kwargs)

        # Log response status
        logger.info(f"API Response: {method} {endpoint} - Status {response.status_code}")

        # Raise exception for 4xx/5xx status codes
        response.raise_for_status()

        # Parse and return JSON response body
        json_response = response.json()

        # Log response type for debugging
        if isinstance(json_response, list):
            logger.warning(f"API returned a list instead of dict: {endpoint} - First element: {json_response[0] if json_response else 'empty'}")
        elif isinstance(json_response, dict):
            logger.debug(f"Response parsed successfully, status: {json_response.get('status', 'unknown')}")
        else:
            logger.warning(f"API returned unexpected type: {type(json_response)} for {endpoint}")

        return json_response

    except httpx.HTTPStatusError as e:
        status_code = e.response.status_code if e.response is not None else "unknown"
        logger.error(f"HTTP Error: {method} {endpoint} - Status {status_code}: {str(e)}")

        # The API sends 403 (older builds 401) when the user is not a member of the request's team; the session is fine then
        message = ''
        if status_code in (401, 403):
            try:
                message = str((e.response.json() or {}).get('message') or '')
            except (ValueError, AttributeError):
                pass
        if status_code == 401 and 'permission' not in message.lower():
            return auth_required_payload("expired")
        if 'permission' in message.lower():
            sent = {**(kwargs.get('params') or {}), **(kwargs.get('data') or {})}
            team_id = sent.get('team_id') or sent.get('teamId')
            logger.warning(f"{status_code} permission denied: {method} {endpoint} team_id={team_id}: {message}")
            return {
                "error": message,
                "status": "failed",
                "error_type": "PermissionDenied",
                "message": (f"The signed-in user is not a member of team {team_id}, or the project is not in it. "
                            "Check the team_id and project_id (bugasura_list_teams, bugasura_list_projects); "
                            "signing in again will not help."),
                "endpoint": endpoint,
            }

        # Details stay in the log; the caller gets the status and Bugasura's own JSON message.
        error_response = {
            "error": f"Bugasura API returned HTTP {status_code}.",
            "status": "failed",
            "error_type": "HTTPError",
            "status_code": e.response.status_code if e.response is not None else None,
            "method": method,
            "endpoint": endpoint
        }

        if e.response is not None:
            try:
                error_body = e.response.json()
                error_response["response_body"] = error_body
                if isinstance(error_body, dict):
                    logger.error(f"API Error Details: {error_body.get('message', error_body.get('error', 'No message'))}")
            except (ValueError, json.JSONDecodeError):
                logger.error(f"API Error Response (non-JSON): {e.response.text[:500]}")

        return error_response

    except httpx.ConnectError as e:
        logger.error(f"Connection Error: {method} {endpoint} - Cannot reach {API_BASE}: {str(e)}")
        return {
            "error": "Could not connect to the Bugasura API.",
            "status": "failed",
            "error_type": "ConnectionError",
            "message": "Failed to connect to Bugasura API. Try again shortly; if it persists, the server's API_BASE_URL configuration may be wrong.",
        }

    except httpx.TimeoutException as e:
        logger.error(f"Timeout Error: {method} {endpoint} - Request timed out: {str(e)}")
        return {
            "error": "The Bugasura API did not respond in time.",
            "status": "failed",
            "error_type": "Timeout",
            "message": "Request to Bugasura API timed out. The server may be slow or unresponsive.",
            "endpoint": endpoint
        }

    except httpx.RequestError as e:
        logger.error(f"Request Error: {method} {endpoint} - {type(e).__name__}: {str(e)}")
        return {
            "error": "The request to the Bugasura API failed.",
            "status": "failed",
            "error_type": "RequestError",
            "message": "Unexpected error occurred while making API request."
        }

    except (json.JSONDecodeError, ValueError) as e:
        logger.critical(f"Unexpected Error: {method} {endpoint} - {type(e).__name__}: {str(e)}", exc_info=True)
        return {
            "error": "The Bugasura API returned a response that could not be read.",
            "status": "failed",
            "error_type": "InvalidResponse",
            "message": "Unexpected internal error occurred."
        }
