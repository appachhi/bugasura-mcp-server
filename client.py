"""HTTP client, response envelopes, and shared low-level helpers."""
import json
from typing import Any, List, Literal, Optional, Union

import httpx
import requests  # noqa: F401 — legacy alias for except blocks

from config import API_BASE, logger


# Lazy-initialized shared AsyncClient for connection pooling (one per event loop).
_http_client: Optional[httpx.AsyncClient] = None


# Keys stripped from the upstream response before merging "extras" into the
# pagination envelope — they either describe the envelope itself or are
# rewritten by _paginated().
_PAGINATION_META_KEYS = {'total_rows', 'total', 'count', 'nrows',
                         'start_at', 'max_results', 'items', 'has_more',
                         'next_offset', 'offset'}


def _validate_id(value: Any, param_name: str) -> int:
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
        team_id = _validate_id(team_id, "team_id")
    """
    try:
        # Convert to int if it's not already
        # This handles string numbers like "123" -> 123
        int_value = int(value)

        # Ensure the value is positive (IDs are always positive)
        if int_value <= 0:
            raise ValueError(f"{param_name} must be a positive integer, got {int_value}")

        return int_value
    except (ValueError, TypeError) as e:
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


def _render_markdown(data: Any, title: Optional[str] = None) -> str:
    """
    Render a tool response dict as a human-readable markdown string.

    Keeps the rendering simple and generic — structured for agent readability
    rather than reproducing every upstream field. Error responses (status != 'OK')
    render as an Error block. Pagination envelopes render a summary plus the first
    page of items.
    """
    if isinstance(data, str):
        return data
    if not isinstance(data, dict):
        return f"```\n{data}\n```"

    lines: list = []
    if title:
        lines.append(f"# {title}")
        lines.append("")

    status = data.get('status')
    if status and status != 'OK':
        lines.append(f"**Status:** `{status}`")
        for k in ('error', 'error_type', 'message', 'action', 'help',
                 'step', 'instruction'):
            if k in data and data[k]:
                lines.append(f"- **{k}:** {data[k]}")
        if 'options' in data and isinstance(data['options'], list):
            lines.append("")
            lines.append(f"**Options ({len(data['options'])}):**")
            for opt in data['options'][:20]:
                if isinstance(opt, dict):
                    ident = opt.get('team_id') or opt.get('project_id') or opt.get('issue_id') or opt.get('id') or '?'
                    name = opt.get('team_name') or opt.get('project_name') or opt.get('summary') or opt.get('name') or ''
                    lines.append(f"- `{ident}` — {name}")
        return "\n".join(lines) if lines else json.dumps(data, indent=2)

    # Pagination envelope
    if 'items' in data and isinstance(data['items'], list):
        total = data.get('total', len(data['items']))
        offset = data.get('offset', 0)
        has_more = data.get('has_more', False)
        lines.append(f"**{len(data['items'])} of {total}** (offset {offset}{', more available' if has_more else ''})")
        lines.append("")
        for item in data['items'][:50]:
            if isinstance(item, dict):
                ident = (item.get('issue_id') or item.get('issue_key') or
                         item.get('project_id') or item.get('team_id') or
                         item.get('sprint_id') or item.get('testcase_id') or
                         item.get('requirement_id') or item.get('kb_id') or
                         item.get('page_id') or item.get('doc_id') or
                         item.get('space_key') or item.get('project_key') or
                         item.get('id') or item.get('folder_id') or '?')
                name = (item.get('summary') or item.get('project_name') or
                        item.get('team_name') or item.get('sprint_name') or
                        item.get('doc_name') or item.get('page_name') or
                        item.get('page_title') or item.get('space_name') or
                        item.get('name') or item.get('title') or
                        item.get('folder_name') or '')
                extras = []
                for fk in ('bug_status', 'status', 'severity', 'priority',
                           'platform', 'assignees'):
                    if item.get(fk):
                        extras.append(f"{fk}={item[fk]}")
                line = f"- `{ident}`"
                if name:
                    line += f" {name}"
                if extras:
                    line += f" — {' | '.join(extras)}"
                lines.append(line)
            else:
                lines.append(f"- {item}")
        return "\n".join(lines)

    # Generic detail view: key-value dump, skipping verbose/null fields
    for k, v in data.items():
        if v is None or v == '' or k in ('status',):
            continue
        if isinstance(v, (dict, list)) and len(str(v)) > 400:
            lines.append(f"- **{k}**: _(collapsed — {len(v) if hasattr(v, '__len__') else '?'} entries)_")
        else:
            lines.append(f"- **{k}**: {v}")
    return "\n".join(lines) if lines else json.dumps(data, indent=2)


def _respond(data: Any, response_format: str = "json") -> Any:
    """
    Finalize a tool response.

    - response_format='json'     → pass the dict through unchanged.
    - response_format='markdown' → wrap the rendered markdown in a dict so it
      still satisfies FastMCP's structured-content output schema.

    Tools annotate their return type as `dict`, which causes FastMCP to build
    an output_schema expecting structured content; returning a bare string
    would fail that validation ("structured_content must be a dict or None").
    Wrapping the markdown under a `markdown` key keeps the envelope structured
    while surfacing the human-readable rendering to agents.
    """
    if response_format == 'markdown':
        rendered = _render_markdown(data)
        status = data.get('status') if isinstance(data, dict) else 'OK'
        return {'status': status or 'OK', 'markdown': rendered}
    return data


def _paginated(items: list, total: Optional[int] = None, offset: int = 0,
               max_results: Optional[int] = None, **extras) -> dict:
    """
    Wrap a page of items in the standard pagination envelope (mcp-builder §Pagination).

    Returns:
        {
            'status': 'OK',
            'total':       int,        # total items matching the query
            'count':       int,        # items in this response
            'offset':      int,        # echo of start_at
            'items':       list,       # the page contents
            'has_more':    bool,
            'next_offset': int | None
        }
    Extra keyword arguments are merged at the top level (e.g. 'message',
    legacy keys such as 'project_list' for backwards compatibility).
    """
    count = len(items)
    if total is None:
        total = count + offset  # unknown upstream total — treat current page as terminal
    has_more = (offset + count) < total
    next_offset = offset + count if has_more else None
    envelope = {
        'status': 'OK',
        'total': total,
        'count': count,
        'offset': offset,
        'items': items,
        'has_more': has_more,
        'next_offset': next_offset,
    }
    envelope.update(extras)
    return envelope


def _paginate_upstream(upstream: dict, items_key: Optional[str] = None,
                       offset: int = 0) -> dict:
    """
    Wrap a Bugasura upstream list response in the standard pagination envelope.

    items_key: name of the field carrying the list (e.g. 'project_list', 'comment_list').
               If None, the first list-valued field is used.
    Non-OK upstream responses pass through unchanged.
    """
    if not isinstance(upstream, dict) or upstream.get('status') != 'OK':
        return upstream
    if items_key is None:
        for k, v in upstream.items():
            if isinstance(v, list):
                items_key = k
                break
    if items_key is None:
        return upstream
    items = upstream.get(items_key)
    if not isinstance(items, list):
        return upstream
    total = (upstream.get('total_rows')
             or upstream.get('nrows')
             or upstream.get('total')
             or upstream.get('count'))
    extras = {k: v for k, v in upstream.items()
              if k not in _PAGINATION_META_KEYS
              and k != items_key
              and k != 'status'}
    return _paginated(items, total=total, offset=offset, **extras)


def _get_http_client() -> httpx.AsyncClient:
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
    - Authentication via Basic auth header
    - Parameter type conversion (POST requests require string IDs)
    - Comprehensive error handling with detailed diagnostics
    - Response parsing

    Args:
        method: HTTP method (GET, POST, PUT, DELETE)
        endpoint: API endpoint path (e.g., '/v1/issues/list')
        api_key: User's Bugasura API key for authentication
        **kwargs: Additional arguments passed to requests.request()
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

    # Check if API key is provided before making the request
    if not api_key or not api_key.strip():
        return {
            'status': 'api_key_required',
            'error': 'No API key found. Please provide your Bugasura API key.',
            'error_type': 'ApiKeyMissing',
            'action': 'Please ask the user for their Bugasura API key. Once they provide it, retry the same tool call with the api_key parameter.',
            'help': 'To get your API key:\n'
                   '1. Go to https://bugasura.io\n'
                   '2. Navigate to User Settings → API Key\n'
                   '3. Copy your API key and provide it here'
        }

    # Log API request (without sensitive data)
    # SECURITY: Never log the full API key, only a hint for debugging
    api_key_hint = f"{api_key[:4]}..." if len(api_key) > 4 else "***"
    logger.info(f"API Request: {method} {endpoint}")
    logger.debug(f"API Key hint: {api_key_hint}")

    # Extract headers from kwargs if present, or create empty dict
    headers = kwargs.pop('headers', {})

    # Add Basic authentication header with the provided API key
    # Bugasura API expects: Authorization: Basic {api_key}
    headers['Authorization'] = f'Basic {api_key}'

    # Convert ID parameters to strings for POST requests
    # GET requests can use integers (auto-converted to strings in URL)
    if method.upper() in ('POST', 'PUT', 'PATCH'):
        # Handle form-encoded data (data parameter)
        if 'data' in kwargs and kwargs['data']:
            original_data = kwargs['data'].copy()
            kwargs['data'] = _prepare_post_params(kwargs['data'])
            logger.debug(f"POST data prepared: {len(kwargs['data'])} fields")

        # Handle JSON data (json parameter)
        if 'json' in kwargs and kwargs['json']:
            original_json = kwargs['json'].copy()
            kwargs['json'] = _prepare_post_params(kwargs['json'])
            logger.debug(f"JSON data prepared: {len(kwargs['json'])} fields")

    # Log request parameters (safe to log, no sensitive data)
    if 'params' in kwargs and kwargs['params']:
        # Filter out potentially sensitive params before logging
        safe_params = {k: v for k, v in kwargs['params'].items() if k not in ['api_key', 'password', 'token']}
        logger.debug(f"Request params: {safe_params}")

    client = _get_http_client()
    try:
        # Make the HTTP request with constructed URL and headers
        logger.debug(f"Sending {method} request to {url}")
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

        if status_code == 401:
            return {
                'status': 'api_key_required',
                'error': 'Invalid or expired API key. Please provide a valid Bugasura API key.',
                'error_type': 'AuthenticationError',
                'action': 'Please ask the user for their Bugasura API key. Once they provide it, retry the same tool call with the api_key parameter.',
                'help': 'To get your API key:\n'
                       '1. Go to https://bugasura.io\n'
                       '2. Navigate to User Settings → API Key\n'
                       '3. Copy your API key and provide it here'
            }

        error_response = {
            "error": str(e),
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
                error_text = e.response.text[:500]
                error_response["response_text"] = error_text
                logger.error(f"API Error Response (non-JSON): {error_text[:200]}")

        return error_response

    except httpx.ConnectError as e:
        logger.error(f"Connection Error: {method} {endpoint} - Cannot reach {API_BASE}: {str(e)}")
        return {
            "error": str(e),
            "status": "failed",
            "error_type": "ConnectionError",
            "message": "Failed to connect to Bugasura API. Check network connectivity and API_BASE_URL configuration.",
            "api_base": API_BASE
        }

    except httpx.TimeoutException as e:
        logger.error(f"Timeout Error: {method} {endpoint} - Request timed out: {str(e)}")
        return {
            "error": str(e),
            "status": "failed",
            "error_type": "Timeout",
            "message": "Request to Bugasura API timed out. The server may be slow or unresponsive.",
            "endpoint": endpoint
        }

    except httpx.RequestError as e:
        logger.error(f"Request Error: {method} {endpoint} - {type(e).__name__}: {str(e)}")
        return {
            "error": str(e),
            "status": "failed",
            "error_type": type(e).__name__,
            "message": "Unexpected error occurred while making API request."
        }

    except (json.JSONDecodeError, ValueError) as e:
        logger.critical(f"Unexpected Error: {method} {endpoint} - {type(e).__name__}: {str(e)}", exc_info=True)
        return {
            "error": str(e),
            "status": "failed",
            "error_type": type(e).__name__,
            "message": "Unexpected internal error occurred."
        }
