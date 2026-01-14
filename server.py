#!/usr/bin/env python3
"""
Bugasura MCP Server - Exposes Bugasura API via Model Context Protocol.

This server acts as a bridge between MCP clients and the Bugasura API,
allowing AI assistants to interact with bug tracking, project management, and test case features.

Supports two transport modes:
1. STDIO: For local integration with MCP clients (direct stdin/stdout communication)
2. SSE: For remote deployment via Server-Sent Events over HTTP/HTTPS
"""

# Import FastMCP for building MCP-compliant servers with tool definitions
from fastmcp import FastMCP

# Import Starlette for ASGI web application (used for SSE transport)
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.responses import JSONResponse

# Import uvicorn for serving the ASGI app in SSE mode
import uvicorn

# Import requests for making HTTP calls to Bugasura API
import requests

# Import standard libraries
import os
import sys
import json
import logging
import argparse
from typing import Optional
from dotenv import load_dotenv
from pydantic import Field

# Load environment variables from .env file (API_BASE_URL, MCP_SERVER_NAME, etc.)
load_dotenv()

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================
# Configure comprehensive logging for debugging and monitoring while protecting
# sensitive information (API keys, Authorization headers).

# Set up root logger for this application
logger = logging.getLogger(__name__)

# Get log level from environment variable (default: INFO)
# Options: DEBUG, INFO, WARNING, ERROR, CRITICAL
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logger.setLevel(getattr(logging, log_level, logging.INFO))

# Configure log format with timestamp, level, and message
# Format: 2024-01-27 10:30:45 - INFO - Message here
log_formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Console handler for development/debugging
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(log_formatter)
logger.addHandler(console_handler)

# Optional file handler for production logging
# Set LOG_FILE environment variable to enable file logging
log_file = os.getenv("LOG_FILE")
if log_file:
    # Generate date-based log filename: bugasura-mcp-server.yyyy-mm-dd.log
    from datetime import datetime
    log_date = datetime.now().strftime("%Y-%m-%d")

    # Extract directory and base filename
    log_dir = os.path.dirname(log_file)
    log_basename = os.path.basename(log_file)

    # If the log file already has a date pattern, use it as-is
    # Otherwise, insert date before the .log extension
    if log_basename.endswith('.log'):
        base_name = log_basename[:-4]  # Remove .log extension
        dated_log_file = os.path.join(log_dir, f"{base_name}.{log_date}.log")
    else:
        dated_log_file = f"{log_file}.{log_date}.log"

    file_handler = logging.FileHandler(dated_log_file)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(log_formatter)
    logger.addHandler(file_handler)
    logger.info(f"File logging enabled: {dated_log_file}")

# IMPORTANT: Suppress verbose logging from requests library to prevent
# accidental leakage of sensitive headers (Authorization, API keys)
# The requests library logs full request/response details at DEBUG level
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

logger.info(f"Logging initialized at {log_level} level")
logger.info(f"MCP Server: {os.getenv('MCP_SERVER_NAME', 'Bugasura')}")

# ============================================================================
# CONFIGURATION
# ============================================================================
# All configuration values are loaded from environment variables with sensible defaults.
# This allows deployment-specific configuration without code changes.

# Get Bugasura API base URL from environment variable
# Falls back to local development URL if not set
# Expected values: https://api.bugasura.io (production) or https://api.stage.bugasura.io (staging)
API_BASE = os.getenv("API_BASE_URL", "http://localhost/api.appachhi.com")

# Get MCP server name from environment variable
# This name is used to identify this server to MCP clients
# The name appears in MCP client tool listings and logs
# Default: "Bugasura" - can be customized per deployment (e.g., "Bugasura-Staging", "Bugasura-Team-A")
MCP_SERVER_NAME = os.getenv("MCP_SERVER_NAME", "Bugasura")

# Initialize FastMCP server instance with configured service name
# FastMCP provides the MCP protocol implementation and tool registration
# This creates an MCP-compliant server that AI assistants can communicate with
# The server exposes tools (functions) and resources (documentation) to clients
mcp = FastMCP(MCP_SERVER_NAME)

# ============================================================================
# SSE TRANSPORT CONFIGURATION
# ============================================================================
# The following section configures the Starlette ASGI app for SSE transport.
# This allows the MCP server to be deployed remotely and accessed via HTTPS.

async def health_check(request):
    """
    Health check endpoint for monitoring server status.

    Returns JSON with:
    - status: "ok" if server is running
    - service: Service name
    - version: Current version
    - api_base: Configured Bugasura API URL
    - endpoints: Available endpoints

    Used by load balancers, monitoring tools, and manual testing.
    """
    # Return server status information as JSON
    return JSONResponse({
        "status": "ok",
        "service": "Bugasura MCP Server",
        "version": "1.0.0",
        "api_base": API_BASE,
        "endpoints": {
            "health": "/",
            "sse": "/sse"
        }
    })

# Create Starlette ASGI application with two routes:
# 1. Health check at root (/)
# 2. MCP SSE endpoint at root (/) - FastMCP handles SSE protocol internally
app = Starlette(
    routes=[
        # Health check endpoint for server monitoring
        Route("/", health_check),

        # Mount FastMCP's SSE app at root path
        # This handles the MCP protocol over Server-Sent Events
        # Note: Currently mounted at "/" which creates /sse/sse path
        # TODO: Consider mounting at "/sse" for cleaner URL structure
        Mount("/", app=mcp.sse_app())
    ]
)


# ============================================================================
# CORE API HELPER FUNCTION
# ============================================================================
# IMPORTANT: Bugasura API parameter type requirements:
# - GET requests (params): Accept integers or strings (both work)
# - POST requests (data/json): Require strings for all IDs
#
# This is standard HTTP behavior:
# - Query parameters are always strings in URLs
# - Form-encoded data expects string values
# - JSON can have integers, but Bugasura API expects string IDs
#
# Convention used in this code:
# - GET: Send integers directly (cleaner code, auto-converted to strings in URL)
# - POST: Explicitly convert to strings with str() (API requirement)

def _validate_id(value: any, param_name: str) -> int:
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


def make_api_request(method: str, endpoint: str, api_key: str, **kwargs) -> dict:
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

    # Log API request (without sensitive data)
    # SECURITY: Never log the full API key, only a hint for debugging
    api_key_hint = f"{api_key[:8]}..." if len(api_key) > 8 else "***"
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

    try:
        # Make the HTTP request with constructed URL and headers
        logger.debug(f"Sending {method} request to {url}")
        response = requests.request(method, url, headers=headers, **kwargs)

        # Log response status
        logger.info(f"API Response: {method} {endpoint} - Status {response.status_code}")

        # Raise exception for 4xx/5xx status codes
        # This triggers the except block below for error handling
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

    except requests.exceptions.HTTPError as e:
        # HTTP error (4xx or 5xx status code)
        # Capture detailed information for debugging
        status_code = e.response.status_code if e.response else "unknown"
        logger.error(f"HTTP Error: {method} {endpoint} - Status {status_code}: {str(e)}")

        error_response = {
            "error": str(e),
            "status": "failed",
            "error_type": "HTTPError",
            "status_code": e.response.status_code if e.response else None,
            "method": method,
            "endpoint": endpoint
        }

        # Try to parse error response body if available
        if e.response is not None:
            try:
                # Attempt to parse JSON error response from API
                error_body = e.response.json()
                error_response["response_body"] = error_body
                # Log structured error details if available
                if isinstance(error_body, dict):
                    logger.error(f"API Error Details: {error_body.get('message', error_body.get('error', 'No message'))}")
            except ValueError:
                # If response is not JSON, include raw text
                error_text = e.response.text[:500]  # Limit to 500 chars
                error_response["response_text"] = error_text
                logger.error(f"API Error Response (non-JSON): {error_text[:200]}")

        return error_response

    except requests.exceptions.ConnectionError as e:
        # Network connection error (DNS failure, refused connection, etc.)
        logger.error(f"Connection Error: {method} {endpoint} - Cannot reach {API_BASE}: {str(e)}")
        return {
            "error": str(e),
            "status": "failed",
            "error_type": "ConnectionError",
            "message": "Failed to connect to Bugasura API. Check network connectivity and API_BASE_URL configuration.",
            "api_base": API_BASE
        }

    except requests.exceptions.Timeout as e:
        # Request timeout
        logger.error(f"Timeout Error: {method} {endpoint} - Request timed out: {str(e)}")
        return {
            "error": str(e),
            "status": "failed",
            "error_type": "Timeout",
            "message": "Request to Bugasura API timed out. The server may be slow or unresponsive.",
            "endpoint": endpoint
        }

    except requests.exceptions.RequestException as e:
        # Catch-all for other request errors
        logger.error(f"Request Exception: {method} {endpoint} - {type(e).__name__}: {str(e)}")
        return {
            "error": str(e),
            "status": "failed",
            "error_type": type(e).__name__,
            "message": "Unexpected error occurred while making API request."
        }

    except Exception as e:
        # Unexpected non-requests error (JSON parsing, etc.)
        logger.critical(f"Unexpected Error: {method} {endpoint} - {type(e).__name__}: {str(e)}", exc_info=True)
        return {
            "error": str(e),
            "status": "failed",
            "error_type": type(e).__name__,
            "message": "Unexpected internal error occurred."
        }


# ============================================================================
# API KEY VALIDATION
# ============================================================================

def validate_api_key(api_key: str) -> dict:
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
    # Validate API key format
    if not api_key or not isinstance(api_key, str) or len(api_key.strip()) == 0:
        return {
            'valid': False,
            'status': 'failed',
            'error': 'API key is required and must be a non-empty string',
            'error_type': 'ValidationError',
            'help': 'Get your API key from Bugasura → User Settings → API Key'
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
    response = make_api_request('GET', '/v1/teams/getApps', api_key)

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
        return {'valid': True, 'status': 'OK'}
    else:
        # Return the error details from the API
        return {
            'valid': False,
            'status': 'failed',
            'error': response.get('error', 'Invalid API key or authentication failed'),
            'error_type': response.get('error_type', 'AuthenticationError'),
            'message': 'Please check your API key and try again. Get your API key from Bugasura → User Settings → API Key'
        }


# ============================================================================
# RESPONSE FILTERING
# ============================================================================

def filter_large_fields(data: dict) -> dict:
    """
    Remove large unnecessary fields from API responses to reduce payload size.

    Fields removed:
    - tools_integration_settings: Large JSON containing integration configs
      (can be 100KB+, not needed by MCP clients)
    - tools_mapped_fields: Integration field mappings (also large)

    This function recursively processes nested structures (lists and dicts).
    """
    if not isinstance(data, dict):
        return data

    # Fields to remove from responses
    fields_to_remove = ['tools_integration_settings', 'tools_mapped_fields']

    # Create a new dict without the large fields
    filtered = {}
    for key, value in data.items():
        if key in fields_to_remove:
            logger.debug(f"Filtered out large field: {key}")
            continue

        # Recursively filter nested dicts
        if isinstance(value, dict):
            filtered[key] = filter_large_fields(value)
        # Recursively filter lists of dicts
        elif isinstance(value, list):
            filtered[key] = [filter_large_fields(item) if isinstance(item, dict) else item for item in value]
        else:
            filtered[key] = value

    return filtered


# ============================================================================
# CONTEXT SELECTION HELPER
# ============================================================================
# Centralized helper function to handle interactive team/project selection.
# This ensures consistent UX across all operations that require context.

def select_team_project_context(api_key: str, team_id: Optional[int], project_id: Optional[int], operation_name: str, operation_params: str = "") -> dict:
    """
    Helper function to handle interactive team and project selection.

    Returns either:
    1. A selection_required response if team_id or project_id is missing
    2. A dict with 'team_id' and 'project_id' keys if both are provided

    Args:
        api_key: User's Bugasura API key
        team_id: Team identifier (optional)
        project_id: Project identifier (optional)
        operation_name: Name of the operation (for display in prompts)
        operation_params: Additional parameters to include in instruction examples

    Returns:
        dict: Either selection prompt or validated context with team_id and project_id
    """
    # Step 1: If team_id not provided, fetch and return team options
    if team_id is None:
        context = _fetch_user_context(api_key)

        # Handle unexpected list response
        if isinstance(context, list):
            return {
                'status': 'failed',
                'error': 'Unexpected API response format in team selection',
                'error_type': 'ResponseFormatError',
                'details': 'Expected dict, got list'
            }

        if context.get('status') != 'OK':
            return context

        teams = context.get('teams', [])
        if not teams:
            return {
                'status': 'failed',
                'error': 'No teams found. Please create a team first.'
            }

        return {
            'status': 'selection_required',
            'step': 'team_selection',
            'message': f'Please select a team for {operation_name}:',
            'options': [{
                'team_id': team['team_id'],
                'team_name': team['team_name'],
                'role': team['role']
            } for team in teams],
            'instruction': f'Please call {operation_name} again with team_id parameter. Example: {operation_name}(api_key="{api_key[:10]}...", team_id=<selected_team_id>{operation_params})'
        }

    # Step 2: If project_id not provided, fetch and return project options
    if project_id is None:
        context = _fetch_user_context(api_key)

        # Handle unexpected list response
        if isinstance(context, list):
            return {
                'status': 'failed',
                'error': 'Unexpected API response format in project selection',
                'error_type': 'ResponseFormatError',
                'details': 'Expected dict, got list'
            }

        if context.get('status') != 'OK':
            return context

        # Find the selected team
        selected_team = None
        for team in context.get('teams', []):
            if team['team_id'] == team_id:
                selected_team = team
                break

        if not selected_team:
            return {
                'status': 'failed',
                'error': f'Team with ID {team_id} not found or you do not have access to it.'
            }

        projects = selected_team.get('projects', [])
        if not projects:
            return {
                'status': 'failed',
                'error': f'No projects found in team "{selected_team.get("team_name", "Unknown Team")}". Please create a project first.'
            }

        return {
            'status': 'selection_required',
            'step': 'project_selection',
            'message': f'Please select a project in team "{selected_team.get("team_name", "Unknown Team")}" for {operation_name}:',
            'options': [{
                'project_id': proj['project_id'],
                'project_name': proj['project_name'],
                'platform': proj.get('platform', ''),
                'platform_type': proj.get('platform_type', '')
            } for proj in projects],
            'instruction': f'Please call {operation_name} again with project_id parameter. Example: {operation_name}(api_key="{api_key[:10]}...", team_id={team_id}, project_id=<selected_project_id>{operation_params})'
        }

    # Both team_id and project_id provided - return validated context
    return {
        'team_id': team_id,
        'project_id': project_id
    }


# ============================================================================
# TEAM MANAGEMENT TOOLS
# ============================================================================
# Teams are the top-level organizational unit in Bugasura.
# All projects, issues, and test cases belong to a team.
# Users must be members of a team to access its data.

@mcp.tool(
    name = "list_teams",
    description = "List all teams the user belongs to. Returns minimal team info for selection."
)
def list_teams(api_key: str = Field(description="User's Bugasura API key")) -> dict:
    """
    List all teams the user belongs to.

    This is typically the first API call made, as team_id is required for
    most other operations. Returns minimal team information to reduce payload size.

    Args:
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'teams': [
                {
                    'team_id': int,
                    'name': str,
                    'is_admin': bool,
                    'owner_id': int,
                    'project_count': int
                },
                ...
            ]
        }
    """
    # Call Bugasura API to fetch user's teams and projects
    full_response = make_api_request('GET', '/v1/teams/getApps', api_key)

    # Handle case where API might return a list instead of dict
    if isinstance(full_response, list):
        return {
            'status': 'failed',
            'error': 'Unexpected API response format (received list instead of dict)',
            'error_type': 'ResponseFormatError',
            'response_preview': str(full_response[:2]) if len(full_response) > 0 else 'Empty list'
        }

    # Check if API call was successful
    if full_response.get('status') == 'OK':
        # Extract team details from response
        # The API returns 'userTeamsProjectsDetails' which includes full team info
        teams_data = full_response.get('userTeamsProjectsDetails', [])

        # Transform to minimal format to reduce response size and improve readability
        # Only include essential fields needed for subsequent operations
        minimal_teams = [{
            'team_id': t.get('team_id'),           # Required for all team-scoped operations
            'name': t.get('team_name'),            # Display name
            'is_admin': t.get('is_admin'),         # User's role in team
            'owner_id': t.get('team_owner_id'),    # Team owner for permission checks
            'project_count': t.get('apps_count', 0) # Number of projects in team
        } for t in teams_data]

        # Return simplified response
        return {'status': 'OK', 'teams': minimal_teams}

    # Return raw response if API call failed (includes error details)
    return full_response


def _fetch_user_context(api_key: str) -> dict:
    """
    Internal helper function to fetch user context.
    This is NOT an MCP tool, so it can be called from other Python functions.
    """
    # Call Bugasura API to fetch user's teams and projects
    full_response = make_api_request('GET', '/v1/teams/getApps', api_key)

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

    return {
        'status': 'OK',
        'teams': structured_teams,
        'message': 'Use team_id and project_id from this response in other tool calls'
    }


@mcp.tool(
    name = "get_user_context",
    description = "Get complete user context including all teams and their projects. Returns comprehensive information for discovery and finding team_id/project_id values."
)
def get_user_context(api_key: str = Field(description="User's Bugasura API key")) -> dict:
    """
    Get complete user context including all teams and their projects.

    This is a convenience tool that returns comprehensive information about
    all teams and projects the user has access to. It's useful for:
    - Initial setup/discovery
    - Finding team_id and project_id values for subsequent operations
    - Understanding the user's organizational structure

    Args:
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'teams': [
                {
                    'team_id': int,
                    'team_name': str,
                    'role': str,
                    'projects': [
                        {
                            'project_id': int,
                            'project_name': str,
                            'platform': str,
                            'platform_type': str
                        },
                        ...
                    ]
                },
                ...
            ],
            'message': 'Use team_id and project_id from this response in other tool calls'
        }

    Example:
        User: "Get my user context"
        Returns all teams and projects with IDs for easy reference

        User: "Show me issues in Mobile App (team 1, project 10)"
        Now you have the IDs to use in list_issues()
    """
    return _fetch_user_context(api_key)


@mcp.tool(
    name = "find_project_by_name",
    description = "Find projects by name across ALL teams. Searches case-insensitive, partial match. Returns team_id and project_id for use in other operations."
)
def find_project_by_name(
    api_key: str = Field(description="User's Bugasura API key"),
    project_name: str = Field(description="Project name to search for (case-insensitive, partial match supported)")
) -> dict:
    """
    Find projects by name across ALL teams the user belongs to.

    This is a convenience tool that searches for projects matching the given name
    (case-insensitive, partial match) across ALL teams. This is the recommended
    function when:
    - User doesn't specify which team
    - You want to search projects by name only
    - You need to discover projects across multiple teams

    Useful when you know the project name but not the team_id or project_id.

    Args:
        api_key: User's Bugasura API key
        project_name: Project name to search for (case-insensitive, partial match)

    Returns:
        dict: {
            'status': 'OK',
            'query': str,           # The search term used
            'matches': [
                {
                    'team_id': int,
                    'team_name': str,
                    'project_id': int,
                    'project_name': str,
                    'platform': str,
                    'platform_type': str
                },
                ...
            ],
            'count': int            # Number of matches found
        }

    Example:
        User: "Find project named mobile"
        Returns all projects with "mobile" in their name, along with their team_id and project_id

        Then you can use these IDs:
        list_issues(api_key, team_id=1, project_id=10, ...)
    """
    # Validation
    if not project_name or not project_name.strip():
        return {
            'status': 'failed',
            'error': 'project_name cannot be empty'
        }

    # Get user context using internal helper
    context = _fetch_user_context(api_key)
    if context.get('status') != 'OK':
        return context

    # Search for matching projects
    matches = []
    search_term = project_name.lower().strip()

    for team in context['teams']:
        for project in team.get('projects', []):
            if search_term in project.get('project_name', '').lower():
                matches.append({
                    'team_id': team.get('team_id'),
                    'team_name': team.get('team_name'),
                    'project_id': project.get('project_id'),
                    'project_name': project.get('project_name'),
                    'platform': project.get('platform', ''),
                    'platform_type': project.get('platform_type', '')
                })

    return {
        'status': 'OK',
        'query': project_name,
        'matches': matches,
        'count': len(matches)
    }


@mcp.tool(
    name = "find_team_by_name",
    description = "Find teams by name (case-insensitive, partial match). Returns team_id and project count for teams the user belongs to."
)
def find_team_by_name(
    api_key: str = Field(description="User's Bugasura API key"),
    team_name: str = Field(description="Team name to search for (case-insensitive, partial match supported)")
) -> dict:
    """
    Find teams by name that the user belongs to.

    This is a convenience tool that searches for teams matching the given name
    (case-insensitive, partial match). Useful when you know the team name but
    not the team_id.

    Args:
        api_key: User's Bugasura API key
        team_name: Team name to search for (case-insensitive, partial match)

    Returns:
        dict: {
            'status': 'OK',
            'query': str,           # The search term used
            'matches': [
                {
                    'team_id': int,
                    'team_name': str,
                    'role': str,
                    'project_count': int
                },
                ...
            ],
            'count': int            # Number of matches found
        }

    Example:
        User: "Find team named acme"
        Returns all teams with "acme" in their name, along with their team_id

        Then you can use this ID:
        list_projects(api_key, team_id=1, ...)
    """
    # Validation
    if not team_name or not team_name.strip():
        return {
            'status': 'failed',
            'error': 'team_name cannot be empty'
        }

    # Get user context using internal helper
    context = _fetch_user_context(api_key)
    if context.get('status') != 'OK':
        return context

    # Search for matching teams
    matches = []
    search_term = team_name.lower().strip()

    for team in context['teams']:
        if search_term in team.get('team_name', '').lower():
            matches.append({
                'team_id': team.get('team_id'),
                'team_name': team.get('team_name'),
                'role': team.get('role'),
                'project_count': len(team.get('projects', []))
            })

    return {
        'status': 'OK',
        'query': team_name,
        'matches': matches,
        'count': len(matches)
    }


@mcp.tool(
    name="get_team",
    description="Get detailed information about a specific team including settings, custom fields, and subscription details. Supports team_id or team_name."
)
def get_team(
    api_key: str = Field(description="User's Bugasura API key"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (provide either team_id or team_name)"),
    team_name: Optional[str] = Field(default=None, description="Team name to search for (provide either team_id or team_name)")
) -> dict:
    """
    Get detailed team information.

    Returns comprehensive team data including owner details, subscription info,
    custom field configurations, and team settings.

    Args:
        api_key: User's Bugasura API key (required)
        team_id: Team identifier (optional, provide either team_id or team_name)
        team_name: Team name to search for (optional, provide either team_id or team_name)

    Returns:
        dict: {
            'status': 'OK',
            'team': {
                'team_id': int,
                'name': str,
                'owner_id': int,
                'owner_name': str,
                'member_count': int,
                'plan_name': str,
                'subscription_status': str,
                'standard_status_list': str,
                'tags_list': str,
                ...
            }
        }

    Error Response:
        dict: {
            'status': 'ERROR' or 'failed',
            'message': 'Error description'
        }

    Examples:
        # Get team details by ID
        get_team(api_key, team_id=123)

        # Get team details by name
        get_team(api_key, team_name="Engineering Team")

    Notes:
        - User must be a member of the team to access its details
        - Returns full team configuration including custom fields and settings
        - Useful for understanding team setup before creating projects
        - Provide either team_id or team_name (not both)
    """
    # Validate API key before proceeding
    logger.info(f"get_team: Starting for team_id={team_id}, team_name={team_name}")
    validation = validate_api_key(api_key)

    # Handle case where API might return a list instead of dict
    if isinstance(validation, list):
        logger.error("get_team: API validation returned unexpected list format")
        return {
            'status': 'failed',
            'error': 'Unexpected API response format',
            'details': str(validation)
        }

    if not validation.get('valid'):
        logger.error(f"get_team: API key validation failed: {validation.get('error')}")
        return validation

    # Resolve team identifier (team_id or team_name)
    team_resolution = _resolve_team_identifier(api_key, team_id, team_name)
    if team_resolution.get('status') != 'OK':
        logger.error(f"get_team: Team resolution failed: {team_resolution}")
        return team_resolution

    team_id = team_resolution['team_id']

    logger.info(f"get_team: Fetching team details for team_id={team_id}")

    # Make GET request to get team endpoint
    response = make_api_request('GET', '/v1/teams/get', api_key, params={
        'team_id': team_id
    })

    # Handle response
    if isinstance(response, dict):
        if response.get('status') == 'OK':
            logger.info(f"get_team: Successfully fetched team {team_id}")
        else:
            logger.error(f"get_team: Failed to fetch team. Response: {response}")
    else:
        logger.warning(f"get_team: Unexpected response type: {type(response)}")

    return response


@mcp.tool(
    name="create_team",
    description="Create a new team. The user who creates the team becomes the team owner/admin."
)
def create_team(
    api_key: str = Field(description="User's Bugasura API key"),
    team_name: str = Field(description="Team name (required, 1-100 characters)")
) -> dict:
    """
    Create a new team.

    The user creating the team automatically becomes the team owner/admin.
    Team name must be unique within the user's teams.

    Args:
        api_key: User's Bugasura API key (required)
        team_name: Name for the new team (required, 1-100 characters)

    Returns:
        dict: {
            'status': 'OK',
            'team_id': int,
            'team_name': str,
            'message': str
        }

    Error Response:
        dict: {
            'status': 'ERROR' or 'failed',
            'message': 'Error description'
        }

    Examples:
        # Create a new team
        create_team(api_key, team_name="Mobile App Team")

        # Create team with descriptive name
        create_team(api_key, team_name="Q4 2024 Product Development")

    Notes:
        - Creator automatically becomes team owner/admin
        - Team name must be unique within your teams
        - Can create unlimited teams on most subscription plans
        - Team comes with default settings that can be customized later
    """
    # Validate API key before proceeding
    logger.info(f"create_team: Starting for team_name='{team_name}'")
    validation = validate_api_key(api_key)

    # Handle case where API might return a list instead of dict
    if isinstance(validation, list):
        logger.error("create_team: API validation returned unexpected list format")
        return {
            'status': 'failed',
            'error': 'Unexpected API response format',
            'details': str(validation)
        }

    if not validation.get('valid'):
        logger.error(f"create_team: API key validation failed: {validation.get('error')}")
        return validation

    # Validate team name
    if not team_name or not team_name.strip():
        logger.error("create_team: Empty team_name provided")
        return {
            'status': 'failed',
            'error': 'Team name is required',
            'error_type': 'ValidationError',
            'message': 'Please provide a team name'
        }

    team_name = team_name.strip()

    if len(team_name) > 100:
        logger.error(f"create_team: Team name too long: {len(team_name)} characters")
        return {
            'status': 'failed',
            'error': 'Team name too long',
            'error_type': 'ValidationError',
            'message': 'Team name must be 100 characters or less'
        }

    logger.info(f"create_team: Creating team '{team_name}'")

    # Build payload with required fields
    payload = {
        "team_name": team_name
    }

    logger.debug(f"create_team: Payload prepared")

    # Make POST request to create team endpoint
    response = make_api_request('POST', '/v1/teams/add', api_key, data=payload)

    # Handle response
    if isinstance(response, dict):
        if response.get('status') == 'OK':
            logger.info(f"create_team: Successfully created team '{team_name}'")
            if response.get('team_id'):
                logger.info(f"create_team: New team_id={response.get('team_id')}")
        else:
            logger.error(f"create_team: Failed to create team. Response: {response}")
    else:
        logger.warning(f"create_team: Unexpected response type: {type(response)}")

    return response


@mcp.tool(
    name="update_team",
    description="Update team name. Only team admins can update team details. Supports team_id or team_name to identify the team."
)
def update_team(
    api_key: str = Field(description="User's Bugasura API key"),
    new_team_name: str = Field(description="New team name (required, 1-100 characters)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (provide either team_id or team_name)"),
    team_name: Optional[str] = Field(default=None, description="Current team name to search for (provide either team_id or team_name)")
) -> dict:
    """
    Update team name.

    Only team admins can update team details. The API will return an
    authorization error if the user is not an admin.

    Args:
        api_key: User's Bugasura API key (required)
        new_team_name: New name for the team (required, 1-100 characters)
        team_id: Team identifier (optional, provide either team_id or team_name)
        team_name: Current team name to search for (optional, provide either team_id or team_name)

    Returns:
        dict: {
            'status': 'OK',
            'message': 'Team name updated successfully'
        }

    Error Response:
        dict: {
            'status': 'ERROR' or 'failed',
            'message': 'Error description'
        }

    Examples:
        # Update team name by ID
        update_team(api_key, new_team_name="Updated Team Name", team_id=123)

        # Update team name by name
        update_team(api_key, new_team_name="Q1 2025 - Mobile Development", team_name="Mobile Team")

    Notes:
        - Only team admins can update team details
        - Team owner always has admin permissions
        - API returns authorization error if user is not admin
        - Team name must be unique within your teams
        - Provide either team_id or team_name (not both)
    """
    # Validate API key before proceeding
    logger.info(f"update_team: Starting for team_id={team_id}, team_name='{team_name}', new_team_name='{new_team_name}'")
    validation = validate_api_key(api_key)

    # Handle case where API might return a list instead of dict
    if isinstance(validation, list):
        logger.error("update_team: API validation returned unexpected list format")
        return {
            'status': 'failed',
            'error': 'Unexpected API response format',
            'details': str(validation)
        }

    if not validation.get('valid'):
        logger.error(f"update_team: API key validation failed: {validation.get('error')}")
        return validation

    # Resolve team identifier (team_id or team_name)
    team_resolution = _resolve_team_identifier(api_key, team_id, team_name)
    if team_resolution.get('status') != 'OK':
        logger.error(f"update_team: Team resolution failed: {team_resolution}")
        return team_resolution

    team_id = team_resolution['team_id']

    # Validate new team name
    if not new_team_name or not new_team_name.strip():
        logger.error("update_team: Empty new_team_name provided")
        return {
            'status': 'failed',
            'error': 'New team name is required',
            'error_type': 'ValidationError',
            'message': 'Please provide a new team name'
        }

    new_team_name = new_team_name.strip()

    if len(new_team_name) > 100:
        logger.error(f"update_team: New team name too long: {len(new_team_name)} characters")
        return {
            'status': 'failed',
            'error': 'Team name too long',
            'error_type': 'ValidationError',
            'message': 'Team name must be 100 characters or less'
        }

    logger.info(f"update_team: Updating team_id={team_id} to '{new_team_name}'")

    # Build payload with required fields
    payload = {
        "team_id": team_id,
        "team_name": new_team_name
    }

    logger.debug(f"update_team: Payload prepared")

    # Make POST request to update team endpoint
    response = make_api_request('POST', '/v1/teams/update', api_key, data=payload)

    # Handle response
    if isinstance(response, dict):
        if response.get('status') == 'OK':
            logger.info(f"update_team: Successfully updated team {team_id} to '{new_team_name}'")
        else:
            logger.error(f"update_team: Failed to update team. Response: {response}")
    else:
        logger.warning(f"update_team: Unexpected response type: {type(response)}")

    return response


@mcp.tool(
    name="delete_team",
    description="Delete team permanently. Only team admins can delete teams. WARNING: This deletes all associated projects, sprints, issues, and test cases. Supports team_id or team_name."
)
def delete_team(
    api_key: str = Field(description="User's Bugasura API key"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (provide either team_id or team_name)"),
    team_name: Optional[str] = Field(default=None, description="Team name to search for (provide either team_id or team_name)")
) -> dict:
    """
    Delete team permanently.

    WARNING: This is a destructive operation that permanently deletes:
    - The team itself
    - All projects in the team
    - All sprints and test runs
    - All issues/bugs
    - All test cases
    - All requirements
    - All team data and settings

    This operation CANNOT be undone!

    Args:
        api_key: User's Bugasura API key (required)
        team_id: Team identifier (optional, provide either team_id or team_name)
        team_name: Team name to search for (optional, provide either team_id or team_name)

    Returns:
        dict: {
            'status': 'OK',
            'message': 'Team deleted successfully'
        }

    Error Response:
        dict: {
            'status': 'ERROR' or 'failed',
            'message': 'Error description'
        }

    Examples:
        # Delete a test team by ID
        delete_team(api_key, team_id=999)

        # Delete a test team by name
        delete_team(api_key, team_name="Test Team")

    Notes:
        - Only team admins can delete teams
        - This operation cannot be undone
        - All data associated with the team will be permanently deleted
        - Consider archiving projects instead of deleting the team
        - Team owner always has admin permissions
        - Provide either team_id or team_name (not both)
        - Use with extreme caution!
    """
    # Validate API key before proceeding
    logger.warning(f"delete_team: DESTRUCTIVE OPERATION - Starting for team_id={team_id}, team_name={team_name}")
    validation = validate_api_key(api_key)

    # Handle case where API might return a list instead of dict
    if isinstance(validation, list):
        logger.error("delete_team: API validation returned unexpected list format")
        return {
            'status': 'failed',
            'error': 'Unexpected API response format',
            'details': str(validation)
        }

    if not validation.get('valid'):
        logger.error(f"delete_team: API key validation failed: {validation.get('error')}")
        return validation

    # Resolve team identifier (team_id or team_name)
    team_resolution = _resolve_team_identifier(api_key, team_id, team_name)
    if team_resolution.get('status') != 'OK':
        logger.error(f"delete_team: Team resolution failed: {team_resolution}")
        return team_resolution

    team_id = team_resolution['team_id']

    logger.warning(f"delete_team: Deleting team_id={team_id} - THIS WILL DELETE ALL TEAM DATA")

    # Build payload with required fields
    payload = {
        "team_id": team_id
    }

    logger.debug(f"delete_team: Payload prepared")

    # Make POST request to delete team endpoint
    response = make_api_request('POST', '/v1/teams/delete', api_key, data=payload)

    # Handle response
    if isinstance(response, dict):
        if response.get('status') == 'OK':
            logger.warning(f"delete_team: Successfully deleted team {team_id}")
        else:
            logger.error(f"delete_team: Failed to delete team. Response: {response}")
    else:
        logger.warning(f"delete_team: Unexpected response type: {type(response)}")

    return response


# ============================================================================
# PROJECT MANAGEMENT TOOLS
# ============================================================================
# Projects (apps in Bugasura terminology) organize issues and test cases.
# Each project belongs to a team and has its own workflow, tags, and settings.
#
# IMPORTANT NAMING CONVENTION:
# - MCP tool parameters use "project_id" (user-friendly, consistent naming)
# - Bugasura API uses "app_id" internally (legacy naming from "apps" table)
# - Some endpoints use "project_id", others use "app_id" - check each endpoint
# - Test case endpoints specifically require "app_id" parameter name

@mcp.tool(
    name = "list_projects",
    description = "List projects for a specific team with filtering and pagination. Supports platform, status, and search filters."
)
def list_projects(
    api_key: str = Field(description="User's Bugasura API key"),
    team_id: int = Field(description="Team identifier (required)"),
    start_at: int = Field(default=0, description="Pagination offset (default: 0)"),
    max_results: int = Field(default=10, description="Number of results to return (10-100, default: 10)"),
    platform: str = Field(default="ALL", description="Filter by platform: 'ALL', 'Android', 'iOS', 'Desktop', 'Multiple' (case-sensitive)"),
    platform_type: str = Field(default="ALL", description="Filter by platform type: 'ALL', 'Apps', 'Mobileweb', 'Web', 'Multiple' (case-sensitive)"),
    status: str = Field(default="ACTIVE", description="Filter by status: 'ACTIVE', 'ARCHIVE', 'ALL' (case-insensitive)"),
    project_type: str = Field(default="all", description="Filter by access: 'all', 'contributed', 'private', 'public' (case-insensitive)"),
    search_text: str = Field(default="", description="Search projects by name (case-insensitive partial match)"),
    source: str = Field(default="", description="Filter by creation source: 'PLATFORM', 'EXTENSION', 'API', 'IMPORT'")
) -> dict:
    """
    List all projects for a team with filtering and pagination.

    NOTE: This function requires a team_id. If you want to:
    - Search for projects across ALL teams by name: Use find_project_by_name()
    - List all teams first: Use list_teams()
    - Get all teams and projects in one call: Use get_user_context()

    Args:
        api_key: User's Bugasura API key
        team_id: Team identifier (required - specify which team's projects to list)
        start_at: Pagination offset (default: 0)
        max_results: Number of results to return (default: 10, min: 10, max: 100)
        platform: Filter by platform (default: ALL, case-sensitive)
            Allowed: 'ALL', 'Android', 'iOS', 'Desktop', 'Multiple'
        platform_type: Filter by platform type (default: ALL, case-sensitive)
            Allowed: 'ALL', 'Apps', 'Mobileweb', 'Web', 'Multiple'
        status: Filter by project status (default: ACTIVE, case-insensitive)
            Allowed: 'ACTIVE', 'ARCHIVE', 'ALL'
        project_type: Filter by project access type (default: all, case-insensitive)
            Allowed: 'all', 'contributed', 'private', 'public'
            - 'all': All projects user has access to
            - 'contributed': Projects user contributed to but not a team member
            - 'private': Private projects
            - 'public': Public projects
        search_text: Search projects by name (case-insensitive, partial match)
        source: Filter by creation source (optional, case-sensitive)
            Common values: 'PLATFORM', 'EXTENSION', 'API', 'IMPORT'

    Returns:
        dict: {
            'status': 'OK',
            'message': 'Project list fetched successfully',
            'project_list': [
                {
                    'project_id': int,
                    'project_name': str,
                    'issue_prefix': str,
                    'platform': str,
                    'platform_type': str,
                    'team_id': int,
                    'team_name': str,
                    'status': str,
                    'public_link_url': str,
                    ...
                },
                ...
            ],
            'nrows': int,           # Number of projects in current page
            'total_rows': int,      # Total number of projects matching filters
            'start_at': int,        # Current pagination offset
            'max_results': int      # Results per page
        }

    Filter Value Details:

    Platform (case-sensitive):
        - 'ALL': Show all platforms (default)
        - 'Android': Android mobile projects
        - 'iOS': iOS mobile projects
        - 'Desktop': Desktop application projects
        - 'Multiple': Projects targeting multiple platforms

    Platform Type (case-sensitive):
        - 'ALL': Show all platform types (default)
        - 'Apps': Native mobile applications
        - 'Mobileweb': Mobile web applications
        - 'Web': Web applications
        - 'Multiple': Projects with multiple platform types

    Status (case-insensitive, converted to uppercase):
        - 'ACTIVE': Only active projects (default)
        - 'ARCHIVE': Only archived/deleted projects
        - 'ALL': Both active and archived projects

    Project Type (case-insensitive, converted to lowercase):
        - 'all': All projects user can access (default)
        - 'contributed': Public projects user contributed to
        - 'private': Private team projects
        - 'public': Public team projects

    Pagination:
        - start_at: Offset for pagination (min: 0)
        - max_results: Results per page (min: 10, max: 100, adjusted automatically)

    Examples:
        # Get all active projects (default filters)
        list_projects(api_key, team_id)

        # Get web platform projects
        list_projects(api_key, team_id, platform="Web", platform_type="Web")

        # Search for projects with "mobile" in name
        list_projects(api_key, team_id, search_text="mobile")

        # Get archived Android app projects
        list_projects(api_key, team_id, platform="Android", platform_type="Apps", status="ARCHIVE")

        # Get only public projects
        list_projects(api_key, team_id, project_type="public")

        # Pagination: Get second page (results 10-20)
        list_projects(api_key, team_id, start_at=10, max_results=10)

        # Get projects created via API
        list_projects(api_key, team_id, source="API")
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    # Handle case where API might return a list instead of dict
    if isinstance(validation, list):
        return {'status': 'failed', 'error': 'Unexpected API response format', 'details': str(validation)}
    if not validation.get('valid'):
        return validation

    # Validate and normalize platform (case-sensitive)
    valid_platforms = ['ALL', 'Android', 'iOS', 'Desktop', 'Multiple', '']
    if platform not in valid_platforms:
        return {
            'status': 'failed',
            'error': f'Invalid platform value: "{platform}". Allowed values: {", ".join([v for v in valid_platforms if v != ""])}'
        }

    # Validate and normalize platform_type (case-sensitive)
    valid_platform_types = ['ALL', 'Apps', 'Mobileweb', 'Web', 'Multiple', '']
    if platform_type not in valid_platform_types:
        return {
            'status': 'failed',
            'error': f'Invalid platform_type value: "{platform_type}". Allowed values: {", ".join([v for v in valid_platform_types if v != ""])}'
        }

    # Normalize status (case-insensitive, convert to uppercase)
    status = status.upper()
    valid_statuses = ['ACTIVE', 'ARCHIVE', 'DELETED']
    if status not in valid_statuses:
        return {
            'status': 'failed',
            'error': f'Invalid status value. Allowed values (case-insensitive): {", ".join(valid_statuses)}'
        }

    # Normalize project_type (case-insensitive, convert to lowercase)
    project_type = project_type.lower()
    valid_project_types = ['all', 'contributed', 'private', 'public']
    if project_type not in valid_project_types:
        return {
            'status': 'failed',
            'error': f'Invalid project_type value. Allowed values (case-insensitive): {", ".join(valid_project_types)}'
        }

    # Build parameters with required fields
    params = {
        'team_id': team_id,
        'start_at': start_at,
        'max_results': max_results,
        'platform': platform,
        'platform_type': platform_type,
        'status': status,
        'project_type': project_type
    }

    # Add optional search and filter parameters if provided
    if search_text:
        params['search_text'] = search_text
    if source:
        params['source'] = source

    return make_api_request('GET', '/v1/projects/list', api_key, params=params)


@mcp.tool(
    name = "get_project_details",
    description = "Get detailed information about a specific project including workflow, tags, and settings."
)
def get_project_details(
    api_key: str = Field(description="User's Bugasura API key"),
    team_id: int = Field(description="Team identifier"),
    project_id: int = Field(description="Project identifier")
) -> dict:
    """Get detailed information about a specific project."""
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    return make_api_request('GET', '/v1/projects/get', api_key, params={'team_id': team_id, 'project_id': project_id})


@mcp.tool(
    name = "create_project",
    description = "Create a new project in a team. Projects organize test cases, issues, and sprints. Supports interactive team selection."
)
def create_project(
    api_key: str = Field(description="User's Bugasura API key"),
    project_name: str = Field(description="Project name (required)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    platform: str = Field(default="Multiple", description="Platform: 'Android', 'iOS', 'Desktop', 'API', 'Multiple' (default: Multiple)"),
    platform_type: str = Field(default="Multiple", description="Platform type: 'Apps', 'Mobileweb', 'Web', 'API', 'Multiple' (default: Multiple)"),
    is_public_project: bool = Field(default=False, description="Public visibility (default: False for private)"),
    is_public_issues: bool = Field(default=False, description="Allow public issue visibility (default: False)"),
    clean_public_project_name: str = Field(default="", description="Unique identifier for public projects (optional)")
) -> dict:
    """
    Create a new project in a team.

    Interactive flow: If team_id is not provided, this function
    will guide you through team selection.

    Args:
        api_key: User's Bugasura API key (required)
        project_name: Name for the new project (required)
        team_id: Team identifier (optional - will prompt if not provided)
        platform: Platform selection (default: Multiple)
        platform_type: Platform type (default: Multiple)
        is_public_project: Public visibility (default: False)
        is_public_issues: Public issue visibility (default: False)
        clean_public_project_name: Unique identifier for public projects (optional)

    Returns:
        dict: {
            'status': 'OK' | 'ERROR',
            'app_id': int,
            'project_name': str,
            'sprint_details': {...},
            'message': str
        }

    Note:
        - Creates a default sprint automatically
        - User must be team member to create projects
        - Team admins may have additional permissions
    """
    # Validate API key
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Validate project name
    if not project_name or len(project_name.strip()) == 0:
        return {
            'status': 'ERROR',
            'message': 'Project name is required'
        }

    # Interactive team selection if team_id not provided
    if team_id is None:
        teams_response = list_teams(api_key)
        if teams_response.get('status') != 'OK':
            return teams_response

        teams = teams_response.get('teams', [])
        if not teams:
            return {
                'status': 'ERROR',
                'message': 'No teams found. Please create a team first.'
            }

        # Return selection prompt
        return {
            'selection_required': True,
            'selection_type': 'team',
            'message': 'Please select a team for the new project',
            'options': [
                {
                    'team_id': team['team_id'],
                    'name': team['name'],
                    'role': 'Admin' if team.get('is_admin') else 'Member'
                }
                for team in teams
            ],
            'next_call': f'create_project with api_key, project_name="{project_name}", team_id=<selected_team_id>'
        }

    # Build API request data
    # Note: Use /projects/add endpoint (not /apps/add) - it has consistent snake_case naming
    data = {
        'team_id': team_id,
        'project_name': project_name.strip(),
        'platform': platform,
        'platform_type': platform_type,
        'source': 'API',  # Required field
        'is_public_project': 1 if is_public_project else 0,
        'is_public_issues': 1 if is_public_issues else 0
    }

    if clean_public_project_name:
        data['clean_public_project_name'] = clean_public_project_name.strip()

    logger.info(f"Creating project: {project_name} in team {team_id}")

    # Make API request
    result = make_api_request('POST', '/v1/projects/add', api_key, data=data)

    if result.get('status') == 'OK':
        logger.info(f"Successfully created project: {project_name} in team {team_id}")
    else:
        logger.error(f"Failed to create project: {result.get('message')}")

    return result


@mcp.tool(
    name = "update_project",
    description = "Update project details including name, issue prefix, and visibility settings. Supports project_id or project_name. Team admin privileges may be required."
)
def update_project(
    api_key: str = Field(description="User's Bugasura API key"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (provide either project_id or search_project_name)"),
    search_project_name: Optional[str] = Field(default=None, description="Project name to search for (provide either project_id or search_project_name)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    new_project_name: Optional[str] = Field(default=None, description="New project name (optional)"),
    issue_prefix: Optional[str] = Field(default=None, description="New issue prefix (e.g., 'BUG', 'ISS') (optional)"),
    is_public_project: Optional[bool] = Field(default=None, description="Public visibility (optional)"),
    clean_public_project_name: Optional[str] = Field(default=None, description="Unique identifier for public projects (optional)")
) -> dict:
    """
    Update project details.

    Interactive flow: If team_id is not provided, this function
    will guide you through team selection.

    Args:
        api_key: User's Bugasura API key (required)
        project_id: Project identifier (provide either project_id or search_project_name)
        search_project_name: Project name to search for (provide either project_id or search_project_name)
        team_id: Team identifier (optional - will prompt if not provided)
        new_project_name: New project name (optional)
        issue_prefix: New issue prefix (optional)
        is_public_project: Public visibility (optional)
        clean_public_project_name: Unique identifier for public projects (optional)

    Returns:
        dict: {
            'status': 'OK' | 'ERROR',
            'message': str
        }

    Note:
        - Only updates fields that are provided
        - Team admin privileges may be required
        - Issue prefix affects issue keys (e.g., BUG-123)
        - Supports both project_id and project_name for flexibility
    """
    # Validate API key
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Resolve project identifier (project_id or search_project_name)
    resolved_project_id = project_id
    resolved_team_id = team_id

    if not project_id and not search_project_name:
        return {
            'status': 'ERROR',
            'message': 'Either project_id or search_project_name must be provided'
        }

    # If search_project_name provided, resolve to project_id
    if search_project_name and not project_id:
        logger.info(f"Resolving project name: {search_project_name}")
        search_result = find_project_by_name(api_key, search_project_name)

        if search_result.get('status') != 'OK':
            return search_result

        matches = search_result.get('matches', [])
        if not matches:
            return {
                'status': 'ERROR',
                'message': f'No projects found matching "{search_project_name}"'
            }

        if len(matches) == 1:
            # Single match - use it
            resolved_project_id = matches[0]['project_id']
            resolved_team_id = matches[0]['team_id']
            logger.info(f"Resolved '{search_project_name}' to project_id={resolved_project_id}, team_id={resolved_team_id}")
        else:
            # Multiple matches - return selection prompt
            return {
                'status': 'ERROR',
                'message': f'Multiple projects found matching "{search_project_name}". Please provide more specific name or use project_id.',
                'matches': matches
            }

    # Interactive team selection if team_id not provided
    if resolved_team_id is None:
        teams_response = list_teams(api_key)
        if teams_response.get('status') != 'OK':
            return teams_response

        teams = teams_response.get('teams', [])
        if not teams:
            return {
                'status': 'ERROR',
                'message': 'No teams found.'
            }

        # Return selection prompt
        return {
            'selection_required': True,
            'selection_type': 'team',
            'message': 'Please select the team for this project',
            'options': [
                {
                    'team_id': team['team_id'],
                    'name': team['name'],
                    'role': 'Admin' if team.get('is_admin') else 'Member'
                }
                for team in teams
            ],
            'next_call': f'update_project with api_key, project_id={resolved_project_id}, team_id=<selected_team_id>, ...'
        }

    # Build API request with only provided fields
    data = {
        'team_id': resolved_team_id,
        'project_id': resolved_project_id
    }

    if new_project_name is not None:
        data['project_name'] = new_project_name.strip()

    if issue_prefix is not None:
        data['issue_prefix'] = issue_prefix.strip()

    if is_public_project is not None:
        data['is_public_project'] = 1 if is_public_project else 0

    if clean_public_project_name is not None:
        data['clean_public_project_name'] = clean_public_project_name.strip()

    # Note: The API accepts 'clean_public_project_name' (snake_case) as shown in updateProjectApi

    logger.info(f"Updating project {project_id} in team {team_id}")

    # Make API request
    # Note: Use /projects/update endpoint (not /apps/update which has a typo and calls non-existent function)
    result = make_api_request('POST', '/v1/projects/update', api_key, data=data)

    if result.get('status') == 'OK':
        logger.info(f"Successfully updated project {project_id} in team {team_id}")
    else:
        logger.error(f"Failed to update project: {result.get('message')}")

    return result


@mcp.tool(
    name = "delete_project",
    description = "Delete project permanently. WARNING: This deletes all associated sprints, issues, and test cases. Supports project_id or project_name. Team admin privileges required."
)
def delete_project(
    api_key: str = Field(description="User's Bugasura API key"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (provide either project_id or project_name)"),
    project_name: Optional[str] = Field(default=None, description="Project name to search for (provide either project_id or project_name)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)")
) -> dict:
    """
    Delete project permanently.

    WARNING: This is a destructive operation that permanently deletes:
    - The project itself
    - All sprints and test runs
    - All issues/bugs
    - All test cases
    - All project data

    Interactive flow: If team_id is not provided, this function
    will guide you through team selection.

    Args:
        api_key: User's Bugasura API key (required)
        project_id: Project identifier (provide either project_id or project_name)
        project_name: Project name to search for (provide either project_id or project_name)
        team_id: Team identifier (optional - will prompt if not provided)

    Returns:
        dict: {
            'status': 'OK' | 'ERROR',
            'message': str
        }

    Note:
        - Team admin privileges required
        - This operation cannot be undone
        - All data associated with the project will be permanently deleted
        - Supports both project_id and project_name for flexibility
    """
    # Validate API key
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Resolve project identifier (project_id or project_name)
    resolved_project_id = project_id
    resolved_team_id = team_id

    if not project_id and not project_name:
        return {
            'status': 'ERROR',
            'message': 'Either project_id or project_name must be provided'
        }

    # If project_name provided, resolve to project_id
    if project_name and not project_id:
        logger.info(f"Resolving project name for deletion: {project_name}")
        search_result = find_project_by_name(api_key, project_name)

        if search_result.get('status') != 'OK':
            return search_result

        matches = search_result.get('matches', [])
        if not matches:
            return {
                'status': 'ERROR',
                'message': f'No projects found matching "{project_name}"'
            }

        if len(matches) == 1:
            # Single match - use it
            resolved_project_id = matches[0]['project_id']
            resolved_team_id = matches[0]['team_id']
            logger.warning(f"Resolved '{project_name}' to project_id={resolved_project_id}, team_id={resolved_team_id} for deletion")
        else:
            # Multiple matches - return error with matches
            return {
                'status': 'ERROR',
                'message': f'Multiple projects found matching "{project_name}". Please provide more specific name or use project_id to avoid accidental deletion.',
                'matches': matches
            }

    # Interactive team selection if team_id not provided
    if resolved_team_id is None:
        teams_response = list_teams(api_key)
        if teams_response.get('status') != 'OK':
            return teams_response

        teams = teams_response.get('teams', [])
        if not teams:
            return {
                'status': 'ERROR',
                'message': 'No teams found.'
            }

        # Return selection prompt
        return {
            'selection_required': True,
            'selection_type': 'team',
            'message': 'WARNING: Select the team for the project you want to DELETE',
            'options': [
                {
                    'team_id': team['team_id'],
                    'name': team['name'],
                    'role': 'Admin' if team.get('is_admin') else 'Member'
                }
                for team in teams
            ],
            'next_call': f'delete_project with api_key, project_id={resolved_project_id}, team_id=<selected_team_id>'
        }

    # Build API request
    # Note: Use /projects/delete endpoint (not /apps/delete) - expects 'project_id'
    data = {
        'team_id': resolved_team_id,
        'project_id': resolved_project_id,
        'isDeleteApp': 1  # Required to actually delete (not just disable)
    }

    logger.warning(f"Deleting project {resolved_project_id} in team {resolved_team_id}")

    # Make API request
    result = make_api_request('POST', '/v1/projects/delete', api_key, data=data)

    if result.get('status') == 'OK':
        logger.warning(f"Project {resolved_project_id} in team {resolved_team_id} deleted successfully")
    else:
        logger.error(f"Failed to delete project: {result.get('message')}")

    return result



# ============================================================================
# SPRINT MANAGEMENT TOOLS
# ============================================================================
# Sprints (also called reports or test runs) organize issues and test cases
# for a specific release, iteration, or test cycle. All issues must belong
# to a sprint.
#
# IMPORTANT NAMING CONVENTION:
# - MCP tool parameters: use sprint_id (user-friendly)
# - Database: tbReports table uses report_id column (legacy naming)
# - Most API endpoints: accept sprint_id parameter
# - Some API endpoints: use report_id parameter (matches database column)
# - Comments added where parameter names differ from function parameters

@mcp.tool(
    name = "list_sprints",
    description = "List all sprints for a project. Supports interactive team/project selection if IDs not provided."
)
def list_sprints(
    api_key: str = Field(description="User's Bugasura API key"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)")
) -> dict:
    """
    List all sprints for a project.

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    Args:
        api_key: User's Bugasura API key (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)

    Returns:
        dict: List of sprints or selection prompt if context not provided
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = select_team_project_context(api_key, team_id, project_id, 'list_sprints')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Context validated - proceed with operation
    return make_api_request('GET', '/v1/sprints/list', api_key, params={
        'team_id': context['team_id'],
        'project_id': context['project_id']
    })


@mcp.tool(
    name = "get_sprint_details",
    description = "Get detailed sprint information and statistics. Supports interactive team/project selection."
)
def get_sprint_details(
    api_key: str = Field(description="User's Bugasura API key"),
    sprint_id: int = Field(description="Sprint identifier"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)")
) -> dict:
    """
    Get sprint details and statistics.

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    Args:
        api_key: User's Bugasura API key (required)
        sprint_id: Sprint identifier (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)

    Returns:
        dict: Sprint details or selection prompt if context not provided
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = select_team_project_context(api_key, team_id, project_id, 'get_sprint_details', f', sprint_id={sprint_id}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Context validated - proceed with operation
    return make_api_request('GET', '/v1/sprints/get', api_key, params={
        'team_id': context['team_id'],
        'project_id': context['project_id'],
        'sprint_id': sprint_id
    })


@mcp.tool(
    name = "create_sprint",
    description = "Create a new sprint for a project. Requires sprint_name (5-250 chars). Supports dates, duration, and status. Interactive team/project selection available."
)
def create_sprint(
    api_key: str = Field(description="User's Bugasura API key"),
    sprint_name: str = Field(description="Name of the sprint (5-250 characters required)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    start_date: Optional[str] = Field(default=None, description="Sprint start date in YYYY-MM-DD format (optional)"),
    end_date: Optional[str] = Field(default=None, description="Sprint end date in YYYY-MM-DD format (optional)"),
    duration: Optional[int] = Field(default=None, description="Sprint duration in days (optional)"),
    sprint_status: str = Field(default="IN PROGRESS", description="Sprint status: 'SCHEDULED', 'IN PROGRESS', 'CANCELLED', 'COMPLETED' (default: IN PROGRESS)")
) -> dict:
    """
    Create a new sprint for a project.

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    Args:
        api_key: User's Bugasura API key (required)
        sprint_name: Name of the sprint (5-250 characters required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        start_date: Sprint start date in YYYY-MM-DD format (optional)
        end_date: Sprint end date in YYYY-MM-DD format (optional)
        duration: Sprint duration in days (optional)
        sprint_status: Sprint status (default: IN PROGRESS)
            Allowed values: 'SCHEDULED', 'IN PROGRESS', 'CANCELLED', 'COMPLETED'

    Returns:
        dict: {
            'status': 'OK',
            'message': 'Sprint created successfully',
            'sprint_id': int,
            'project_id': int,
            'sprint_name': str,
            'project_name': str,
            'platform': str,
            'platform_type': str
        }

    Sprint Status Values:
        - 'SCHEDULED': Sprint is planned but not yet started
        - 'IN PROGRESS': Sprint is currently active (default)
        - 'CANCELLED': Sprint has been cancelled
        - 'COMPLETED': Sprint has been completed

    Date Format:
        - Dates must be in YYYY-MM-DD format (e.g., '2025-12-31')
        - start_date and end_date are optional
        - If provided, end_date should be after start_date

    Examples:
        # Create a sprint with default status (IN PROGRESS)
        create_sprint(api_key, team_id, project_id, "Sprint 1")

        # Create a scheduled sprint with dates
        create_sprint(api_key, team_id, project_id, "Sprint 2",
                     start_date="2025-12-01", end_date="2025-12-15",
                     sprint_status="SCHEDULED")

        # Create a sprint with duration
        create_sprint(api_key, team_id, project_id, "Sprint 3",
                     duration=14, sprint_status="IN PROGRESS")
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = select_team_project_context(api_key, team_id, project_id, 'create_sprint', f', sprint_name="{sprint_name}"')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Validate sprint_name length (backend requires 5-250 characters)
    if len(sprint_name) < 5:
        return {
            'status': 'failed',
            'error': f"Sprint name too short: '{sprint_name}' ({len(sprint_name)} characters)",
            'error_type': 'ValidationError',
            'message': 'Sprint name must be at least 5 characters long (5-250 characters required)'
        }
    if len(sprint_name) > 250:
        return {
            'status': 'failed',
            'error': f"Sprint name too long: {len(sprint_name)} characters",
            'error_type': 'ValidationError',
            'message': 'Sprint name must be at most 250 characters long (5-250 characters required)'
        }

    # Validate sprint_status
    allowed_statuses = ['SCHEDULED', 'IN PROGRESS', 'CANCELLED', 'COMPLETED']
    if sprint_status not in allowed_statuses:
        return {
            'status': 'failed',
            'error': f"Invalid sprint_status: '{sprint_status}'",
            'error_type': 'ValidationError',
            'message': f"sprint_status must be one of: {', '.join(allowed_statuses)}",
            'allowed_values': allowed_statuses
        }

    # Build payload with required fields
    # IDs and numeric values auto-converted to strings by make_api_request()
    payload = {
        "team_id": context['team_id'],
        "project_id": context['project_id'],
        "sprint_name": sprint_name,
        "sprint_status": sprint_status,
        "source": "API"
    }

    # Add optional date/duration fields if provided
    if start_date:
        payload["start_date"] = start_date
    if end_date:
        payload["end_date"] = end_date
    if duration:
        payload["duration"] = duration  # Will be converted to string
    return make_api_request('POST', '/v1/sprints/add', api_key, data=payload)


@mcp.tool(
    name = "update_sprint",
    description = "Update sprint details (partial updates supported). Can update name, dates, duration, or status. Interactive team/project selection available."
)
def update_sprint(
    api_key: str = Field(description="User's Bugasura API key"),
    sprint_id: int = Field(description="Sprint identifier"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    sprint_name: Optional[str] = Field(default=None, description="New sprint name (5-250 characters, optional)"),
    start_date: Optional[str] = Field(default=None, description="New start date in YYYY-MM-DD format (optional)"),
    end_date: Optional[str] = Field(default=None, description="New end date in YYYY-MM-DD format (optional)"),
    duration: Optional[int] = Field(default=None, description="New duration in days (optional)"),
    sprint_status: Optional[str] = Field(default=None, description="New status: 'SCHEDULED', 'IN PROGRESS', 'CANCELLED', 'COMPLETED' (optional)")
) -> dict:
    """
    Update an existing sprint.

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    Args:
        api_key: User's Bugasura API key (required)
        sprint_id: Sprint identifier to update (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        sprint_name: New sprint name (5-250 characters, optional)
        start_date: New start date in YYYY-MM-DD format (optional)
        end_date: New end date in YYYY-MM-DD format (optional)
        duration: New duration in days (optional)
        sprint_status: New sprint status (optional)
            Allowed values: 'SCHEDULED', 'IN PROGRESS', 'CANCELLED', 'COMPLETED'

    Returns:
        dict: {
            'status': 'OK',
            'message': 'Sprint updated successfully',
            ...
        }

    Sprint Status Values:
        - 'SCHEDULED': Sprint is planned but not yet started
        - 'IN PROGRESS': Sprint is currently active
        - 'CANCELLED': Sprint has been cancelled
        - 'COMPLETED': Sprint has been completed

    Examples:
        # Update sprint name
        update_sprint(api_key, team_id, sprint_id, sprint_name="Sprint 1 - Updated")

        # Change sprint status to completed
        update_sprint(api_key, team_id, sprint_id, sprint_status="COMPLETED")

        # Update dates and status
        update_sprint(api_key, team_id, sprint_id,
                     start_date="2025-12-01", end_date="2025-12-15",
                     sprint_status="IN PROGRESS")
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = select_team_project_context(api_key, team_id, project_id, 'update_sprint', f', sprint_id={sprint_id}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id
    team_id = context['team_id']

    # Validate sprint_name length if provided (backend requires 5-250 characters)
    if sprint_name is not None:
        if len(sprint_name) < 5:
            return {
                'status': 'failed',
                'error': f"Sprint name too short: '{sprint_name}' ({len(sprint_name)} characters)",
                'error_type': 'ValidationError',
                'message': 'Sprint name must be at least 5 characters long (5-250 characters required)'
            }
        if len(sprint_name) > 250:
            return {
                'status': 'failed',
                'error': f"Sprint name too long: {len(sprint_name)} characters",
                'error_type': 'ValidationError',
                'message': 'Sprint name must be at most 250 characters long (5-250 characters required)'
            }

    # Validate sprint_status if provided
    if sprint_status is not None:
        allowed_statuses = ['SCHEDULED', 'IN PROGRESS', 'CANCELLED', 'COMPLETED']
        if sprint_status not in allowed_statuses:
            return {
                'status': 'failed',
                'error': f"Invalid sprint_status: '{sprint_status}'",
                'error_type': 'ValidationError',
                'message': f"sprint_status must be one of: {', '.join(allowed_statuses)}",
                'allowed_values': allowed_statuses
            }

    # Step 1: Fetch existing sprint details to preserve unmodified fields
    logger.info(f"Fetching existing sprint details for sprint_id={sprint_id}")
    existing_sprint_response = make_api_request('GET', '/v1/sprints/list', api_key, params={
        'team_id': team_id,
        'project_id': context.get('project_id')  # Use project_id from context if available
    })

    # Find the specific sprint from the list
    sprint_data = None
    if existing_sprint_response.get('status') == 'OK':
        sprints_list = existing_sprint_response.get('sprintsList', [])
        for sprint in sprints_list:
            if sprint.get('sprint_id') == sprint_id:
                sprint_data = sprint
                break

    if not sprint_data:
        logger.warning(f"Could not fetch existing sprint data for sprint_id={sprint_id}, proceeding with only provided fields")
        sprint_data = {}

    logger.info(f"Fetched existing sprint data. Merging updates...")

    # Step 2: Build base payload with required fields
    # IDs will be auto-converted to strings by make_api_request()
    payload = {
        "team_id": team_id,
        "sprint_id": sprint_id
    }

    # Step 3: Build field mappings - use new value if provided, otherwise keep existing
    field_mappings = {
        'sprint_name': (sprint_name, sprint_data.get('sprint_name')),
        'start_date': (start_date, sprint_data.get('start_date')),
        'end_date': (end_date, sprint_data.get('end_date')),
        'duration': (duration, sprint_data.get('duration')),
        'sprint_status': (sprint_status, sprint_data.get('sprint_status'))
    }

    # Add fields to payload: use new value if provided, otherwise use existing
    for field_name, (new_value, existing_value) in field_mappings.items():
        if new_value is not None:
            payload[field_name] = new_value
            logger.debug(f"Updated field {field_name} with new value")
        elif existing_value is not None and existing_value != '':
            # Only include existing value if it's not empty
            payload[field_name] = existing_value
            logger.debug(f"Kept existing value for field {field_name}")

    logger.info(f"Sending update request for sprint_id={sprint_id} with {len(payload)} fields")
    return make_api_request('POST', '/v1/sprints/update', api_key, data=payload)


@mcp.tool(
    name = "delete_sprint",
    description = "Delete a sprint permanently by numeric ID or exact name match. Supports interactive team/project selection."
)
def delete_sprint(
    api_key: str = Field(description="User's Bugasura API key"),
    sprint_identifier: str = Field(description="Sprint identifier: numeric ID (e.g., '123') or exact sprint name (e.g., 'Sprint 15')"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)")
) -> dict:
    """
    Delete a sprint from a project by ID or name.

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    WARNING: This action cannot be undone. The sprint and all its associations
    will be permanently removed.

    Args:
        api_key: User's Bugasura API key (required)
        sprint_identifier: Sprint ID (numeric) or sprint name (string) to delete (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)

    Returns:
        dict: {
            'status': 'OK',
            'message': 'Sprint deleted successfully'
        }

    Examples:
        # Delete a sprint by ID
        delete_sprint(api_key, sprint_identifier="123", team_id=456, project_id=789)

        # Delete a sprint by name
        delete_sprint(api_key, sprint_identifier="Sprint 15", team_id=456, project_id=789)

        # Delete with interactive context selection
        delete_sprint(api_key, sprint_identifier="Sprint 15")
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = select_team_project_context(api_key, team_id, project_id, 'delete_sprint', f', sprint_identifier={sprint_identifier}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Resolve sprint_identifier to sprint_id
    sprint_id = None

    # Check if it's a numeric ID
    if sprint_identifier.isdigit():
        sprint_id = int(sprint_identifier)
        logger.info(f"delete_sprint: Using numeric sprint_id={sprint_id}")
    else:
        # It's a name - search for the sprint
        logger.info(f"delete_sprint: Searching for sprint by name: '{sprint_identifier}'")
        sprints_response = make_api_request('GET', '/v1/sprints/list', api_key, params={
            'team_id': str(team_id),
            'project_id': str(project_id)
        })

        if sprints_response.get('status') != 'OK':
            return {
                'status': 'failed',
                'error': 'Failed to fetch sprints',
                'message': sprints_response.get('message', 'Could not retrieve sprints list')
            }

        # Search for sprint by name (case-insensitive)
        sprints = sprints_response.get('sprintsList', [])
        matching_sprints = [s for s in sprints if s.get('sprint_name', '').lower() == sprint_identifier.lower()]

        if not matching_sprints:
            # Try partial match
            matching_sprints = [s for s in sprints if sprint_identifier.lower() in s.get('sprint_name', '').lower()]

        if not matching_sprints:
            return {
                'status': 'failed',
                'error': 'Sprint not found',
                'message': f"No sprint found with name '{sprint_identifier}' in project {project_id}"
            }

        if len(matching_sprints) > 1:
            sprint_list = '\n'.join([f"  - ID: {s['sprint_id']}, Name: {s['sprint_name']}" for s in matching_sprints])
            return {
                'status': 'failed',
                'error': 'Multiple sprints found',
                'message': f"Multiple sprints match '{sprint_identifier}'. Please use the sprint ID instead:\n{sprint_list}"
            }

        sprint_id = matching_sprints[0]['sprint_id']
        logger.info(f"delete_sprint: Found sprint '{sprint_identifier}' with ID {sprint_id}")

    # Build payload
    payload = {
        "team_id": team_id,
        "project_id": project_id,
        "sprint_id": sprint_id
    }

    logger.info(f"Deleting sprint_id={sprint_id} for team_id={team_id}, project_id={project_id}")
    return make_api_request('POST', '/v1/sprints/delete', api_key, data=payload)


# ============================================================================
# ISSUE/BUG MANAGEMENT TOOLS
# ============================================================================
# Issues (also called bugs or test results) are the core entities in Bugasura.
# They represent defects, feature requests, or test failures.

@mcp.tool(
    name = "create_issue",
    description = "Create a new issue/bug with required summary. Supports severity, status, environment details, tags, assignees, and custom fields. Interactive team/project/sprint selection available."
)
def create_issue(
    api_key: str = Field(description="User's Bugasura API key"),
    summary: str = Field(description="Issue summary/title (required)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (optional - will prompt if not provided)"),
    description: str = Field(default="", description="Detailed issue description (optional, supports HTML)"),
    severity: str = Field(default="MEDIUM", description="Severity: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW' (default: MEDIUM)"),
    status: str = Field(default="New", description="Status (default: New, must match project workflow)"),
    device_name: str = Field(default="", description="Device name for testing environment (optional)"),
    os_name: str = Field(default="", description="Operating system name (optional)"),
    os_version: str = Field(default="", description="OS version (optional)"),
    browser_name: str = Field(default="", description="Browser name (optional)"),
    browser_version: str = Field(default="", description="Browser version (optional)"),
    network_name: str = Field(default="", description="Network condition (optional)"),
    resolution: str = Field(default="", description="Screen resolution (optional)"),
    tags: str = Field(default="", description="Comma-separated tags (optional)"),
    issue_type: str = Field(default="", description="Issue type/category (optional)"),
    issue_assignees: str = Field(default="", description="Comma-separated assignee names, emails, or IDs (optional)"),
    is_public: str = Field(default="", description="Public visibility: 'true' or 'false' (optional)"),
    custom_fields: str = Field(default="", description="JSON string of custom field values (optional)")
) -> dict:
    """
    Create a new issue/bug in Bugasura.

    Interactive flow: If team_id/project_id/sprint_id are not provided, this function
    will return available options for the user to select from. The AI assistant will
    guide the user through the selection process.

    Args:
        api_key: User's Bugasura API key (required)
        summary: Issue title/summary (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        sprint_id: Sprint identifier (optional - will prompt if not provided)
        description: Detailed description of the issue
        severity: CRITICAL/HIGH/MEDIUM/LOW (default: MEDIUM)
        status: Issue status (default: "New")
        device_name: Device where issue was found (e.g., "iPhone 13")
        os_name: Operating system (e.g., "iOS", "Android", "Windows")
        os_version: OS version (e.g., "15.0")
        browser_name: Browser name (e.g., "Chrome", "Safari")
        browser_version: Browser version (e.g., "96.0")
        network_name: Network condition (e.g., "WiFi", "4G")
        resolution: Screen resolution (e.g., "1920x1080")
        tags: Comma-separated tags
        issue_type: Type of issue (e.g., "Functional", "UI")
        issue_assignees: Comma-separated user IDs
        is_public: "1" for public, "0" for private
        custom_fields: JSON string of custom field values

    Returns:
        dict: API response containing:
            - issue_key: Numeric ID (testresults_id)
            - issue_id: Human-readable ID (e.g., "JUS6")
            - status: "OK" or error status
        OR a selection prompt if team_id/project_id/sprint_id not provided
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper for team and project
    context = select_team_project_context(api_key, team_id, project_id, 'create_issue', f', summary="{summary}"')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Step 3: If sprint_id not provided, fetch and return sprint options for the selected project
    if sprint_id is None:
        # Call API directly instead of using the MCP tool function
        sprints_response = make_api_request('GET', '/v1/sprints/list', api_key, params={
            'team_id': team_id,
            'project_id': project_id
        })
        # Handle case where API might return a list instead of dict
        if isinstance(sprints_response, list):
            return {
                'status': 'failed',
                'error': 'Unexpected API response format (received list instead of dict)',
                'error_type': 'ResponseFormatError',
                'response_preview': str(sprints_response[:2]) if len(sprints_response) > 0 else 'Empty list'
            }
        if sprints_response.get('status') != 'OK':
            return sprints_response

        sprints = sprints_response.get('sprintsList', [])
        if not sprints:
            return {
                'status': 'failed',
                'error': 'No sprints found in the selected project. Please create a sprint first.',
                'suggestion': 'You can create a sprint using create_sprint() tool.'
            }

        # Filter active/in-progress sprints first for better UX
        active_sprints = [s for s in sprints if s.get('sprint_status') == 'IN PROGRESS']

        return {
            'status': 'selection_required',
            'step': 'sprint_selection',
            'message': 'Please select a sprint to create the issue in:',
            'options': [{
                'sprint_id': sprint['sprint_id'],
                'sprint_name': sprint['sprint_name'],
                'status': sprint.get('sprint_status', ''),
                'start_date': sprint.get('start_date', ''),
                'end_date': sprint.get('end_date', '')
            } for sprint in sprints],
            'active_sprints': [{
                'sprint_id': sprint['sprint_id'],
                'sprint_name': sprint['sprint_name']
            } for sprint in active_sprints] if active_sprints else None,
            'instruction': f'Please call create_issue again with sprint_id parameter. Example: create_issue(api_key="{api_key[:10]}...", team_id={team_id}, project_id={project_id}, sprint_id=<selected_sprint_id>, summary="{summary}")'
        }

    # All context parameters provided - proceed with issue creation

    # IMPORTANT: Validate that the sprint exists and belongs to this project
    # The backend will fail with "Error getting testplan report" if sprint_id is invalid
    logger.info(f"create_issue: Validating sprint_id={sprint_id} for project_id={project_id}")
    sprint_validation = make_api_request('GET', '/v1/sprints/list', api_key, params={
        'team_id': str(team_id),
        'project_id': str(project_id)
    })

    if sprint_validation.get('status') == 'OK':
        sprints = sprint_validation.get('sprintsList', [])
        # Check if the provided sprint_id exists in this project
        sprint_ids = [s.get('sprint_id') for s in sprints]
        if sprint_id not in sprint_ids:
            return {
                'status': 'failed',
                'error': 'Invalid sprint_id',
                'message': f"Sprint ID {sprint_id} does not exist in project {project_id}. Available sprint IDs: {sprint_ids[:10]}",
                'suggestion': 'Please verify the sprint_id belongs to the selected project.'
            }
        logger.info(f"create_issue: Sprint validation passed. Sprint {sprint_id} exists in project {project_id}")
    else:
        logger.warning(f"create_issue: Could not validate sprint (API error), proceeding anyway")

    # Build required fields payload
    # Note: IDs will be auto-converted to strings by make_api_request()
    payload = {
        "team_id": team_id,          # Integer ID (auto-converted to string for POST)
        "sprint_id": sprint_id,      # Required: Issues must belong to a sprint
        "summary": summary,           # Issue title - required field
        "description": description,   # Detailed description
        "severity": severity,         # CRITICAL/HIGH/MEDIUM/LOW
        "status": status,             # Current status (e.g., "New", "In Progress")
        "source": "API"               # Track that this issue came from API
    }

    # Build optional fields dictionary
    # These fields provide additional context about the issue
    optional = {
        'device_name': device_name,           # Test device information
        'os_name': os_name,                   # Operating system
        'os_version': os_version,             # OS version number
        'browser_name': browser_name,         # Browser for web issues
        'browser_version': browser_version,   # Browser version
        'network_name': network_name,         # Network conditions during test
        'resolution': resolution,             # Screen resolution
        'tags': tags,                         # Categorization tags
        'issue_type': issue_type,             # Issue classification
        'issue_assignees': issue_assignees,   # Assigned team members
        'is_public': is_public,               # Visibility setting
        'custom_fields': custom_fields        # Project-specific custom fields
    }

    # Add only non-empty optional fields to payload
    # This keeps the API request clean and avoids sending empty values
    payload.update({k: v for k, v in optional.items() if v})

    # Make POST request to create issue endpoint
    # data= parameter sends as form-encoded data (application/x-www-form-urlencoded)
    return make_api_request('POST', '/v1/issues/add', api_key, data=payload)


@mcp.tool(
    name = "get_issue",
    description = "Get detailed issue information by numeric ID. Returns full issue details including comments and attachments. Interactive team/project selection available."
)
def get_issue(
    api_key: str = Field(description="User's Bugasura API key"),
    issue_id: int = Field(description="Issue numeric ID (testresults_id)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)")
) -> dict:
    """
    Get issue details by numeric ID (testresults_id).

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    Args:
        api_key: User's Bugasura API key (required)
        issue_id: Issue numeric ID (testresults_id) (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)

    Returns:
        dict: Complete issue details including comments, attachments, history

    Note:
        Use list_issues() to find the issue_id if you don't know it.
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = select_team_project_context(api_key, team_id, project_id, 'get_issue', f', issue_id={issue_id}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # GET request - integers are fine (auto-converted to strings in URL)
    response = make_api_request('GET', '/v1/issues/get', api_key, params={
        'team_id': context['team_id'],
        'project_id': context['project_id'],
        'issue_key': issue_id
    })

    # Return full response for individual issue (including tools_integration_settings if needed)
    return response


@mcp.tool(
    name = "update_issue",
    description = "Update an existing issue (partial updates supported). Can update any field including summary, description, severity, status, tags, assignees, environment, and custom fields. Interactive selection available."
)
def update_issue(
    api_key: str = Field(description="User's Bugasura API key"),
    issue_id: int = Field(description="Issue numeric ID to update"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (optional)"),
    summary: Optional[str] = Field(default=None, description="New issue summary/title (optional)"),
    description: Optional[str] = Field(default=None, description="New description (optional, supports HTML)"),
    severity: Optional[str] = Field(default=None, description="New severity: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW' (optional)"),
    status: Optional[str] = Field(default=None, description="New status (optional, must match project workflow)"),
    tags: Optional[str] = Field(default=None, description="New tags, comma-separated (optional)"),
    issue_type: Optional[str] = Field(default=None, description="New issue type/category (optional)"),
    is_public: Optional[str] = Field(default=None, description="New public visibility: 'true' or 'false' (optional)"),
    device_name: Optional[str] = Field(default=None, description="New device name (optional)"),
    os_name: Optional[str] = Field(default=None, description="New OS name (optional)"),
    os_version: Optional[str] = Field(default=None, description="New OS version (optional)"),
    network_name: Optional[str] = Field(default=None, description="New network condition (optional)"),
    browser_name: Optional[str] = Field(default=None, description="New browser name (optional)"),
    browser_version: Optional[str] = Field(default=None, description="New browser version (optional)"),
    resolution: Optional[str] = Field(default=None, description="New screen resolution (optional)"),
    similar_issues: Optional[str] = Field(default=None, description="Related issue IDs, comma-separated (optional)"),
    custom_fields: Optional[str] = Field(default=None, description="JSON string of custom field updates (optional)"),
    project_testcase_ids: Optional[str] = Field(default=None, description="Linked test case IDs, comma-separated (optional)")
) -> dict:
    """
    Update an existing issue. Only updates the fields that are provided.

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    This function fetches the existing issue details first, then merges
    the updates with existing data to ensure all required fields (like report_id/sprint_id)
    are present.

    Args:
        api_key: User's Bugasura API key (required)
        issue_id: Issue numeric ID (testresults_id) (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        sprint_id: Sprint identifier (optional, to move issue to different sprint)
        summary: Issue title/summary (optional)
        description: Detailed description (optional)
        severity: CRITICAL/HIGH/MEDIUM/LOW (optional)
        status: Issue status (optional, e.g., "New", "In Progress", "Fixed")
        tags: Comma-separated tags (optional)
        issue_type: Type of issue (optional, e.g., "Functional", "UI")
        is_public: "1" for public, "0" for private (optional)
        device_name: Device name (optional)
        os_name: Operating system (optional)
        os_version: OS version (optional)
        network_name: Network condition (optional)
        browser_name: Browser name (optional)
        browser_version: Browser version (optional)
        resolution: Screen resolution (optional)
        similar_issues: Similar issue IDs (optional)
        custom_fields: JSON string of custom field values (optional)
        project_testcase_ids: Linked test case IDs (optional)

    Returns:
        dict: API response with update status

    Examples:
        # Update only the summary
        update_issue(api_key, team_id, issue_id, project_id,
                    summary="Updated issue title")

        # Update severity and status
        update_issue(api_key, team_id, issue_id, project_id,
                    severity="HIGH", status="In Progress")

        # Move issue to different sprint
        update_issue(api_key, team_id, issue_id, project_id,
                    sprint_id=456)
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = select_team_project_context(api_key, team_id, project_id, 'update_issue', f', issue_id={issue_id}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Step 1: Fetch existing issue details to get required fields like report_id
    logger.info(f"Fetching existing issue details for issue_id={issue_id}")
    existing_issue_response = make_api_request('GET', '/v1/issues/get', api_key, params={
        'team_id': team_id,
        'project_id': project_id,
        'issue_key': issue_id
    })

    # Handle case where API might return a list instead of dict
    if isinstance(existing_issue_response, list):
        return {
            'status': 'failed',
            'error': 'Unexpected API response format (received list instead of dict)',
            'error_type': 'ResponseFormatError',
            'response_preview': str(existing_issue_response[:2]) if len(existing_issue_response) > 0 else 'Empty list'
        }

    # Check if fetch was successful
    if existing_issue_response.get('status') == 'failed':
        logger.error(f"Failed to fetch existing issue: {existing_issue_response.get('error')}")
        return {
            'status': 'failed',
            'error': 'Could not fetch existing issue details',
            'error_type': 'IssueFetchError',
            'message': f"Unable to update issue. Error: {existing_issue_response.get('message', 'Unknown error')}",
            'details': existing_issue_response
        }

    # Step 2: Extract existing issue data
    issue_data = existing_issue_response.get('issue_details', {})

    # Handle case where issue_details is a list instead of dict
    if isinstance(issue_data, list):
        if len(issue_data) > 0:
            issue_data = issue_data[0]
            logger.info(f"Converted issue_details list to dict")
        else:
            issue_data = {}
            logger.warning(f"issue_details was empty list, using empty dict")

    if not issue_data:
        logger.error(f"No issue data found for issue_id={issue_id}")
        return {
            'status': 'failed',
            'error': 'Issue not found',
            'error_type': 'IssueNotFound',
            'message': f"Issue with ID {issue_id} not found"
        }

    logger.info(f"Fetched existing issue data. Merging updates...")

    # Step 3: Build base payload with required fields
    # IDs will be auto-converted to strings by make_api_request()
    payload = {
        "issue_key": issue_id,
        "team_id": team_id,
        "source": "API"
    }

    # Step 4: Get sprint_id - REQUIRED by backend for update
    # The backend always requires sprint_id to fetch and update the issue
    if sprint_id is not None:
        # User wants to move issue to a different sprint
        payload['sprint_id'] = sprint_id
        logger.info(f"Moving issue to sprint_id={sprint_id}")
    elif 'sprint_id' in issue_data and issue_data['sprint_id']:
        # Auto-fetch from existing issue - keep issue in current sprint
        payload['sprint_id'] = issue_data['sprint_id']
        logger.debug(f"Auto-fetched sprint_id from existing issue: {issue_data['sprint_id']}")
    else:
        # Issue has no sprint - backend still requires sprint_id for validation
        logger.error(f"Issue {issue_id} has no sprint_id - cannot update")
        return {
            'status': 'failed',
            'error': 'Issue has no sprint assigned',
            'error_type': 'MissingSprintError',
            'message': 'Cannot update issue: Issue must be assigned to a sprint. The backend requires sprint_id to update issues.'
        }

    # Step 5: Build optional fields with smart merging
    # Use provided value if not None, otherwise keep existing value
    field_mappings = {
        'summary': (summary, issue_data.get('reason')),
        'description': (description, issue_data.get('bug_description')),
        'severity': (severity, issue_data.get('severity')),
        'status': (status, issue_data.get('bug_status')),
        'tags': (tags, issue_data.get('tags')),
        'issue_type': (issue_type, issue_data.get('bug_types')),
        'is_public': (is_public, issue_data.get('is_public')),
        'device_name': (device_name, issue_data.get('device_name')),
        'os_name': (os_name, issue_data.get('os_name')),
        'os_version': (os_version, issue_data.get('os_version')),
        'network_name': (network_name, issue_data.get('network_name')),
        'browser_name': (browser_name, issue_data.get('browser_name')),
        'browser_version': (browser_version, issue_data.get('browser_version')),
        'resolution': (resolution, issue_data.get('resolution')),
        'similar_issues': (similar_issues, None),  # No existing field mapping
        'custom_fields': (custom_fields, None),  # No existing field mapping
        'project_testcase_ids': (project_testcase_ids, None)  # No existing field mapping
    }

    # Add fields to payload: use new value if provided, otherwise use existing
    for field_name, (new_value, existing_value) in field_mappings.items():
        if new_value is not None:
            payload[field_name] = new_value
            logger.debug(f"Updated field {field_name} with new value")
        elif existing_value is not None and existing_value != '':
            # Only include existing value if it's not empty
            payload[field_name] = existing_value
            logger.debug(f"Kept existing value for field {field_name}")

    # Step 6: Make the update request
    logger.info(f"Sending update request for issue_id={issue_id} with {len(payload)} fields")
    return make_api_request('POST', '/v1/issues/update', api_key, data=payload)


@mcp.tool(
    name = "delete_issue",
    description = "Delete an issue permanently by numeric ID, issue key (e.g., 'ISS09'), or exact/partial summary match. Uses 3-step matching: exact key → exact summary → partial summary. Interactive selection available."
)
def delete_issue(
    api_key: str = Field(description="User's Bugasura API key"),
    issue_identifier: str = Field(description="Issue identifier: numeric ID (e.g., '123'), issue key (e.g., 'ISS09'), or summary text for matching"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (optional - narrows search scope)")
) -> dict:
    """
    Delete an issue/bug from Bugasura by ID, issue key, or summary/title.

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    WARNING: This action cannot be undone. The issue and all its data
    (comments, attachments, history) will be permanently removed.

    Args:
        api_key: User's Bugasura API key (required)
        issue_identifier: Issue ID (numeric), issue key (e.g., "ISS09"), or issue summary/title (string) to delete (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        sprint_id: Sprint identifier to narrow search (optional, helps when searching by name)

    Returns:
        dict: {
            'status': 'OK',
            'message': 'Issue deleted successfully'
        }

    Examples:
        # Delete an issue by numeric ID
        delete_issue(api_key, issue_identifier="123", team_id=456, project_id=789)

        # Delete an issue by issue key
        delete_issue(api_key, issue_identifier="ISS09", team_id=456, project_id=789)

        # Delete an issue by summary
        delete_issue(api_key, issue_identifier="Login button not working", team_id=456, project_id=789)

        # Delete with sprint context
        delete_issue(api_key, issue_identifier="Login bug", sprint_id=5)

        # Delete with interactive context selection
        delete_issue(api_key, issue_identifier="ISS09")
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    # Handle case where API might return a list instead of dict
    if isinstance(validation, list):
        return {'status': 'failed', 'error': 'Unexpected API response format', 'details': str(validation)}
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = select_team_project_context(api_key, team_id, project_id, 'delete_issue', f', issue_identifier={issue_identifier}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Resolve issue_identifier to issue_id
    issue_id = None

    # Check if it's a numeric ID
    if issue_identifier.isdigit():
        issue_id = int(issue_identifier)
        logger.info(f"delete_issue: Using numeric issue_id={issue_id}")
    else:
        # It could be an issue key (e.g., "ISS09") or a summary/title - search for it
        logger.info(f"delete_issue: Searching for issue by key or summary: '{issue_identifier}'")

        params = {
            'team_id': str(team_id),
            'project_id': str(project_id),
            'start_at': 0,
            'max_results': 100  # Get more results for better matching
        }

        if sprint_id:
            params['sprint_id'] = str(sprint_id)

        issues_response = make_api_request('GET', '/v1/issues/list', api_key, params=params)

        if issues_response.get('status') != 'OK':
            return {
                'status': 'failed',
                'error': 'Failed to fetch issues',
                'message': issues_response.get('message', 'Could not retrieve issues list')
            }

        issues = issues_response.get('issues', [])

        # Step 1: Try exact match by issue key (case-insensitive)
        # Issue keys are usually in format like "ISS09", "BUG123", etc.
        matching_issues = [i for i in issues if i.get('issue_id', '').upper() == issue_identifier.upper()]

        if matching_issues:
            logger.info(f"delete_issue: Found issue by issue key: {matching_issues[0].get('issue_id')}")
        else:
            # Step 2: Try exact match by summary (case-insensitive)
            matching_issues = [i for i in issues if i.get('reason', '').lower() == issue_identifier.lower()]

            if not matching_issues:
                # Step 3: Try partial match by summary
                matching_issues = [i for i in issues if issue_identifier.lower() in i.get('reason', '').lower()]

        if not matching_issues:
            return {
                'status': 'failed',
                'error': 'Issue not found',
                'message': f"No issue found with key or summary '{issue_identifier}' in project {project_id}"
            }

        if len(matching_issues) > 1:
            issue_list = '\n'.join([f"  - ID: {i['testresults_id']}, Key: {i.get('issue_id', 'N/A')}, Summary: {i['reason']}" for i in matching_issues[:10]])
            return {
                'status': 'failed',
                'error': 'Multiple issues found',
                'message': f"Multiple issues match '{issue_identifier}'. Please use the issue ID or unique issue key instead:\n{issue_list}"
            }

        issue_id = matching_issues[0]['testresults_id']
        logger.info(f"delete_issue: Found issue '{issue_identifier}' with ID {issue_id}")

    # Build payload
    payload = {
        "team_id": team_id,
        "issue_key": issue_id
    }

    logger.info(f"Deleting issue_id={issue_id} for team_id={team_id}, project_id={project_id}")
    return make_api_request('POST', '/v1/issues/delete', api_key, data=payload)


@mcp.tool(
    name = "list_issues",
    description = "List issues for a project with optional sprint filter and pagination. Returns issue summaries with key details. Interactive team/project selection available."
)
def list_issues(
    api_key: str = Field(description="User's Bugasura API key"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier to filter issues (optional)"),
    start_at: int = Field(default=0, description="Pagination offset (default: 0)"),
    max_results: int = Field(default=10, description="Number of results to return (default: 10)")
) -> dict:
    """
    List issues for a project with optional sprint filter and pagination.

    Interactive flow: If team_id/project_id are not provided, this function
    will return available options for the user to select from.

    Args:
        api_key: User's Bugasura API key (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        sprint_id: Optional sprint ID to filter issues by sprint
        start_at: Pagination offset (default: 0)
        max_results: Number of results to return (default: 10, min: 10, max: 100)

    Returns:
        dict: List of issues with pagination metadata
        OR a selection prompt if team_id/project_id not provided
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = select_team_project_context(api_key, team_id, project_id, 'list_issues')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # All required parameters provided - proceed with listing issues
    params = {"team_id": context['team_id'], "project_id": context['project_id'], "start_at": start_at, "max_results": max_results}
    if sprint_id:
        params["sprint_id"] = sprint_id

    response = make_api_request('GET', '/v1/issues/list', api_key, params=params)

    # Filter out large unnecessary fields to reduce payload size
    return filter_large_fields(response)

# ============================================================================
# ISSUE COMMENTS MANAGEMENT TOOLS
# ============================================================================
# Functions for managing comments on issues

@mcp.tool(
    name="list_issue_comments",
    description="List all comments for a specific issue. Returns comment history with user details, timestamps, and content. Supports interactive team/project/issue selection."
)
def list_issue_comments(
    api_key: str = Field(description="User's Bugasura API key"),
    issue_id: Optional[int] = Field(default=None, description="Issue numeric ID (optional - will prompt if not provided)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    creator_id: Optional[int] = Field(default=None, description="Filter by comment author ID (optional)"),
    get_user_comments_only: bool = Field(default=False, description="If True, return only user comments (exclude system comments)"),
    start_at: int = Field(default=0, description="Pagination offset (default: 0)"),
    max_results: int = Field(default=10, description="Number of results to return (10-100, default: 10)")
) -> dict:
    """
    List all comments for a specific issue with pagination and filtering.
    Interactive flow: If team_id/project_id/issue_id are not provided, this function
    will guide you through selection:
    1. Select team (if not provided)
    2. Select project (if not provided)
    3. Select issue (if not provided)
    Args:
        api_key: User's Bugasura API key (required)
        issue_id: Issue numeric ID (testresults_id) (optional - will prompt if not provided)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        creator_id: Filter by comment author ID (optional)
        get_user_comments_only: Exclude system comments (default: False)
        start_at: Pagination offset (default: 0)
        max_results: Results per page, max 100 (default: 10)
    Returns:
        dict: {
            'status': 'OK',
            'comment_list': [
                {
                    'comment_id': int,
                    'comment': str,
                    'plain_text_comment': str,
                    'user_name': str,
                    'user_email': str,
                    'created_date': str,
                    'last_modified': str,
                    'is_system_comment': int,
                    ...
                },
                ...
            ],
            'total_comments': int,
            'nrows': int,
            'start_at': int,
            'max_results': int
        }
    Examples:
        # List comments with all context provided
        list_issue_comments(api_key, issue_id=123, team_id=456, project_id=789)
        # With pagination
        list_issue_comments(api_key, issue_id=123, team_id=456, project_id=789, start_at=10, max_results=20)
        # Filter by author and exclude system comments
        list_issue_comments(api_key, issue_id=123, team_id=456, project_id=789, creator_id=99, get_user_comments_only=True)
        # Interactive mode - will prompt for selections
        list_issue_comments(api_key)
        # Partial context - will prompt for missing info
        list_issue_comments(api_key, team_id=456)
    Note:
        System comments are auto-generated (status changes, assignments, etc.).
        Set get_user_comments_only=True to exclude them.
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Step 1 & 2: Use centralized context selection helper for team and project
    context = select_team_project_context(api_key, team_id, project_id, 'list_issue_comments')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Step 3: If issue_id not provided, fetch and return issue options
    if issue_id is None:
        logger.info(f"list_issue_comments: No issue_id provided, fetching issues for project_id={project_id}")

        # Fetch issues for the selected project
        issues_response = make_api_request('GET', '/v1/issues/list', api_key, params={
            'team_id': team_id,
            'project_id': project_id,
            'start_at': 0,
            'max_results': 50  # Get enough issues for selection
        })

        if issues_response.get('status') != 'OK':
            return issues_response

        issues = issues_response.get('issue_list', [])

        if not issues:
            return {
                'status': 'failed',
                'error': 'No issues found in the selected project.',
                'suggestion': 'Please create an issue first using create_issue() tool.'
            }

        return {
            'status': 'selection_required',
            'step': 'issue_selection',
            'message': 'Please select an issue to view comments:',
            'options': [{
                'issue_id': issue['issue_key'],
                'issue_key': issue.get('issue_id', 'N/A'),
                'summary': issue['summary'],
                'status': issue.get('bug_status', ''),
                'severity': issue.get('severity', ''),
                'assignees': issue.get('assignees', '')
            } for issue in issues[:20]],  # Show top 20 issues
            'instruction': f'Please call list_issue_comments again with issue_id parameter. Example: list_issue_comments(api_key="{api_key[:10]}...", team_id={team_id}, project_id={project_id}, issue_id=<selected_issue_id>)'
        }

    # All context parameters provided - proceed with fetching comments
    logger.info(f"list_issue_comments: Fetching comments for issue_id={issue_id}, team_id={team_id}, project_id={project_id}")

    # API parameters for listing comments
    params = {
        'team_id': team_id,
        'project_id': project_id,
        'issue_key': issue_id,
        'start_at': start_at,
        'max_results': min(max_results, 100)  # Cap at 100 per backend spec
    }

    # Add optional filter parameters
    if creator_id:
        params['creator_id'] = creator_id
    if get_user_comments_only:
        params['get_user_comments_only'] = 1

    # Make API request to get comments list
    response = make_api_request('GET', '/v1/issues/comments/list', api_key, params=params)

    # Add helpful information to response
    if response.get('status') == 'OK':
        comments = response.get('comment_list', [])
        response['total_comments'] = len(comments)
        logger.info(f"list_issue_comments: Retrieved {len(comments)} comments for issue {issue_id}")
    else:
        logger.error(f"list_issue_comments: Failed to fetch comments: {response.get('message')}")

    return filter_large_fields(response)


@mcp.tool(
    name="get_issue_comment",
    description="Get details of a specific comment by comment ID. Returns full comment data including text, user info, and timestamps. Supports interactive team/project/issue selection."
)
def get_issue_comment(
    api_key: str = Field(description="User's Bugasura API key"),
    comment_id: Optional[int] = Field(default=None, description="Comment numeric ID (optional - will prompt if not provided)"),
    issue_id: Optional[int] = Field(default=None, description="Issue numeric ID (optional - will prompt if not provided)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)")
) -> dict:
    """
    Get details of a specific comment.
    Interactive flow: If team_id/project_id/issue_id are not provided, this function
    will guide you through selection:
    1. Select team (if not provided)
    2. Select project (if not provided)
    3. Select issue (if not provided)
    Args:
        api_key: User's Bugasura API key (required)
        comment_id: Comment identifier (required)
        issue_id: Issue numeric ID (testresults_id) (optional - will prompt if not provided)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
    Returns:
        dict: {
            'status': 'OK',
            'comment_details': {
                'comment_id': int,
                'comment_text': str,
                'user_id': int,
                'user_name': str,
                'user_email': str,
                'created_at': str,
                'updated_at': str,
                'is_edited': bool,
                ...
            }
        }
    Examples:
        # Get comment with all context provided
        get_issue_comment(api_key, comment_id=789, issue_id=123, team_id=456, project_id=789)
        # Interactive mode - will prompt for selections
        get_issue_comment(api_key, comment_id=789)
        # Partial context - will prompt for missing info
        get_issue_comment(api_key, comment_id=789, team_id=456)
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Step 1 & 2: Use centralized context selection helper for team and project
    context = select_team_project_context(api_key, team_id, project_id, 'get_issue_comment', f', comment_id={comment_id}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Step 3: If issue_id not provided, fetch and return issue options
    if issue_id is None:
        logger.info(f"get_issue_comment: No issue_id provided, fetching issues for project_id={project_id}")

        # Fetch issues for the selected project
        issues_response = make_api_request('GET', '/v1/issues/list', api_key, params={
            'team_id': team_id,
            'project_id': project_id,
            'start_at': 0,
            'max_results': 50  # Get enough issues for selection
        })

        if issues_response.get('status') != 'OK':
            return issues_response

        issues = issues_response.get('issue_list', [])


        if not issues:
            return {
                'status': 'failed',
                'error': 'No issues found in the selected project.',
                'suggestion': 'Please create an issue first using create_issue() tool.'
            }

        return {
            'status': 'selection_required',
            'step': 'issue_selection',
            'message': f'Please select an issue to get comment {comment_id} from:',
            'options': [{
                'issue_id': issue['issue_key'],
                'issue_key': issue.get('issue_id', 'N/A'),
                'summary': issue['summary'],
                'status': issue.get('bug_status', ''),
                'severity': issue.get('severity', ''),
                'assignees': issue.get('assignees', '')
            } for issue in issues[:20]],  # Show top 20 issues
            'instruction': f'Please call get_issue_comment again with issue_id parameter. Example: get_issue_comment(api_key="{api_key[:10]}...", comment_id={comment_id}, team_id={team_id}, project_id={project_id}, issue_id=<selected_issue_id>)'
        }

    # All context parameters provided - proceed with fetching comment
    logger.info(f"get_issue_comment: Fetching comment_id={comment_id} for issue_id={issue_id}, team_id={team_id}, project_id={project_id}")

    # API parameters for getting specific comment
    params = {
        'team_id': team_id,
        'project_id': project_id,
        'issue_key': issue_id,
        'comment_id': comment_id
    }

    # Make API request to get comment details
    response = make_api_request('GET', '/v1/issues/comments/get', api_key, params=params)

    # Add helpful information to response
    if response.get('status') == 'OK':
        logger.info(f"get_issue_comment: Successfully retrieved comment {comment_id}")
    else:
        logger.error(f"get_issue_comment: Failed to fetch comment: {response.get('message')}")

    return response

@mcp.tool(
    name="add_issue_comment",
    description="Add a comment to an issue. Supports text comments with optional attachments and mentions. Interactive team/project/issue selection available."
)
def add_issue_comment(
    api_key: str = Field(description="User's Bugasura API key"),
    comment: str = Field(description="Comment text content (required, 1-65535 characters, supports HTML)"),
    issue_id: Optional[int] = Field(default=None, description="Issue numeric ID (optional - will prompt if not provided)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    is_public_comment: int = Field(default=1, description="Comment visibility: 1 for public (default), 0 for private"),
    source: str = Field(default="API", description="Comment source (default: API)")
) -> dict:
    """
    Add a comment to an issue with support for mentions and formatting.
    Interactive flow: If team_id/project_id/issue_id are not provided, this function
    will guide you through selection:
    1. Select team (if not provided)
    2. Select project (if not provided)
    3. Select issue (if not provided)
    The comment text supports:
    - Plain text
    - HTML formatting (automatically wrapped in <p> tags by API)
    - User mentions (use @username format, will be validated against team members)
    - Line breaks and paragraphs
    Args:
        api_key: User's Bugasura API key (required)
        comment: Comment text content (required, 1-65535 characters)
                 - Supports HTML formatting
                 - Use @username to mention team members
                 - Will be automatically HTML-encoded by API for security
        issue_id: Issue numeric ID (testresults_id) (optional - will prompt if not provided)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        is_public_comment: Comment visibility (default: 1)
                          - 1: Public comment (visible to all team members and guests)
                          - 0: Private comment (visible only to team members)
        source: Comment source tracking (default: "API")
                Common values: "API", "PLATFORM", "EXTENSION", "IMPORT"
    Returns:
        dict: {
            'status': 'OK',
            'message': 'Issue comment added successfully',
            'comment_id': int,              # ID of created comment
            'created_date': str,            # ISO timestamp
            'comment': str,                 # Full HTML comment
            'plain_text_comment': str,      # Plain text version
            'is_system_comment': 0,         # Always 0 for user comments
            'is_public_comment': int        # Visibility flag (0 or 1)
        }
    Error Responses:
        - Validation errors: Invalid parameters (comment too short/long, invalid IDs)
        - Permission errors: User not authorized to comment on issue
        - Not found errors: Issue, team, or project doesn't exist
    Examples:
        # Simple comment with all context provided
        add_issue_comment(
            api_key,
            comment="Fixed the login issue",
            issue_id=123,
            team_id=456,
            project_id=789
        )
        # Comment with HTML formatting
        add_issue_comment(
            api_key,
            comment="<strong>Important:</strong> This needs immediate attention",
            issue_id=123,
            team_id=456,
            project_id=789
        )
        # Comment with user mention
        add_issue_comment(
            api_key,
            comment="@John Doe please review this fix",
            issue_id=123,
            team_id=456,
            project_id=789
        )
        # Private comment (visible only to team members)
        add_issue_comment(
            api_key,
            comment="Internal note: Check with client before deploying",
            issue_id=123,
            team_id=456,
            project_id=789,
            is_public_comment=0
        )
        # Interactive mode - will prompt for selections
        add_issue_comment(api_key, comment="Great work!")
        # Partial context - will prompt for missing info
        add_issue_comment(
            api_key,
            comment="Looks good to me",
            team_id=456
        )
    Notes:
        - Comment text is required and must be 1-65535 characters
        - API automatically wraps plain text in <p> tags and HTML-encodes it
        - User mentions (@username) trigger email notifications
        - Comments can trigger Slack notifications if configured
        - System validates user permissions before adding comment
        - For public issues, guest creators can add comments
        - Private comments are only visible to team members
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Validate comment length (backend requires 1-65535 characters)
    if not comment or not comment.strip():
        return {
            'status': 'failed',
            'error': 'Comment text is required',
            'error_type': 'ValidationError',
            'message': 'Comment cannot be empty. Please provide comment text (1-65535 characters).'
        }

    comment_length = len(comment.strip())
    if comment_length < 1:
        return {
            'status': 'failed',
            'error': 'Comment too short',
            'error_type': 'ValidationError',
            'message': 'Comment must be at least 1 character long'
        }

    if comment_length > 65535:
        return {
            'status': 'failed',
            'error': f'Comment too long: {comment_length} characters',
            'error_type': 'ValidationError',
            'message': f'Comment must be at most 65535 characters (current: {comment_length})'
        }

    # Step 1 & 2: Use centralized context selection helper for team and project
    context = select_team_project_context(
        api_key, team_id, project_id, 
        'add_issue_comment', 
        f', comment="{comment[:50]}..."'  # Show truncated comment in instruction
    )

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Step 3: If issue_id not provided, fetch and return issue options
    if issue_id is None:
        logger.info(f"add_issue_comment: No issue_id provided, fetching issues for project_id={project_id}")

        # Fetch issues for the selected project
        issues_response = make_api_request('GET', '/v1/issues/list', api_key, params={
            'team_id': team_id,
            'project_id': project_id,
            'start_at': 0,
            'max_results': 50  # Get enough issues for selection
        })

        if issues_response.get('status') != 'OK':
            return issues_response

        issues = issues_response.get('issue_list', [])
        if not issues:
            return {
                'status': 'failed',
                'error': 'No issues found in the selected project',
                'suggestion': 'Please create an issue first using create_issue() tool.'
            }

        # Return issue selection prompt with preview of comment
        return {
            'status': 'selection_required',
            'step': 'issue_selection',
            'message': f'Please select an issue to add this comment: "{comment[:100]}..."',
            'options': [{
                'issue_id': issue['issue_key'],
                'issue_key': issue.get('issue_id', 'N/A'),
                'summary': issue['summary'],
                'status': issue.get('bug_status', ''),
                'severity': issue.get('severity', ''),
                'assignees': issue.get('assignees', ''),
                'comment_count': issue.get('comments_count', 0)
            } for issue in issues[:20]],  # Show top 20 issues
            'instruction': f'Please call add_issue_comment again with issue_id parameter. Example: add_issue_comment(api_key="{api_key[:10]}...", comment="{comment[:30]}...", team_id={team_id}, project_id={project_id}, issue_id=<selected_issue_id>)'
        }

    # All context parameters provided - proceed with adding comment
    logger.info(f"add_issue_comment: Adding comment to issue_id={issue_id}, team_id={team_id}, project_id={project_id}")

    # Validate is_public_comment value
    if is_public_comment not in [0, 1]:
        return {
            'status': 'failed',
            'error': 'Invalid is_public_comment value',
            'error_type': 'ValidationError',
            'message': 'is_public_comment must be 0 (private) or 1 (public)'
        }

    # Build payload matching API expectations
    # IDs will be auto-converted to strings by make_api_request()
    # NOTE: API parameter name is 'issue_key' (not 'issue_id')
    payload = {
        "issue_key": issue_id,           # API expects 'issue_key' for the issue ID
        "team_id": team_id,              # Team identifier
        "comment": comment,              # Comment text (will be HTML-encoded by API)
        "is_public_comment": is_public_comment,  # Visibility flag
        "source": source                 # Source tracking
    }

    # Make POST request to create comment endpoint
    logger.info(f"add_issue_comment: Sending request with {len(comment)} character comment, is_public={is_public_comment}")
    response = make_api_request('POST', '/v1/issues/comments/add', api_key, data=payload)

    # Add helpful information to response
    if response.get('status') == 'OK':
        logger.info(f"add_issue_comment: Successfully added comment to issue {issue_id}, comment_id={response.get('comment_id')}")

        # Enhance response with helpful metadata
        response['comment_length'] = len(comment)
        response['visibility'] = 'Public' if is_public_comment else 'Private'

        # Log if comment contains potential mentions
        if '@' in comment:
            mentioned_users = [word for word in comment.split() if word.startswith('@')]
            if mentioned_users:
                logger.info(f"add_issue_comment: Comment contains potential user mentions: {mentioned_users}")
                response['mentioned_users'] = mentioned_users
    else:
        logger.error(f"add_issue_comment: Failed to add comment: {response.get('message')}")

    return response

@mcp.tool(
    name="update_issue_comment",
    description="Update an existing issue comment. Supports full interactive selection - prompts for team/project/issue/comment if not provided. Guides user through entire flow."
)
def update_issue_comment(
    api_key: str = Field(description="User's Bugasura API key"),
    comment: str = Field(default="", description="Updated comment text (required when comment_id provided, 1-65535 characters, supports HTML)"),
    comment_id: Optional[int] = Field(default=None, description="Comment numeric ID to update (optional - will prompt if not provided)"),
    issue_id: Optional[int] = Field(default=None, description="Issue numeric ID (optional - will prompt if not provided)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    comment_attachment_names: str = Field(default="", description="Comma-separated attachment filenames (optional, preserves existing if empty)")
) -> dict:
    """
    Update an existing issue comment with full interactive flow.
    Interactive flow (prompts for missing context):
    1. Select team (if team_id not provided)
    2. Select project (if project_id not provided)
    3. Select issue (if issue_id not provided)
    4. Select comment (if comment_id not provided) ← NEW STEP
    5. Update the comment
    Security & Permissions:
    - Only the comment creator can update their own comment
    - Cannot update system comments (is_system_comment=1)
    - Cannot update deleted comments (is_deleted=1)
    - Guest users can only update their own comments on public issues
    The comment text supports:
    - Plain text
    - HTML formatting (automatically wrapped in <p> tags by API)
    - User mentions (use @username format)
    - Line breaks and paragraphs
    Args:
        api_key: User's Bugasura API key (required)
        comment: Updated comment text (required when updating, 1-65535 characters)
                 - Supports HTML formatting
                 - Use @username to mention team members
                 - Will be automatically HTML-encoded by API for security
        comment_id: Comment identifier (optional - will prompt if not provided)
        issue_id: Issue numeric ID (testresults_id) (optional - will prompt if not provided)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        comment_attachment_names: Comma-separated attachment filenames to preserve (optional)
                                 - If empty, existing attachments are preserved
                                 - If provided, only listed attachments are kept
    Returns:
        dict: {
            'status': 'OK',
            'message': 'Issue comment updated successfully',
            'comment_id': int,
            'last_modified': str,
            'comment': str,
            ...
        }
        OR selection prompt if context not complete
    Examples:
        # Fully interactive - will prompt for everything
        update_issue_comment(api_key, comment="Updated text")
        # Partial context - will prompt for missing info
        update_issue_comment(api_key, comment="Updated", team_id=456)
        # Direct update with all IDs
        update_issue_comment(
            api_key,
            comment="Fixed typo",
            comment_id=789,
            issue_id=123,
            team_id=456,
            project_id=789
        )
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Step 1 & 2: Use centralized context selection helper for team and project
    context = select_team_project_context(
        api_key, team_id, project_id,
        'update_issue_comment',
        f', comment="{comment[:50] if comment else ""}..."' if comment else ''
    )

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Step 3: If issue_id not provided, fetch and return issue options
    if issue_id is None:
        logger.info(f"update_issue_comment: No issue_id provided, fetching issues for project_id={project_id}")

        issues_response = make_api_request('GET', '/v1/issues/list', api_key, params={
            'team_id': team_id,
            'project_id': project_id,
            'start_at': 0,
            'max_results': 50
        })

        if issues_response.get('status') != 'OK':
            return issues_response

        issues = issues_response.get('issue_list', [])
        if not issues:
            return {
                'status': 'failed',
                'error': 'No issues found in the selected project',
                'suggestion': 'Please create an issue first using create_issue() tool.'
            }

        # Return issue selection prompt
        return {
            'status': 'selection_required',
            'step': 'issue_selection',
            'message': 'Please select an issue to update comment in:',
            'options': [{
                'issue_id': issue['issue_key'],
                'issue_key': issue.get('issue_id', 'N/A'),
                'summary': issue['summary'],
                'status': issue.get('bug_status', ''),
                'comment_count': issue.get('comments_count', 0)
            } for issue in issues[:20]],
            'instruction': f'Please call update_issue_comment again with issue_id parameter. Example: update_issue_comment(api_key="{api_key[:10]}...", comment="{comment[:30] if comment else ""}...", team_id={team_id}, project_id={project_id}, issue_id=<selected_issue_id>)'
        }

    # Step 4: NEW - If comment_id not provided, fetch and return comment options
    if comment_id is None:
        logger.info(f"update_issue_comment: No comment_id provided, fetching comments for issue_id={issue_id}")

        # Fetch all comments for the selected issue
        comments_response = make_api_request('GET', '/v1/issues/comments/list', api_key, params={
            'team_id': team_id,
            'project_id': project_id,
            'issue_key': issue_id,
            'is_list': 'true'
        })

        if comments_response.get('status') != 'OK':
            return comments_response

        comments = comments_response.get('comment_list', [])
        if not comments:
            return {
                'status': 'failed',
                'error': 'No comments found on this issue',
                'message': 'This issue has no comments to update. Please add a comment first.',
                'suggestion': 'Use add_issue_comment() to add a comment first.',
                'issue_id': issue_id,
                'issue_context': {
                    'team_id': team_id,
                    'project_id': project_id
                }
            }

        # Filter out system comments and deleted comments (can't be updated)
        editable_comments = [
            c for c in comments 
            if not c.get('is_system_comment', 0) and not c.get('is_deleted', 0)
        ]

        if not editable_comments:
            return {
                'status': 'failed',
                'error': 'No editable comments found',
                'message': 'All comments on this issue are either system comments or deleted.',
                'total_comments': len(comments),
                'system_comments': len([c for c in comments if c.get('is_system_comment')]),
                'deleted_comments': len([c for c in comments if c.get('is_deleted')]),
                'suggestion': 'System comments and deleted comments cannot be updated.'
            }

        # Return comment selection prompt
        return {
            'status': 'selection_required',
            'step': 'comment_selection',
            'message': f'Please select a comment to update (showing {len(editable_comments)} editable comments):',
            'options': [{
                'comment_id': comment['comment_id'],
                'comment_preview': (
                    comment.get('plain_text_comment', comment.get('comment', ''))[:100] + '...' 
                    if len(comment.get('plain_text_comment', comment.get('comment', ''))) > 100 
                    else comment.get('plain_text_comment', comment.get('comment', ''))
                ),
                'author': comment.get('user_name', 'Unknown'),
                'author_email': comment.get('user_email', ''),
                'created_at': comment.get('created_date', ''),
                'last_modified': comment.get('last_modified', ''),
                'is_editable': True,
                'attachments_count': len(comment.get('comment_attachments_files', []))
            } for comment in editable_comments[:20]],
            'total_editable_comments': len(editable_comments),
            'instruction': f'Please call update_issue_comment again with comment_id parameter. Example: update_issue_comment(api_key="{api_key[:10]}...", comment="Your updated text here", comment_id=<selected_comment_id>, issue_id={issue_id}, team_id={team_id}, project_id={project_id})'
        }

    # Step 5: All context parameters provided - validate comment text and proceed
    if not comment or not comment.strip():
        return {
            'status': 'failed',
            'error': 'Comment text is required',
            'error_type': 'ValidationError',
            'message': 'Updated comment cannot be empty. Please provide comment text (1-65535 characters).',
            'hint': 'You must provide the new comment text when updating. Example: comment="This is the updated text"'
        }

    comment_length = len(comment.strip())
    if comment_length < 1:
        return {
            'status': 'failed',
            'error': 'Comment too short',
            'error_type': 'ValidationError',
            'message': 'Comment must be at least 1 character long'
        }

    if comment_length > 65535:
        return {
            'status': 'failed',
            'error': f'Comment too long: {comment_length} characters',
            'error_type': 'ValidationError',
            'message': f'Comment must be at most 65535 characters (current: {comment_length})'
        }

    # All context parameters provided - proceed with updating comment
    logger.info(f"update_issue_comment: Updating comment_id={comment_id} for issue_id={issue_id}")

    # Build payload matching API expectations
    payload = {
        "team_id": team_id,
        "comment_id": comment_id,
        "comment": comment
    }

    # Add optional attachment names if provided
    if comment_attachment_names:
        payload["commentAttachmentNames"] = comment_attachment_names
        logger.info(f"update_issue_comment: Preserving specific attachments: {comment_attachment_names}")

    # Make POST request to update comment endpoint
    logger.info(f"update_issue_comment: Sending request to update comment {comment_id}")
    response = make_api_request('POST', '/v1/issues/comments/update', api_key, data=payload)

    # Add helpful information to response
    if response.get('status') == 'OK':
        logger.info(f"update_issue_comment: Successfully updated comment {comment_id}")
        response['comment_length'] = len(comment)
        response['operation'] = 'update'

        # Log if comment contains potential mentions
        if '@' in comment:
            mentioned_users = [word for word in comment.split() if word.startswith('@')]
            if mentioned_users:
                logger.info(f"update_issue_comment: Updated comment contains mentions: {mentioned_users}")
                response['mentioned_users'] = mentioned_users
                response['notifications_sent'] = True
    else:
        logger.error(f"update_issue_comment: Failed to update comment: {response.get('message')}")

    return response


@mcp.tool(
    name="delete_issue_comment",
    description="Delete an issue comment permanently. Supports full interactive selection - prompts for team/project/issue/comment if not provided. Shows deletion warnings."
)
def delete_issue_comment(
    api_key: str = Field(description="User's Bugasura API key"),
    comment_id: Optional[int] = Field(default=None, description="Comment numeric ID to delete (optional - will prompt if not provided)"),
    issue_id: Optional[int] = Field(default=None, description="Issue numeric ID (optional - will prompt if not provided)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)")
) -> dict:
    """
    Delete an issue comment permanently with full interactive flow.
    Interactive flow (prompts for missing context):
    1. Select team (if team_id not provided)
    2. Select project (if project_id not provided)
    3. Select issue (if issue_id not provided)
    4. Select comment (if comment_id not provided) ← NEW STEP
    5. Confirm and delete the comment
    WARNING: This action cannot be undone. The comment will be marked as deleted
    and replaced with "This comment is deleted by <username>".
    Security & Permissions:
    - Only the comment creator OR team admins can delete comments
    - Cannot delete system comments (is_system_comment=1)
    - Cannot delete already deleted comments (is_deleted=1)
    - Guest users can only delete their own comments on public issues
    Deletion Behavior:
    - Comment text is replaced with deletion message
    - Attachments and inline images are permanently removed from S3/storage
    - Comment reactions are deleted
    - Email notifications sent to assignees/admins
    - Slack notifications triggered if configured
    - Comment remains in database but marked as deleted (is_deleted=1)
    Args:
        api_key: User's Bugasura API key (required)
        comment_id: Comment identifier (optional - will prompt if not provided)
        issue_id: Issue numeric ID (testresults_id) (optional - will prompt if not provided)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
    Returns:
        dict: {
            'status': 'OK',
            'message': 'Issue comment got deleted successfully',
            'commentContent': str,
            'comment_id': int,
            ...
        }
        OR selection prompt if context not complete
    Examples:
        # Fully interactive - will prompt for everything
        delete_issue_comment(api_key)
        # Partial context - will prompt for missing info
        delete_issue_comment(api_key, team_id=456)
        # Direct delete with all IDs
        delete_issue_comment(
            api_key,
            comment_id=789,
            issue_id=123,
            team_id=456,
            project_id=789
        )
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Step 1 & 2: Use centralized context selection helper for team and project
    context = select_team_project_context(
        api_key, team_id, project_id,
        'delete_issue_comment',
        f', comment_id={comment_id}' if comment_id else ''
    )

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Step 3: If issue_id not provided, fetch and return issue options
    if issue_id is None:
        logger.info(f"delete_issue_comment: No issue_id provided, fetching issues for project_id={project_id}")

        issues_response = make_api_request('GET', '/v1/issues/list', api_key, params={
            'team_id': team_id,
            'project_id': project_id,
            'start_at': 0,
            'max_results': 50
        })

        if issues_response.get('status') != 'OK':
            return issues_response

        issues = issues_response.get('issue_list', [])
        if not issues:
            return {
                'status': 'failed',
                'error': 'No issues found in the selected project',
                'suggestion': 'Please create an issue first using create_issue() tool.'
            }

        # Return issue selection prompt
        return {
            'status': 'selection_required',
            'step': 'issue_selection',
            'message': 'Please select an issue to delete comment from:',
            'options': [{
                'issue_id': issue['issue_key'],
                'issue_key': issue.get('issue_id', 'N/A'),
                'summary': issue['summary'],
                'status': issue.get('bug_status', ''),
                'comment_count': issue.get('comments_count', 0)
            } for issue in issues[:20]],
            'instruction': f'Please call delete_issue_comment again with issue_id parameter. Example: delete_issue_comment(api_key="{api_key[:10]}...", team_id={team_id}, project_id={project_id}, issue_id=<selected_issue_id>)'
        }

    # Step 4: NEW - If comment_id not provided, fetch and return comment options
    if comment_id is None:
        logger.info(f"delete_issue_comment: No comment_id provided, fetching comments for issue_id={issue_id}")

        # Fetch all comments for the selected issue
        comments_response = make_api_request('GET', '/v1/issues/comments/list', api_key, params={
            'team_id': team_id,
            'project_id': project_id,
            'issue_key': issue_id,
            'is_list': 'true'
        })

        if comments_response.get('status') != 'OK':
            return comments_response

        comments = comments_response.get('comment_list', [])
        if not comments:
            return {
                'status': 'failed',
                'error': 'No comments found on this issue',
                'message': 'This issue has no comments to delete.',
                'suggestion': 'Please select a different issue or add comments first.',
                'issue_id': issue_id,
                'issue_context': {
                    'team_id': team_id,
                    'project_id': project_id
                }
            }

        # Filter out system comments and already deleted comments (can't be deleted)
        deletable_comments = [
            c for c in comments 
            if not c.get('is_system_comment', 0) and not c.get('is_deleted', 0)
        ]

        if not deletable_comments:
            return {
                'status': 'failed',
                'error': 'No deletable comments found',
                'message': 'All comments on this issue are either system comments or already deleted.',
                'total_comments': len(comments),
                'system_comments': len([c for c in comments if c.get('is_system_comment')]),
                'deleted_comments': len([c for c in comments if c.get('is_deleted')]),
                'suggestion': 'System comments cannot be deleted, and already deleted comments cannot be deleted again.'
            }

        # Return comment selection prompt with deletion warning
        return {
            'status': 'selection_required',
            'step': 'comment_selection',
            'message': f' WARNING: Select a comment to DELETE PERMANENTLY (showing {len(deletable_comments)} deletable comments):',
            'warning': 'DELETION IS PERMANENT AND CANNOT BE UNDONE',
            'deletion_effects': [
                'Comment text will be replaced with "This comment is deleted by <username>"',
                'All attachments and images will be permanently removed',
                'Comment reactions will be deleted',
                'Email notifications will be sent to assignees/admins',
                'This action cannot be reversed'
            ],
            'options': [{
                'comment_id': comment['comment_id'],
                'comment_preview': (
                    comment.get('plain_text_comment', comment.get('comment', ''))[:100] + '...' 
                    if len(comment.get('plain_text_comment', comment.get('comment', ''))) > 100 
                    else comment.get('plain_text_comment', comment.get('comment', ''))
                ),
                'author': comment.get('user_name', 'Unknown'),
                'author_email': comment.get('user_email', ''),
                'created_at': comment.get('created_date', ''),
                'last_modified': comment.get('last_modified', ''),
                'is_deletable': True,
                'attachments_count': len(comment.get('comment_attachments_files', []))
            } for comment in deletable_comments[:20]],
            'total_deletable_comments': len(deletable_comments),
            'instruction': f'To proceed with PERMANENT deletion, call: delete_issue_comment(api_key="{api_key[:10]}...", comment_id=<selected_comment_id>, issue_id={issue_id}, team_id={team_id}, project_id={project_id})'
        }

    # Step 5: All context parameters provided - proceed with deleting comment
    logger.info(f"delete_issue_comment: Deleting comment_id={comment_id} from issue_id={issue_id}")

    # Build payload matching API expectations
    payload = {
        "team_id": team_id,
        "comment_id": comment_id
    }

    # Make POST request to delete comment endpoint
    logger.info(f"delete_issue_comment: Sending request to delete comment {comment_id}")
    response = make_api_request('POST', '/v1/issues/comments/delete', api_key, data=payload)

    # Add helpful information to response
    if response.get('status') == 'OK':
        logger.info(f"delete_issue_comment: Successfully deleted comment {comment_id}")

        # Add warning about permanence and what was deleted
        response['warning'] = 'Comment has been permanently deleted. This action cannot be undone.'
        response['operation'] = 'delete'
        response['permanent'] = True

        # Log if attachments were deleted
        if response.get('commentContent'):
            logger.info(f"delete_issue_comment: Comment replaced with deletion message: {response['commentContent']}")
            response['replaced_with'] = response['commentContent']

        # Add helpful deletion summary
        response['deletion_summary'] = {
            'comment_id': comment_id,
            'issue_id': issue_id,
            'deleted_successfully': True,
            'attachments_removed': True,
            'notifications_sent': True
        }
    else:
        logger.error(f"delete_issue_comment: Failed to delete comment: {response.get('message')}")

    return response


# ============================================================================
# TEST CASE MANAGEMENT TOOLS
# ============================================================================
# Test cases define scenarios to be tested. They can be organized in folders
# and linked to sprints for execution tracking. When executed, results are
# stored as issues if they fail.
#
# IMPORTANT: Test case API endpoints use 'app_id' parameter (not 'project_id')
# This is legacy naming from the database 'apps' table. For consistency:
# - MCP tool parameters: use project_id (user-friendly)
# - API requests: map to app_id (what the Bugasura API expects)
# - Comment added at each mapping point for clarity

@mcp.tool(
    name = "list_test_cases",
    description = "List test cases for a project with pagination. Returns test case summaries. Interactive team/project selection available."
)
def list_test_cases(
    api_key: str = Field(description="User's Bugasura API key"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    start_at: int = Field(default=0, description="Pagination offset (default: 0)"),
    max_results: int = Field(default=10, description="Number of results to return (default: 10)")
) -> dict:
    """
    List test cases for a project with pagination.

    Interactive flow: If team_id/project_id are not provided, this function
    will return available options for the user to select from.

    Args:
        api_key: User's Bugasura API key (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        start_at: Pagination offset (default: 0)
        max_results: Number of results to return (default: 10, min: 10, max: 100)

    Returns:
        dict: List of test cases with pagination metadata
        OR a selection prompt if team_id/project_id not provided
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = select_team_project_context(api_key, team_id, project_id, 'list_test_cases')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # All required parameters provided - proceed with listing test cases
    # NOTE: Test case API endpoints use 'app_id' parameter name (not 'project_id')
    # This is legacy naming from the database 'apps' table
    response = make_api_request('GET', '/v1/testcases/list', api_key, params={
        'team_id': context['team_id'],
        'app_id': context['project_id'],  # API expects 'app_id' (project_id mapped here)
        'start_at': start_at,
        'max_results': max_results
    })

    # Filter out large unnecessary fields to reduce payload size
    return filter_large_fields(response)


@mcp.tool(
    name = "create_test_case",
    description = "Create a new test case with required scenario. Supports feature tags, testing type, severity, priority, conditions, test data, assignees, and folder organization. Interactive team/project selection available."
)
def create_test_case(
    api_key: str = Field(description="User's Bugasura API key"),
    scenario: str = Field(description="Test case scenario/title (required)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    feature_name: str = Field(default="", description="Feature name/tag (optional)"),
    sub_feature_name: str = Field(default="", description="Sub-feature name/tag (optional)"),
    testing_type: str = Field(default="Functional", description="Testing type: 'Functional', 'Regression', 'Smoke', 'Integration', etc. (default: Functional)"),
    severity: str = Field(default="MEDIUM", description="Severity: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW' (default: MEDIUM)"),
    priority: str = Field(default="P2", description="Priority: 'P0', 'P1', 'P2', 'P3', 'P4' (default: P2)"),
    test_conditions: str = Field(default="", description="Pre-conditions and test setup (optional)"),
    test_idea: str = Field(default="", description="Test idea or objective (optional)"),
    test_data: str = Field(default="", description="Test data required (optional)"),
    acceptance_criteria: str = Field(default="", description="Acceptance criteria or expected results (optional)"),
    assignees: Optional[str] = Field(default=None, description="Comma-separated assignee names, emails, or IDs (optional)"),
    is_api_test_case: bool = Field(default=False, description="Flag for API test cases (default: False)"),
    folder_id: Optional[int] = Field(default=None, description="Folder ID for organization (optional)")
) -> dict:
    """
    Create a new test case in Bugasura.

    Interactive flow: If team_id/project_id are not provided, this function
    will return available options for the user to select from.

    **Smart Assignee Resolution**: The assignees parameter automatically converts
    user names or emails to user IDs. You can provide:
    - User IDs (e.g., "123")
    - Email addresses (e.g., "john@example.com")
    - Names or partial names (e.g., "John", "John Doe")
    - Mix of any of the above (e.g., "John, jane@example.com, 789")

    Args:
        api_key: User's Bugasura API key (required)
        scenario: Test case scenario/title (required)
                 Note: If "API" is mentioned in scenario, automatically sets is_api_test_case=True
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        feature_name: Feature being tested (default: 'feature_name_1')
        sub_feature_name: Sub-feature or component (default: 'sub_feature_name_1')
        testing_type: Type of testing - "Functional" or "API" (default: "Functional")
                     Note: If "API" is mentioned, automatically sets is_api_test_case=True
        severity: CRITICAL/HIGH/MEDIUM/LOW (default: "MEDIUM")
        priority: Test case priority - typically P1, P2, P3, P4 (default: "P2")
        test_conditions: Pre-conditions for the test
        test_idea: What to test/verify
        test_data: Sample data needed for test
        acceptance_criteria: Expected results
        assignees: Comma-separated names, emails, or user IDs (optional)
        is_api_test_case: Set to True for API test cases (auto-detected if "API" in scenario/testing_type)
        folder_id: Optional folder to organize test cases

    Returns:
        dict: API response with created test case details
        OR a selection prompt if team_id/project_id not provided
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = select_team_project_context(api_key, team_id, project_id, 'create_test_case', f', scenario="{scenario}"')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # All required parameters provided - proceed with test case creation

    # Auto-detect API test case from scenario or testing_type
    # If user mentions "API" in scenario or explicitly sets testing_type to "API", mark as API test case
    if not is_api_test_case:
        scenario_lower = scenario.lower()
        testing_type_lower = testing_type.lower()
        if 'api' in scenario_lower or 'api' in testing_type_lower:
            is_api_test_case = True
            # Also set testing_type to API if not already set
            if testing_type.lower() != 'api':
                testing_type = 'API'

    # Build test case object with required fields
    # Severity must be uppercase to match API enum values
    tc = {
        "test_case_scenario": scenario,    # Test scenario/title
        "severity": severity.upper(),      # Ensure uppercase (CRITICAL, HIGH, etc.)
        "priority": priority               # Priority (required field)
    }

    # Set default values for feature names if not provided
    if not feature_name:
        feature_name = "feature_name_1"
    if not sub_feature_name:
        sub_feature_name = "sub_feature_name_1"

    # Resolve assignees if provided
    assignee_ids = None
    if assignees is not None:
        # Convert names/emails to user IDs using smart identifier resolution
        logger.info(f"create_test_case: Resolving assignee identifiers '{assignees}' for team_id={team_id}")
        resolution_result = _find_user_ids_by_names_or_emails(api_key, team_id, assignees)
        if resolution_result['status'] != 'OK':
            logger.error(f"create_test_case: Failed to resolve assignee identifiers: {resolution_result.get('error')}")
            return resolution_result

        assignee_ids = resolution_result['user_ids']
        logger.info(f"create_test_case: Resolved assignees to user_ids: {assignee_ids}")

    # Build optional fields dictionary
    optional = {
        'feature_name': feature_name,                # Feature under test
        'sub_feature_name': sub_feature_name,        # Sub-feature/component
        'testing_type': testing_type,                # Test type classification
        'test_conditions': test_conditions,          # Pre-requisites
        'test_idea': test_idea,                      # What to verify
        'test_data': test_data,                      # Input data needed
        'acceptance_criteria': acceptance_criteria,  # Expected outcomes
        'is_api_test_case': is_api_test_case        # Flag for API test cases
    }

    # Add assignees if provided and resolved
    if assignee_ids is not None:
        optional['assignee'] = assignee_ids

    # Add only non-empty optional fields to test case object
    # For boolean fields, always include them
    for k, v in optional.items():
        if k == 'is_api_test_case':
            tc[k] = v  # Always include boolean field
        elif v:
            tc[k] = v

    # Build API payload
    # Note: testCaseDetails is a JSON array to support bulk creation
    # IDs will be auto-converted to strings by make_api_request()
    # IMPORTANT: isQuickAdd is set to "0" to prevent backend from overriding testing_type to 'Functional'
    payload = {
        "app_id": project_id,                   # API expects 'app_id' (project_id mapped here)
        "team_id": team_id,                     # Team ID
        "testCaseDetails": json.dumps([tc]),    # JSON array of test cases
        "source": "API",                        # Source tracking
        "isAIGenerated": "0",                   # Not AI-generated
        "isQuickAdd": "0",                      # Set to 0 to avoid testing_type override,
        "folderType": "TESTCASES"               # Folder type
    }

    # Add folder_id if provided (for organization)
    if folder_id is not None:
        payload["folder_id"] = folder_id  # Will be converted to string

    # Make POST request to create test case
    return make_api_request('POST', '/v1/testcases/add', api_key, data=payload)


@mcp.tool(
    name = "get_test_case",
    description = "Get detailed test case information by numeric ID. Returns full test case details including steps and execution history. Interactive team/project selection available."
)
def get_test_case(
    api_key: str = Field(description="User's Bugasura API key"),
    testcase_id: int = Field(description="Test case numeric ID"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (optional)")
) -> dict:
    """
    Get test case details.

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    Args:
        api_key: User's Bugasura API key (required)
        testcase_id: Test case identifier (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        sprint_id: Optional sprint ID for execution context

    Returns:
        dict: Complete test case details with execution history if sprint_id provided
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = select_team_project_context(api_key, team_id, project_id, 'get_test_case', f', testcase_id={testcase_id}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # GET request - integers are fine (auto-converted to strings in URL)
    # NOTE: Test case endpoints use 'app_id' not 'project_id'
    params = {
        'team_id': context['team_id'],
        'app_id': context['project_id'],  # API expects 'app_id' (project_id mapped here)
        'testcase_id': testcase_id
    }

    # Add sprint context if provided
    # NOTE: API uses 'report_id' for sprint identifier (legacy naming)
    if sprint_id is not None:
        params['report_id'] = sprint_id  # API expects 'report_id' (sprint_id mapped here)

    response = make_api_request('GET', '/v1/testcases/get', api_key, params=params)

    # Return full response for individual test case (including tools_integration_settings if needed)
    return response


@mcp.tool(
    name = "update_test_case",
    description = "Update test case details (partial updates supported). Can update any field including scenario, feature tags, testing type, severity, priority, conditions, assignees, status, and sprint associations. Interactive selection available."
)
def update_test_case(
    api_key: str = Field(description="User's Bugasura API key"),
    testcase_id: int = Field(description="Test case numeric ID to update"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    feature_name: Optional[str] = Field(default=None, description="New feature name/tag (optional)"),
    sub_feature_name: Optional[str] = Field(default=None, description="New sub-feature name/tag (optional)"),
    scenario: Optional[str] = Field(default=None, description="New test case scenario/title (optional)"),
    testing_type: Optional[str] = Field(default=None, description="New testing type (optional)"),
    severity: Optional[str] = Field(default=None, description="New severity: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW' (optional)"),
    priority: Optional[str] = Field(default=None, description="New priority: 'P0', 'P1', 'P2', 'P3', 'P4' (optional)"),
    test_conditions: Optional[str] = Field(default=None, description="New test conditions (optional)"),
    test_idea: Optional[str] = Field(default=None, description="New test idea (optional)"),
    test_data: Optional[str] = Field(default=None, description="New test data (optional)"),
    acceptance_criteria: Optional[str] = Field(default=None, description="New acceptance criteria (optional)"),
    execution_status: Optional[str] = Field(default=None, description="New execution status: 'PASS', 'FAIL', 'BLOCKED', 'NOT EXECUTED' (optional)"),
    test_case_status: Optional[str] = Field(default=None, description="New test case status (optional)"),
    assignees: Optional[str] = Field(default=None, description="New assignees, comma-separated names/emails/IDs (optional)"),
    folder_id: Optional[int] = Field(default=None, description="New folder ID for organization (optional)"),
    sprint_ids: Optional[str] = Field(default=None, description="New sprint associations, comma-separated sprint IDs (optional)")
) -> dict:
    """
    Update a test case. Only updates the fields that are provided.

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    This function fetches the existing test case details first, then merges
    the updates with existing data to ensure all required fields are present.

    **Smart Assignee Resolution**: The assignees parameter automatically converts
    user names or emails to user IDs. You can provide:
    - User IDs (e.g., "123")
    - Email addresses (e.g., "john@example.com")
    - Names or partial names (e.g., "John", "John Doe")
    - Mix of any of the above (e.g., "John, jane@example.com, 789")

    Args:
        api_key: User's Bugasura API key (required)
        testcase_id: Test case identifier to update (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        feature_name: Feature name (optional)
        sub_feature_name: Sub-feature name (optional)
        scenario: Test case scenario/title (optional)
        testing_type: Type of testing (optional)
        severity: CRITICAL/HIGH/MEDIUM/LOW (optional)
        priority: Priority of the Test Case (optional)
        test_conditions: Pre-conditions (optional)
        test_idea: What to test (optional)
        test_data: Test data needed (optional)
        acceptance_criteria: Expected results (optional)
        execution_status: Execution status - NEW/IN_PROGRESS/ERROR/CANCELLED/COMPLETED/BLOCKED (optional)
        test_case_status: Test case status - PENDING/PASS/FAIL (optional)
        assignees: Comma-separated names, emails, or user IDs (optional)
        folder_id: Folder ID for organization (optional)
        sprint_ids: Comma-separated sprint IDs (optional)

    Returns:
        dict: API response with update status

    Examples:
        # Update only the scenario
        update_test_case(api_key, team_id, project_id, testcase_id, scenario="Updated test scenario")

        # Update severity and status
        update_test_case(api_key, team_id, project_id, testcase_id, severity="HIGH", test_case_status="PASS")

        # Assign test case to user by name
        update_test_case(api_key, team_id, project_id, testcase_id, assignees="John Doe")

        # Assign to multiple users (mixed formats)
        update_test_case(api_key, team_id, project_id, testcase_id, assignees="John, jane@example.com, 789")

        # Move to different folder
        update_test_case(api_key, team_id, project_id, testcase_id, folder_id=123)
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    # Handle case where API might return a list instead of dict
    if isinstance(validation, list):
        return {'status': 'failed', 'error': 'Unexpected API response format', 'details': str(validation)}
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = select_team_project_context(api_key, team_id, project_id, 'update_test_case', f', testcase_id={testcase_id}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Step 1: Fetch existing test case details
    logger.info(f"Fetching existing test case details for testcase_id={testcase_id}")
    existing_tc_response = make_api_request('GET', '/v1/testcases/get', api_key, params={
        'team_id': team_id,
        'app_id': project_id,  # API expects 'app_id' (project_id mapped here)
        'testcase_id': testcase_id
    })

    # Handle case where API might return a list instead of dict
    if isinstance(existing_tc_response, list):
        return {
            'status': 'failed',
            'error': 'Unexpected API response format (received list instead of dict)',
            'error_type': 'ResponseFormatError',
            'response_preview': str(existing_tc_response[:2]) if len(existing_tc_response) > 0 else 'Empty list'
        }

    # Check if fetch was successful
    if existing_tc_response.get('status') == 'failed':
        logger.error(f"Failed to fetch existing test case: {existing_tc_response.get('error')}")
        return {
            'status': 'failed',
            'error': 'Could not fetch existing test case details',
            'error_type': 'TestCaseFetchError',
            'message': f"Unable to update test case. Error: {existing_tc_response.get('message', 'Unknown error')}",
            'details': existing_tc_response
        }

    # Step 2: Extract existing test case data
    tc_data_raw = existing_tc_response.get('testCaseDetails', {})

    # Handle case where API returns list instead of dict
    if isinstance(tc_data_raw, list):
        if len(tc_data_raw) == 0:
            logger.error(f"No test case data found for testcase_id={testcase_id} (empty list)")
            return {
                'status': 'failed',
                'error': 'Test case not found',
                'error_type': 'TestCaseNotFound',
                'message': f"Test case with ID {testcase_id} not found (empty response)"
            }
        # Get first element if it's a list
        tc_data = tc_data_raw[0]
        logger.info(f"API returned testCaseDetails as list, using first element")
    else:
        tc_data = tc_data_raw

    if not tc_data:
        logger.error(f"No test case data found for testcase_id={testcase_id}")
        return {
            'status': 'failed',
            'error': 'Test case not found',
            'error_type': 'TestCaseNotFound',
            'message': f"Test case with ID {testcase_id} not found"
        }

    logger.info(f"Fetched existing test case data. Merging updates...")

    # Step 3: Build merged test case details
    # IMPORTANT: Backend requires certain fields even for partial updates.
    # We always include these baseline fields from the existing test case,
    # then override only the fields the user wants to change.
    #
    # Baseline fields (always included):
    # - feature_name, sub_feature_name, test_case_scenario, testing_type (mandatory)
    # - severity, priority (backend validation may require these)

    # Start with baseline fields from existing test case
    tc_details = {
        'feature_name': tc_data.get('feature_name', ''),
        'sub_feature_name': tc_data.get('sub_feature_name', ''),
        'test_case_scenario': tc_data.get('test_case_scenario', ''),
        'testing_type': tc_data.get('testing_type', ''),
        'severity': tc_data.get('severity', 'MEDIUM'),
        'priority': tc_data.get('priority', 'P2')
    }

    # Override mandatory fields if user provided new values
    if feature_name is not None:
        tc_details['feature_name'] = feature_name
    if sub_feature_name is not None:
        tc_details['sub_feature_name'] = sub_feature_name
    if scenario is not None:
        tc_details['test_case_scenario'] = scenario
    if testing_type is not None:
        tc_details['testing_type'] = testing_type

    # Override severity and priority if user provided new values
    if severity is not None:
        tc_details['severity'] = severity
    if priority is not None:
        tc_details['priority'] = priority
    if test_conditions is not None:
        tc_details['test_conditions'] = test_conditions
    if test_idea is not None:
        tc_details['test_idea'] = test_idea
    if test_data is not None:
        tc_details['test_data'] = test_data
    if acceptance_criteria is not None:
        tc_details['acceptance_criteria'] = acceptance_criteria
    if assignees is not None:
        # Convert names/emails to user IDs using smart identifier resolution
        logger.info(f"update_test_case: Resolving assignee identifiers '{assignees}' for team_id={team_id}")
        resolution_result = _find_user_ids_by_names_or_emails(api_key, team_id, assignees)
        if resolution_result['status'] != 'OK':
            logger.error(f"update_test_case: Failed to resolve assignee identifiers: {resolution_result.get('error')}")
            return resolution_result

        assignee_ids = resolution_result['user_ids']
        logger.info(f"update_test_case: Resolved assignees to user_ids: {assignee_ids}")
        tc_details['assignee'] = assignee_ids
    if sprint_ids is not None:
        tc_details['sprint_ids'] = sprint_ids

    logger.debug(f"Prepared test case details with {len(tc_details)} fields")

    # Step 4: Build base payload with required fields
    # IDs will be auto-converted to strings by make_api_request()
    # NOTE: Test case endpoints use 'app_id' not 'project_id'
    payload = {
        "app_id": project_id,      # API expects 'app_id' (project_id mapped here)
        "testcase_id": testcase_id,
        "team_id": team_id
    }

    # Add test case details if we have any fields to update
    if tc_details:
        payload["testCaseDetails"] = json.dumps([tc_details])
        logger.info(f"Prepared testCaseDetails with {len(tc_details)} fields")

    # Add status fields if provided
    if execution_status is not None:
        payload["executionStatus"] = execution_status
        logger.debug(f"Set executionStatus to {execution_status}")
    if test_case_status is not None:
        payload["testCaseStatus"] = test_case_status
        logger.debug(f"Set testCaseStatus to {test_case_status}")
    if folder_id is not None:
        payload["folderId"] = folder_id  # Will be converted to string
        logger.debug(f"Set folderId to {folder_id}")

    # Step 5: Make the update request
    logger.info(f"Sending update request for testcase_id={testcase_id}")
    return make_api_request('POST', '/v1/testcases/update', api_key, data=payload)


@mcp.tool(
    name = "delete_test_case",
    description = "Delete a test case permanently by numeric ID, test case key (e.g., 'TES5', 'MCP11'), or exact/partial scenario match. Uses 3-step matching: exact key → exact scenario → partial scenario. Interactive selection available."
)
def delete_test_case(
    api_key: str = Field(description="User's Bugasura API key"),
    testcase_identifier: str = Field(description="Test case identifier: numeric ID (e.g., '123'), test case key (e.g., 'TES5', 'MCP11'), or scenario text for matching"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)")
) -> dict:
    """
    Delete a test case from Bugasura by ID, test case key, or scenario name.

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    WARNING: This action cannot be undone. The test case and all its execution
    history will be permanently removed.

    Args:
        api_key: User's Bugasura API key (required)
        testcase_identifier: Test case ID (numeric), test case key (e.g., "TES5", "MCP11"), or scenario name (string) to delete (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)

    Returns:
        dict: {
            'status': 'OK',
            'message': 'Test case deleted successfully'
        }

    Examples:
        # Delete a test case by numeric ID
        delete_test_case(api_key, testcase_identifier="123", team_id=456, project_id=789)

        # Delete a test case by test case key
        delete_test_case(api_key, testcase_identifier="TES5", team_id=456, project_id=789)

        # Delete a test case by scenario name
        delete_test_case(api_key, testcase_identifier="Verify login with valid credentials", team_id=456, project_id=789)

        # Delete with interactive context selection
        delete_test_case(api_key, testcase_identifier="MCP11")
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = select_team_project_context(api_key, team_id, project_id, 'delete_test_case', f', testcase_identifier={testcase_identifier}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Resolve testcase_identifier to testcase_id
    testcase_id = None

    # Check if it's a numeric ID
    if testcase_identifier.isdigit():
        testcase_id = int(testcase_identifier)
        logger.info(f"delete_test_case: Using numeric testcase_id={testcase_id}")
    else:
        # It could be a test case key (e.g., "TES5", "MCP11") or a scenario name - search for it
        logger.info(f"delete_test_case: Searching for test case by key or scenario: '{testcase_identifier}'")

        # NOTE: Test case endpoints use 'app_id' not 'project_id'
        params = {
            'team_id': str(team_id),
            'app_id': str(project_id),  # API expects 'app_id'
            'start_at': 0,
            'max_results': 100  # Get more results for better matching
        }

        testcases_response = make_api_request('GET', '/v1/testcases/list', api_key, params=params)

        if testcases_response.get('status') != 'OK':
            return {
                'status': 'failed',
                'error': 'Failed to fetch test cases',
                'message': testcases_response.get('message', 'Could not retrieve test cases list')
            }

        testcases = testcases_response.get('testCases', [])

        # Step 1: Try exact match by test case key (case-insensitive)
        # Test case keys are usually in format like "TES5", "MCP11", etc.
        matching_testcases = [tc for tc in testcases if tc.get('test_case_key', '').upper() == testcase_identifier.upper()]

        if matching_testcases:
            logger.info(f"delete_test_case: Found test case by key: {matching_testcases[0].get('test_case_key')}")
        else:
            # Step 2: Try exact match by scenario (case-insensitive)
            matching_testcases = [tc for tc in testcases if tc.get('scenario', '').lower() == testcase_identifier.lower()]

            if not matching_testcases:
                # Step 3: Try partial match by scenario
                matching_testcases = [tc for tc in testcases if testcase_identifier.lower() in tc.get('scenario', '').lower()]

        if not matching_testcases:
            return {
                'status': 'failed',
                'error': 'Test case not found',
                'message': f"No test case found with key or scenario '{testcase_identifier}' in project {project_id}"
            }

        if len(matching_testcases) > 1:
            testcase_list = '\n'.join([f"  - ID: {tc['project_test_case_id']}, Key: {tc.get('test_case_key', 'N/A')}, Scenario: {tc['scenario']}" for tc in matching_testcases[:10]])
            return {
                'status': 'failed',
                'error': 'Multiple test cases found',
                'message': f"Multiple test cases match '{testcase_identifier}'. Please use the test case ID or unique test case key instead:\n{testcase_list}"
            }

        testcase_id = matching_testcases[0]['project_test_case_id']
        logger.info(f"delete_test_case: Found test case '{testcase_identifier}' with ID {testcase_id}")

    # Build payload
    # NOTE: Test case endpoints use 'app_id' not 'project_id'
    # The API expects 'testcaseids' (comma-separated list) not 'testcase_id'
    # IMPORTANT: The API requires either sprintId OR isDeleteTestCases=true
    # - If isDeleteTestCases=false (default), sprintId is REQUIRED
    # - If isDeleteTestCases=true, sprintId is optional
    # We set isDeleteTestCases=true to allow deletion without sprint context
    payload = {
        "app_id": project_id,      # API expects 'app_id' (project_id mapped here)
        "testcaseids": str(testcase_id),  # API expects comma-separated string
        "team_id": team_id,
        "isDeleteTestCases": "true"  # Set to true to bypass sprint_id requirement
    }

    logger.info(f"Deleting testcase_id={testcase_id} for team_id={team_id}, project_id={project_id}")
    return make_api_request('POST', '/v1/testcases/delete', api_key, data=payload)

# ============================================================================
# TEST CASE COMMENTS MANAGEMENT TOOLS
# ============================================================================


@mcp.tool(
    name = "list_test_case_comments",
    description = "List comments for a specific test case with test case details. Returns test case information and all associated comments. Interactive team/project/test case selection available."
)
def list_test_case_comments(
    api_key: str = Field(description="User's Bugasura API key"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    test_case_id: Optional[int] = Field(default=None, description="Test case identifier (optional - will prompt if not provided)"),
    report_id: Optional[int] = Field(default=None, description="Report identifier (optional)")
) -> dict:
    """
    List comments for a specific test case along with test case details.
    Interactive flow: If team_id/project_id/test_case_id are not provided, this function
    will return available options for the user to select from.
    Args:
        api_key: User's Bugasura API key (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        test_case_id: Test case identifier (optional - will prompt if not provided)
        report_id: Report identifier (optional)
    Returns:
        dict: Test case comments list with metadata
        OR a selection prompt if team_id/project_id/test_case_id not provided
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper for team and project
    context = select_team_project_context(api_key, team_id, project_id, 'list_test_case_comments')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Now we have team_id and project_id, check if test_case_id is provided
    if test_case_id is None:
        # Fetch available test cases for selection using CORRECTED API call
        test_cases_response = make_api_request('GET', '/v1/testcases/list', api_key, params={
            'team_id': team_id,
            'app_id': project_id,  # API expects 'app_id'
            'start_at': 0,
            'max_results': 100
        })

        # FIXED: Use 'testCasesList' and proper field names
        if test_cases_response.get('status') == 'OK' and test_cases_response.get('testCasesList'):
            return {
                'status': 'selection_required',
                'selection_type': 'test_case',
                'message': 'Please select a test case to view comments',
                'available_test_cases': [
                    {
                        'test_case_id': tc.get('id'),  # FIXED: Use 'id' field
                        'test_case_number': tc.get('test_case_number', ''),
                        'title': tc.get('title', 'Untitled Test Case'),
                        'scenario': tc.get('scenario', 'No scenario'),
                        'status': tc.get('status', 'Unknown'),
                        'priority': tc.get('priority', 'Unknown'),
                        'testing_type': tc.get('testing_type', 'Unknown'),
                        'feature_name': tc.get('feature_name', '')
                    }
                    for tc in test_cases_response.get('testCasesList', [])
                ],
                'total_count': test_cases_response.get('totalCount', 0),
                'instructions': 'Call this function again with the selected test_case_id parameter',
                'current_context': {
                    'team_id': team_id,
                    'project_id': project_id
                }
            }
        else:
            return {
                'status': 'ERROR',
                'message': f'No test cases found for the selected project (team_id={team_id}, project_id={project_id}) or unable to fetch test cases',
                'debug_info': {
                    'response_status': test_cases_response.get('status'),
                    'response_message': test_cases_response.get('message', ''),
                    'response_keys': list(test_cases_response.keys()) if test_cases_response else []
                }
            }

    # All required parameters provided - proceed with fetching test case comments
    params = {
        'team_id': team_id,
        'app_id': project_id,
        'testCaseId': test_case_id
    }

    # Add optional report_id if provided
    if report_id is not None:
        params['report_id'] = report_id

    response = make_api_request('GET', '/v1/testcasecomments/list', api_key, params=params)

    # Attach test case details fetched before listing comments
    try:
        tc_before = get_test_case(api_key, testcase_id=test_case_id, team_id=team_id, project_id=project_id)
        response['test_case_before'] = tc_before
    except Exception as e:
        logger.debug(f"list_test_case_comments: Could not fetch test case details before listing comments: {e}")

    # Filter out large unnecessary fields to reduce payload size
    return filter_large_fields(response)

@mcp.tool(
    name = "add_test_case_comment",
    description = "Add a comment to a specific test case. Supports inline images, file attachments, and threaded replies. Interactive team/project/test case selection available."
)
def add_test_case_comment(
    api_key: str = Field(description="User's Bugasura API key"),
    comment: str = Field(description="Comment content (supports HTML formatting, required)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    test_case_id: Optional[int] = Field(default=None, description="Test case identifier (optional - will prompt if not provided)"),
    report_id: Optional[int] = Field(default=None, description="Report identifier (optional)"),
    parent_comment_id: Optional[int] = Field(default=None, description="Parent comment ID for threaded replies (optional)")
) -> dict:
    """
    Add a comment to a specific test case in Bugasura.
    Interactive flow: If team_id/project_id/test_case_id are not provided, this function
    will return available options for the user to select from.
    Args:
        api_key: User's Bugasura API key (required)
        comment: Comment content (required) - supports HTML formatting
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        test_case_id: Test case identifier (optional - will prompt if not provided)
        report_id: Report identifier for test run context (optional)
        parent_comment_id: Parent comment ID for threaded replies (optional)
    Returns:
        dict: API response with added comment details
        OR a selection prompt if team_id/project_id/test_case_id not provided
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Validate comment is not empty
    if not comment or comment.strip() == '':
        return {
            'status': 'ERROR',
            'message': 'Comment content is required and cannot be empty'
        }

    # Use centralized context selection helper for team and project
    context = select_team_project_context(api_key, team_id, project_id, 'add_test_case_comment', f', comment="{comment[:50]}..."')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Now we have team_id and project_id, check if test_case_id is provided
    if test_case_id is None:
        # Fetch available test cases for selection using CORRECTED API call
        test_cases_response = make_api_request('GET', '/v1/testcases/list', api_key, params={
            'team_id': team_id,
            'app_id': project_id,
            'start_at': 0,
            'max_results': 100
        })

        # FIXED: Use 'testCasesList' and proper field names
        if test_cases_response.get('status') == 'OK' and test_cases_response.get('testCasesList'):
            return {
                'status': 'selection_required',
                'selection_type': 'test_case',
                'message': 'Please select a test case to add comment',
                'available_test_cases': [
                    {
                        'test_case_id': tc.get('id'),  # FIXED: Use 'id' field
                        'test_case_number': tc.get('test_case_number', ''),
                        'title': tc.get('title', 'Untitled Test Case'),
                        'scenario': tc.get('scenario', 'No scenario'),
                        'status': tc.get('status', 'Unknown'),
                        'priority': tc.get('priority', 'Unknown'),
                        'testing_type': tc.get('testing_type', 'Unknown'),
                        'feature_name': tc.get('feature_name', '')
                    }
                    for tc in test_cases_response.get('testCasesList', [])
                ],
                'total_count': test_cases_response.get('totalCount', 0),
                'instructions': 'Call this function again with the selected test_case_id parameter',
                'current_context': {
                    'team_id': team_id,
                    'project_id': project_id,
                    'comment': comment
                }
            }
        else:
            return {
                'status': 'ERROR',
                'message': f'No test cases found for the selected project (team_id={team_id}, project_id={project_id}) or unable to fetch test cases',
                'debug_info': {
                    'response_status': test_cases_response.get('status'),
                    'response_message': test_cases_response.get('message', ''),
                    'response_keys': list(test_cases_response.keys()) if test_cases_response else []
                }
            }

    # All required parameters provided - proceed with adding comment
    payload = {
        'teamId': team_id,
        'team_id': team_id,
        'appId': project_id,
        'app_id': project_id,
        'testCaseId': test_case_id,
        'comment': comment
    }

    # Add optional parameters
    if report_id is not None:
        payload['reportId'] = report_id
        payload['report_id'] = report_id

    if parent_comment_id is not None:
        payload['parentCommentId'] = parent_comment_id

    logger.info(f"add_test_case_comment: Adding comment to test_case_id={test_case_id} in team={team_id}, project={project_id}")

    response = make_api_request('POST', '/v1/testcasecomments/add', api_key, data=payload)

    if response.get('status') == 'OK':
        logger.info(f"add_test_case_comment: Successfully added comment to test case {test_case_id}")
    else:
        logger.error(f"add_test_case_comment: Failed to add comment. Response: {response.get('message', 'Unknown error')}")
    # Attach test case details fetched before adding comment
    try:
        tc_before = get_test_case(api_key, testcase_id=test_case_id, team_id=team_id, project_id=project_id)
        response['test_case_before'] = tc_before
    except Exception as e:
        logger.debug(f"add_test_case_comment: Could not fetch test case details before adding comment: {e}")

    # Refresh test case list for the project so clients can get up-to-date data
    try:
        refreshed = list_test_cases(api_key, team_id=team_id, project_id=project_id)
        response['test_cases_refresh'] = refreshed
        logger.debug("add_test_case_comment: Refreshed test case list attached to response")
    except Exception as e:
        logger.error(f"add_test_case_comment: Failed to refresh test case list: {e}")
        response['test_cases_refresh_error'] = str(e)

    return response

@mcp.tool(
    name = "get_test_case_comment",
    description = "Get detailed information for a specific test case comment by comment ID. Returns full comment details including attachments, inline images, and metadata. Interactive team/project/test case selection available."
)
def get_test_case_comment(
    api_key: str = Field(description="User's Bugasura API key"),
    comment_id: int = Field(description="Comment identifier (required)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    test_case_id: Optional[int] = Field(default=None, description="Test case identifier (optional - will prompt if not provided)"),
    report_id: Optional[int] = Field(default=None, description="Report identifier (optional)"),
    parent_comment_id: Optional[int] = Field(default=None, description="Parent comment ID for fetching threaded replies (optional)")
) -> dict:
    """
    Get detailed information for a specific test case comment.
    Interactive flow: If team_id/project_id/test_case_id are not provided, this function
    will return available options for the user to select from.
    Args:
        api_key: User's Bugasura API key (required)
        comment_id: Comment identifier (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        test_case_id: Test case identifier (optional - will prompt if not provided)
        report_id: Report identifier for test run context (optional)
        parent_comment_id: Parent comment ID for fetching threaded replies (optional)
    Returns:
        dict: API response with comment details
        OR a selection prompt if required parameters not provided
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Validate comment_id is provided (required parameter)
    if comment_id is None or comment_id <= 0:
        return {
            'status': 'ERROR',
            'message': 'comment_id is required and must be a positive integer'
        }

    # Use centralized context selection helper for team and project
    context = select_team_project_context(
        api_key, team_id, project_id, 'get_test_case_comment',
        f', comment_id={comment_id}'
    )

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Check if test_case_id is provided
    # If caller provided a test case identifier (name/key) instead of numeric id,
    # try to resolve it to a numeric test case id.
    if test_case_id is not None and not isinstance(test_case_id, int):
        logger.info(f"Resolving test_case_id identifier '{test_case_id}' to numeric id")
        resolved = _resolve_test_case_id(api_key, team_id, project_id, test_case_id)
        if resolved.get('status') != 'OK':
            return resolved
        test_case_id = resolved['testcase_id']

    if test_case_id is None:
        # Fetch available test cases for selection using CORRECTED API call
        test_cases_response = make_api_request('GET', '/v1/testcases/list', api_key, params={
            'team_id': team_id,
            'app_id': project_id,
            'start_at': 0,
            'max_results': 100
        })

        # FIXED: Use 'testCasesList' and proper field names
        if test_cases_response.get('status') == 'OK' and test_cases_response.get('testCasesList'):
            return {
                'status': 'selection_required',
                'selection_type': 'test_case',
                'message': 'Please select a test case to fetch comment from',
                'available_test_cases': [
                    {
                        'test_case_id': tc.get('id'),  # FIXED: Use 'id' field
                        'test_case_number': tc.get('test_case_number', ''),
                        'title': tc.get('title', 'Untitled Test Case'),
                        'scenario': tc.get('scenario', 'No scenario'),
                        'status': tc.get('status', 'Unknown'),
                        'priority': tc.get('priority', 'Unknown'),
                        'testing_type': tc.get('testing_type', 'Unknown'),
                        'feature_name': tc.get('feature_name', '')
                    }
                    for tc in test_cases_response.get('testCasesList', [])
                ],
                'total_count': test_cases_response.get('totalCount', 0),
                'instructions': 'Call this function again with the selected test_case_id parameter',
                'current_context': {
                    'team_id': team_id,
                    'project_id': project_id,
                    'comment_id': comment_id
                }
            }
        else:
            return {
                'status': 'ERROR',
                'message': f'No test cases found for the selected project (team_id={team_id}, project_id={project_id}) or unable to fetch test cases',
                'debug_info': {
                    'response_status': test_cases_response.get('status'),
                    'response_message': test_cases_response.get('message', ''),
                    'response_keys': list(test_cases_response.keys()) if test_cases_response else []
                }
            }

    # All required parameters provided - proceed with fetching comment details
    params = {
        'teamId': team_id,
        'team_id': team_id,
        'appId': project_id,
        'app_id': project_id,
        'testCaseId': test_case_id,
        'commentId': comment_id
    }

    # Add optional parameters
    if report_id is not None:
        params['reportId'] = report_id
        params['report_id'] = report_id

    if parent_comment_id is not None:
        params['parentCommentId'] = parent_comment_id

    logger.info(f"get_test_case_comment: Fetching comment_id={comment_id} for test_case_id={test_case_id} in team={team_id}, project={project_id}")

    response = make_api_request('GET', '/v1/testcasecomments/get', api_key, params=params)

    # Log the response for debugging
    if response.get('status') == 'OK':
        logger.info(f"get_test_case_comment: Successfully fetched comment {comment_id} for test case {test_case_id}")

        # Add helpful context to the response
        if 'testCaseCommentsDetails' in response and response['testCaseCommentsDetails']:
            comment_details = response['testCaseCommentsDetails'][0] if isinstance(response['testCaseCommentsDetails'], list) else response['testCaseCommentsDetails']

            # Add metadata about the comment
            response['comment_metadata'] = {
                'has_attachments': bool(comment_details.get('comment_attachments')),
                'attachment_count': len(comment_details.get('comment_attachments_files', [])),
                'has_inline_images': bool(comment_details.get('comment_images')),
                'is_deleted': comment_details.get('is_deleted', False),
                'is_threaded_reply': bool(comment_details.get('parent_comment_id')),
                'creator': comment_details.get('creator_name', 'Unknown')
            }
    else:
        logger.error(f"get_test_case_comment: Failed to fetch comment. Response: {response.get('message', 'Unknown error')}")

        error_msg = response.get('message', 'Unknown error')
        if 'not found' in error_msg.lower() or 'no' in error_msg.lower():
            response['suggestion'] = 'The comment may not exist, may have been deleted, or you may not have permission to view it. Try using list_test_case_comments to see available comments.'

    return response

@mcp.tool(
    name = "update_test_case_comment",
    description = "Update a test case comment. Can update comment content and attachments. Only the comment owner can update their comment. Interactive team/project/test case/comment selection available."
)
def update_test_case_comment(
    api_key: str = Field(description="User's Bugasura API key"),
    comment: str = Field(description="Updated comment content (supports HTML formatting, required)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    test_case_id: Optional[int] = Field(default=None, description="Test case identifier (optional - will prompt if not provided)"),
    comment_id: Optional[int] = Field(default=None, description="Comment identifier to update (optional - will prompt if not provided)"),
    report_id: Optional[int] = Field(default=None, description="Report identifier (optional)"),
    comment_attachments: Optional[str] = Field(default=None, description="Comma-separated list of attachment filenames to keep (optional)")
) -> dict:
    """
    Update a test case comment in Bugasura.
    Interactive flow: If team_id/project_id/test_case_id/comment_id are not provided,
    this function will return available options for the user to select from.
    Args:
        api_key: User's Bugasura API key (required)
        comment: Updated comment content (required) - supports HTML formatting
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        test_case_id: Test case identifier (optional - will prompt if not provided)
        comment_id: Comment identifier to update (optional - will prompt if not provided)
        report_id: Report identifier for test run context (optional)
        comment_attachments: Comma-separated attachment filenames to retain (optional)
    Returns:
        dict: API response with updated comment details
        OR a selection prompt if required parameters not provided
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Validate comment is not empty
    if not comment or comment.strip() == '':
        return {
            'status': 'ERROR',
            'message': 'Comment content is required and cannot be empty'
        }

    # Use centralized context selection helper for team and project
    context = select_team_project_context(
        api_key, team_id, project_id, 'update_test_case_comment',
        f', comment="{comment[:50]}..."'
    )

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Check if test_case_id is provided
    if test_case_id is None:
        # Fetch available test cases for selection using CORRECTED API call
        test_cases_response = make_api_request('GET', '/v1/testcases/list', api_key, params={
            'team_id': team_id,
            'app_id': project_id,
            'start_at': 0,
            'max_results': 100
        })

        # FIXED: Use 'testCasesList' and proper field names
        if test_cases_response.get('status') == 'OK' and test_cases_response.get('testCasesList'):
            return {
                'status': 'selection_required',
                'selection_type': 'test_case',
                'message': 'Please select a test case',
                'available_test_cases': [
                    {
                        'test_case_id': tc.get('id'),  # FIXED: Use 'id' field
                        'test_case_number': tc.get('test_case_number', ''),
                        'title': tc.get('title', 'Untitled Test Case'),
                        'scenario': tc.get('scenario', 'No scenario'),
                        'status': tc.get('status', 'Unknown'),
                        'priority': tc.get('priority', 'Unknown'),
                        'testing_type': tc.get('testing_type', 'Unknown'),
                        'feature_name': tc.get('feature_name', '')
                    }
                    for tc in test_cases_response.get('testCasesList', [])
                ],
                'total_count': test_cases_response.get('totalCount', 0),
                'instructions': 'Call this function again with the selected test_case_id parameter',
                'current_context': {
                    'team_id': team_id,
                    'project_id': project_id,
                    'comment': comment
                }
            }
        else:
            return {
                'status': 'ERROR',
                'message': f'No test cases found for the selected project (team_id={team_id}, project_id={project_id}) or unable to fetch test cases',
                'debug_info': {
                    'response_status': test_cases_response.get('status'),
                    'response_message': test_cases_response.get('message', ''),
                    'response_keys': list(test_cases_response.keys()) if test_cases_response else []
                }
            }

    # Check if comment_id is provided
    if comment_id is None:
        # Fetch available comments for the test case
        comments_params = {
            'team_id': team_id,
            'app_id': project_id,
            'testCaseId': test_case_id
        }

        if report_id is not None:
            comments_params['report_id'] = report_id

        comments_response = make_api_request('GET', '/v1/testcasecomments/list', api_key, params=comments_params)

        if comments_response.get('status') == 'OK' and comments_response.get('testCaseCommentsList'):
            return {
                'status': 'selection_required',
                'selection_type': 'comment',
                'message': 'Please select a comment to update',
                'available_comments': [
                    {
                        'comment_id': c.get('comment_id'),
                        'comment_preview': (c.get('comment', '')[:100] + '...') if len(c.get('comment', '')) > 100 else c.get('comment', ''),
                        'creator_name': c.get('creator_name', 'Unknown'),
                        'created_dt': c.get('created_dt', ''),
                        'last_modified': c.get('last_modified', ''),
                        'is_deleted': c.get('is_deleted', False),
                        'has_attachments': bool(c.get('comment_attachments'))
                    }
                    for c in comments_response.get('testCaseCommentsList', [])
                    if not c.get('is_deleted', False)
                ],
                'instructions': 'Call this function again with the selected comment_id parameter. Note: You can only update comments you created.',
                'current_context': {
                    'team_id': team_id,
                    'project_id': project_id,
                    'test_case_id': test_case_id,
                    'report_id': report_id,
                    'comment': comment
                }
            }
        else:
            return {
                'status': 'ERROR',
                'message': 'No comments found for the selected test case or unable to fetch comments'
            }

    # All required parameters provided - proceed with updating comment
    # Fetch and attach test case details before updating comment
    try:
        tc_before = get_test_case(api_key, testcase_id=test_case_id, team_id=team_id, project_id=project_id)
    except Exception as e:
        tc_before = {'status': 'failed', 'error': str(e)}
    payload = {
        'teamId': team_id,
        'team_id': team_id,
        'appId': project_id,
        'app_id': project_id,
        'testCaseId': test_case_id,
        'commentId': comment_id,
        'comment_id': comment_id,
        'comment': comment
    }

    if report_id is not None:
        payload['reportId'] = report_id
        payload['report_id'] = report_id

    if comment_attachments is not None:
        payload['commentsAttachments'] = comment_attachments
        payload['commentAttachments'] = comment_attachments

    logger.info(f"update_test_case_comment: Updating comment_id={comment_id} for test_case_id={test_case_id} in team={team_id}, project={project_id}")

    response = make_api_request('POST', '/v1/testcasecomments/update', api_key, data=payload)

    if response.get('status') == 'OK':
        logger.info(f"update_test_case_comment: Successfully updated comment {comment_id} for test case {test_case_id}")
    else:
        logger.error(f"update_test_case_comment: Failed to update comment. Response: {response.get('message', 'Unknown error')}")
    # Attach the pre-update test case details to the response
    response['test_case_before'] = tc_before

    # Refresh test case list for the project after comment update
    try:
        refreshed = list_test_cases(api_key, team_id=team_id, project_id=project_id)
        response['test_cases_refresh'] = refreshed
        logger.debug("update_test_case_comment: Refreshed test case list attached to response")
    except Exception as e:
        logger.error(f"update_test_case_comment: Failed to refresh test case list: {e}")
        response['test_cases_refresh_error'] = str(e)

    return response

@mcp.tool(
    name = "delete_test_case_comment",
    description = "Delete a test case comment permanently by comment ID. Supports interactive team/project/test case/comment selection. Only the comment owner can delete their comment. WARNING: This action cannot be undone."
)
def delete_test_case_comment(
    api_key: str = Field(description="User's Bugasura API key"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    test_case_id: Optional[int] = Field(default=None, description="Test case identifier (optional - will prompt if not provided)"),
    comment_id: Optional[int] = Field(default=None, description="Comment identifier to delete (optional - will prompt if not provided)"),
    report_id: Optional[int] = Field(default=None, description="Report identifier (optional)")
) -> dict:
    """
    Delete a test case comment permanently from Bugasura.
    Interactive flow: If team_id/project_id/test_case_id/comment_id are not provided,
    this function will return available options for the user to select from.
    **Important Notes**:
    - WARNING: This action cannot be undone. The comment will be permanently deleted.
    - Only the comment owner (creator) can delete their comment
    - Cannot delete already deleted or system comments
    - Deletes all associated attachments and inline images
    - System sends notifications to assignees and admins
    - Slack notifications sent if configured for the project
    Args:
        api_key: User's Bugasura API key (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        test_case_id: Test case identifier (optional - will prompt if not provided)
        comment_id: Comment identifier to delete (optional - will prompt if not provided)
        report_id: Report identifier for test run context (optional)
    Returns:
        dict: API response with deletion confirmation including:
              - status: 'OK' or 'ERROR'
              - message: Success/error message
              - testCaseCommentsDetails: Updated comment details showing deletion
              - deleted_on: Timestamp of deletion
        OR a selection prompt if required parameters not provided
    Examples:
        # Delete a comment with all IDs provided
        delete_test_case_comment(api_key, team_id=123, project_id=456,
                                test_case_id=789, comment_id=101)
        # Delete with interactive selection
        delete_test_case_comment(api_key)
        # Delete comment from a test run report
        delete_test_case_comment(api_key, team_id=123, project_id=456,
                                test_case_id=789, comment_id=101,
                                report_id=555)
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper for team and project
    context = select_team_project_context(
        api_key, team_id, project_id, 'delete_test_case_comment'
    )

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Check if test_case_id is provided
    if test_case_id is None:
        # Fetch available test cases for selection
        test_cases_response = make_api_request('GET', '/v1/testcases/list', api_key, params={
            'team_id': team_id,
            'app_id': project_id,
            'start_at': 0,
            'max_results': 100
        })

        # FIXED: Check for 'testCasesList' instead of 'testCases'
        if test_cases_response.get('status') == 'OK' and test_cases_response.get('testCasesList'):
            return {
                'status': 'selection_required',
                'selection_type': 'test_case',
                'message': 'Please select a test case',
                'available_test_cases': [
                    {
                        'test_case_id': tc.get('id'),  # Use test_case_id from response
                        'test_case_number': tc.get('test_case_number', ''),
                        'scenario': tc.get('scenario', 'No scenario'),
                        'testing_type': tc.get('testing_type', 'Unknown'),
                        'priority': tc.get('priority', 'Unknown'),
                        'feature_name': tc.get('feature_name', ''),
                        'creator_name': tc.get('creator_name', 'Unknown')
                    }
                    for tc in test_cases_response.get('testCasesList', [])
                ],
                'instructions': 'Call this function again with the selected test_case_id parameter',
                'current_context': {
                    'team_id': team_id,
                    'project_id': project_id
                }
            }
        else:
            return {
                'status': 'ERROR',
                'message': f'No test cases found for the selected project (team_id={team_id}, project_id={project_id}) or unable to fetch test cases',
                'debug_info': {
                    'response_status': test_cases_response.get('status'),
                    'response_keys': list(test_cases_response.keys()) if test_cases_response else []
                }
            }

    # Check if comment_id is provided
    if comment_id is None:
        # Fetch available comments for the test case
        comments_params = {
            'team_id': team_id,
            'app_id': project_id,
            'testCaseId': test_case_id
        }

        if report_id is not None:
            comments_params['report_id'] = report_id

        comments_response = make_api_request('GET', '/v1/testcasecomments/list', api_key, params=comments_params)

        if comments_response.get('status') == 'OK' and comments_response.get('testCaseCommentsList'):
            # Filter out already deleted comments
            available_comments = [
                c for c in comments_response.get('testCaseCommentsList', [])
                if not c.get('is_deleted', False)
            ]

            if not available_comments:
                return {
                    'status': 'ERROR',
                    'message': 'No comments available to delete for this test case'
                }

            return {
                'status': 'selection_required',
                'selection_type': 'comment',
                'message': 'WARNING: Deletion is permanent and cannot be undone. Please select a comment to delete:',
                'available_comments': [
                    {
                        'comment_id': c.get('comment_id'),
                        'comment_preview': (c.get('comment', '')[:100] + '...') if len(c.get('comment', '')) > 100 else c.get('comment', ''),
                        'creator_name': c.get('creator_name', 'Unknown'),
                        'created_dt': c.get('created_dt', ''),
                        'last_modified': c.get('last_modified', ''),
                        'has_attachments': bool(c.get('comment_attachments')),
                        'has_inline_images': bool(c.get('comment_images'))
                    }
                    for c in available_comments
                ],
                'instructions': 'Call this function again with the selected comment_id parameter. Note: You can only delete comments you created.',
                'warning': 'This action cannot be undone. All attachments and inline images will be permanently deleted.',
                'current_context': {
                    'team_id': team_id,
                    'project_id': project_id,
                    'test_case_id': test_case_id,
                    'report_id': report_id
                }
            }
        else:
            return {
                'status': 'ERROR',
                'message': f'No comments found for the selected test case (test_case_id={test_case_id}) or unable to fetch comments',
                'debug_info': {
                    'response_status': comments_response.get('status'),
                    'response_message': comments_response.get('message', ''),
                    'response_keys': list(comments_response.keys()) if comments_response else []
                }
            }

    # All required parameters provided - proceed with deleting comment

    # Build API payload matching the backend API structure
    # The API expects both snake_case and camelCase variants for compatibility
    payload = {
        'teamId': team_id,
        'team_id': team_id,           # Backend checks both formats
        'appId': project_id,
        'app_id': project_id,          # Backend checks both formats
        'testCaseId': test_case_id,
        'commentId': comment_id,
        'comment_id': comment_id       # Backend checks both formats
    }

    # Add optional report_id if provided
    if report_id is not None:
        payload['reportId'] = report_id
        payload['report_id'] = report_id

    # Make POST request to delete test case comment
    logger.info(f"delete_test_case_comment: Deleting comment_id={comment_id} for test_case_id={test_case_id} in team={team_id}, project={project_id}")

    response = make_api_request('POST', '/v1/testcasecomments/delete', api_key, data=payload)

    # Log the response for debugging
    if response.get('status') == 'OK':
        logger.info(f"delete_test_case_comment: Successfully deleted comment {comment_id} for test case {test_case_id}")
        # Add helpful context to the success response
        if 'testCaseCommentsDetails' in response:
            response['info'] = 'Comment has been permanently deleted. All attachments and inline images have been removed.'
    else:
        logger.error(f"delete_test_case_comment: Failed to delete comment. Response: {response.get('message', 'Unknown error')}")
    # Fetch and attach test case details before deleting comment
    try:
        tc_before = get_test_case(api_key, testcase_id=test_case_id, team_id=team_id, project_id=project_id)
        response['test_case_before'] = tc_before
    except Exception as e:
        logger.debug(f"delete_test_case_comment: Could not fetch test case details before deletion: {e}")

    # Refresh test case list for the project after comment deletion
    try:
        refreshed = list_test_cases(api_key, team_id=team_id, project_id=project_id)
        response['test_cases_refresh'] = refreshed
        logger.debug("delete_test_case_comment: Refreshed test case list attached to response")
    except Exception as e:
        logger.error(f"delete_test_case_comment: Failed to refresh test case list: {e}")
        response['test_cases_refresh_error'] = str(e)

    return response

# ============================================================================
# REQUIREMENTS MANAGEMENT TOOLS
# ============================================================================
# Requirements define the features, enhancements, or fixes to be delivered.
# They help teams capture, track, and organize product needs across projects.
# Requirements can be grouped into folders, linked to sprints, and assigned
# priorities and statuses for better planning and tracking.
#
# IMPORTANT: Requirement API endpoints use 'app_id' parameter (not 'project_id')
# This comes from Bugasura’s legacy database structure ('apps' table).
# For consistency in MCP tools:
# - MCP tool parameters: use project_id (clear for developers)
# - API requests: map project_id -> app_id (what the backend expects)
# - A mapping comment is added wherever conversion happens

@mcp.tool(
    name="list_requirements",
    description="List requirements for a project with pagination and filtering. Returns requirement summaries with support for folders, sprints, sorting, and search. Interactive team/project selection available."
)
def list_requirements(
    api_key: str = Field(description="User's Bugasura API key"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier for filtering requirements"),
    folder_id: str = Field(default="", description="Folder identifier (empty string fetches all root requirements)"),
    sort_by: str = Field(default="", description="Sort order for requirements"),
    search_text: str = Field(default="", description="Search text to filter requirements"),
    is_first_load: int = Field(default=0, description="Flag indicating first load (0 or 1)"),
    total_loaded_count: int = Field(default=0, description="Total count of requirements already loaded"),
    page_name: str = Field(default="", description="Page name for context-specific logic"),
    report_id: str = Field(default="", description="Report identifier for filtering"),
    req_type: str = Field(default="", description="Requirement type filter"),
    status: str = Field(default="", description="Requirement status filter"),
    start_at: int = Field(default=0, description="Pagination offset (default: 0)"),
    max_results: int = Field(default=10, description="Number of results to return (default: 10)")
) -> dict:
    """
    List requirements for a project with pagination and filtering.

    Interactive flow: If team_id/project_id are not provided, this function
    will return available options for the user to select from.

    Supports:
    - Folder-based filtering (folderId / all_root / subfolder expansion)
    - Sprint-based filtering (sprintId)
    - Sorting and search capabilities
    - First load logic (isFirstLoad)
    - Modal-specific logic (project_requirement_list_modal)

    Args:
        api_key: User's Bugasura API key (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        sprint_id: Sprint identifier for filtering requirements
        folder_id: Folder identifier (empty string fetches all root requirements)
        sort_by: Sort order for requirements
        search_text: Search text to filter requirements
        is_first_load: Flag indicating first load (0 or 1)
        total_loaded_count: Total count of requirements already loaded
        page_name: Page name for context-specific logic
        report_id: Report identifier for filtering
        req_type: Requirement type filter
        status: Requirement status filter
        start_at: Pagination offset (default: 0)
        max_results: Number of results to return (default: 10)

    Returns:
        dict: List of requirements with pagination metadata including:
            - requirementsList: List of requirement objects
            - totalRequirementsCount: Total count of requirements
            - isAdminUser: Admin status flag
            - standardPriorityList: Available priority options
            - sprintListResp: Available sprints
            - projectRequirementIds: Project-specific requirement IDs (conditional)
            - currentSprintRequirementIds: Current sprint requirement IDs (conditional)
        OR a selection prompt if team_id/project_id not provided
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get("valid"):
        return validation

    # Use centralized context selection helper
    context = select_team_project_context(api_key, team_id, project_id, "list_requirements")

    # If context selection is needed, return the selection prompt
    if "status" in context and context["status"] == "selection_required":
        return context

    # If context selection failed, return the error
    if "status" in context and context["status"] == "failed":
        return context

    # All required parameters provided - proceed with listing requirements
    # Construct request params mapped to API endpoint expectations
    params = {
        "teamId": context["team_id"],
        "appId": context["project_id"],
        "sprintId": sprint_id or "",
        "folderId": folder_id,
        "sortBy": sort_by,
        "searchText": search_text,
        "isFirstLoad": is_first_load,
        "totalLoadedCount": total_loaded_count,
        "pageName": page_name,
        "reportId": report_id,
        "type": req_type,
        "status": status,
        "start_at": start_at,
        "max_results": max_results
    }

    # Make API request to requirements list endpoint
    response = make_api_request(
        "GET",
        "/v1/requirements/list",
        api_key,
        params=params
    )

    # Filter out large unnecessary fields to reduce payload size
    return filter_large_fields(response)


@mcp.tool(
    name="list_requirement_folders",
    description="List all requirement folders for a project with hierarchical structure. Use this to view available folders before creating requirements or to check if a folder name already exists."
)
def list_requirement_folders(
    api_key: str = Field(description="User's Bugasura API key"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    parent_folder_id: Optional[int] = Field(default=None, description="Filter by parent folder ID (optional - omit to get all folders)"),
    include_hierarchy: bool = Field(default=True, description="Include full folder hierarchy (default: True)")
) -> dict:
    """
    List all requirement folders for a project.

    This tool is useful for:
    - Viewing available folders before creating a requirement
    - Checking if a folder name already exists
    - Understanding the folder structure
    - Getting folder IDs for nested folder creation

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    Args:
        api_key: User's Bugasura API key (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        parent_folder_id: Filter by parent folder (optional)
                         - Omit/None: Get all folders
                         - 0: Get only root-level folders
                         - folder_id: Get subfolders of specific folder
        include_hierarchy: Return folders with hierarchical structure (default: True)

    Returns:
        dict: {
            'status': 'OK',
            'folders': [
                {
                    'folder_id': 101,
                    'folder_name': 'Sprint 1 Requirements',
                    'parent_folder_id': 0,
                    'tc_count': 15,
                    'total_tc_count': 25,
                    'children': [...]
                }
            ],
            'folders_count': 5,
            'message': 'Retrieved 5 requirement folders'
        }

    Examples:
        # List all requirement folders
        list_requirement_folders(api_key, team_id=456, project_id=789)

        # List only root-level folders
        list_requirement_folders(api_key, team_id=456, project_id=789, parent_folder_id=0)

        # List subfolders of a specific folder
        list_requirement_folders(api_key, team_id=456, project_id=789, parent_folder_id=101)

        # Interactive mode
        list_requirement_folders(api_key)
    """
    # Validate API key
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection
    context = select_team_project_context(api_key, team_id, project_id, 'list_requirement_folders')

    if context.get('status') == 'selection_required':
        return context

    # Extract validated IDs
    team_id = context['team_id']
    project_id = context['project_id']

    logger.info(f"list_requirement_folders: Fetching requirement folders for project_id={project_id}, parent_folder_id={parent_folder_id}")

    # Build request parameters
    params = {
        'appId': project_id,
        'folderId': 0,
        'parentFolderId': 0,
        'folderType': 'REQUIREMENTS'
    }

    # Make API request to get folders
    response = make_api_request('GET', '/v1/testRepo/get', api_key, params=params)

    if response.get('status') != 'OK':
        logger.error(f"list_requirement_folders: Failed to fetch folders: {response.get('message')}")
        return {
            'status': 'failed',
            'error': 'Failed to fetch requirement folders',
            'message': response.get('message', 'Could not retrieve folder list')
        }

    # Extract folders from response
    all_folders = response.get('foldersList', [])

    # Filter folders if parent_folder_id is specified
    filtered_folders = []
    if parent_folder_id is not None:
        # Filter by parent folder
        for folder in all_folders:
            if folder.get('parent_folder_id') == parent_folder_id:
                filtered_folders.append(folder)
        logger.info(f"list_requirement_folders: Filtered {len(filtered_folders)} folders with parent_folder_id={parent_folder_id}")
    else:
        # Return all folders
        filtered_folders = all_folders
        logger.info(f"list_requirement_folders: Retrieved {len(filtered_folders)} total folders")

    # Build clean response
    folders_list = []
    for folder in filtered_folders:
        folder_info = {
            'folder_id': folder.get('folder_id'),
            'folder_name': folder.get('folder_name'),
            'parent_folder_id': folder.get('parent_folder_id'),
            'tc_count': folder.get('tc_count', 0),
            'total_tc_count': folder.get('total_tc_count', 0)
        }

        # Include children if hierarchy is requested
        if include_hierarchy and 'children' in folder:
            folder_info['children'] = folder.get('children', [])

        folders_list.append(folder_info)

    # Build summary message
    if parent_folder_id == 0:
        message = f"Retrieved {len(folders_list)} root-level requirement folders"
    elif parent_folder_id is not None:
        message = f"Retrieved {len(folders_list)} subfolders under parent folder {parent_folder_id}"
    else:
        message = f"Retrieved {len(folders_list)} requirement folders"

    return {
        'status': 'OK',
        'folders': folders_list,
        'folders_count': len(folders_list),
        'project_id': project_id,
        'team_id': team_id,
        'message': message
    }


@mcp.tool(
    name="create_requirement",
    description="Create a new requirement in Bugasura with automatic folder management. If no folder exists for requirements, creates a default folder first. Supports smart assignee resolution and interactive team/project selection."
)
def create_requirement(
    api_key: str = Field(description="User's Bugasura API key"),
    title: str = Field(description="Requirement title"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    app_id: Optional[int] = Field(default=None, description="Application identifier"),
    details: str = Field(default="", description="Detailed description of the requirement"),
    overview: str = Field(default="", description="Brief overview of the requirement"),
    priority: str = Field(default="P2", description="Priority level (e.g., P0, P1, P2, P3, P4)"),
    severity: str = Field(default="MEDIUM", description="Severity level (e.g., LOW, MEDIUM, HIGH, CRITICAL)"),
    source: str = Field(default="CUSTOM", description="Requirement source (e.g., CUSTOM, JIRA, ASANA, GITHUB, FIGMA, GOOGLE_DOCS) (default: CUSTOM)"),
    assignees: Optional[str] = Field(default=None, description="Comma-separated assignee identifiers or names (supports smart resolution)"),
    folder_id: Optional[int] = Field(default=None, description="Folder identifier - if not provided, uses or creates default folder"),
    folder_name: str = Field(default="Requirements", description="Folder name to use/create if folder_id not provided (default: 'Requirements')"),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier"),
    type: str = Field(default="EPIC", description="Requirement type (e.g., EPIC, STORY, TASK)"),
    status: str = Field(default="NEW", description="Requirement status (e.g., NEW, IN_PROGRESS, COMPLETED)"),
    parent_id: Optional[int] = Field(default=None, description="Parent requirement ID for hierarchical structure"),
    tags: str = Field(default="", description="Comma-separated tags for categorization"),
    isQuickAdd: int = Field(default=0, description="Quick add flag (0 or 1)")
) -> dict:
    """
    Create a new requirement in Bugasura with automatic folder management.

    **Automatic Folder Management**:
    - If folder_id is provided, uses that folder
    - If folder_id is not provided:
      1. Checks if a requirements folder exists
      2. If exists, uses the first available folder
      3. If not, creates a new folder with the specified folder_name

    This ensures requirements are always organized in folders without manual setup.

    Args:
        api_key: Bugasura API Key (required)
        title: Requirement title (required)
        team_id: Team ID (optional – auto-select flow)
        project_id: Project ID (optional – auto-select flow)
        app_id: Application ID (takes precedence over project_id)
        details: Requirement details
        overview: Requirement overview
        priority: P0/P1/P2/P3/P4 (default P2)
        severity: CRITICAL/HIGH/MEDIUM/LOW (default MEDIUM)
        source: CUSTOM/JIRA/ASANA/GITHUB/FIGMA/GOOGLE_DOCS/etc. (default CUSTOM) - Requirement source
        assignees: Comma-separated names, emails, or IDs
        folder_id: Folder ID - if not provided, auto-selects or creates folder
        folder_name: Name for new folder if creation needed (default: 'Requirements')
        sprint_id: Optional sprint ID (0 if not assigned)
        type: EPIC/STORY/TASK/BUG (default EPIC)
        status: NEW/IN_PROGRESS/COMPLETED/BLOCKED (default NEW)
        parent_id: Parent requirement ID for sub-requirements
        tags: Comma-separated tags
        isQuickAdd: 0 or 1 (default 0)

    Returns:
        dict: {
            'status': 'OK',
            'message': 'Requirement created successfully',
            'requirement_id': int,
            'folder_id_used': int,
            ...
        }

    Examples:
        # Simple - Auto-manages folders
        create_requirement(
            api_key="your_api_key",
            title="User Authentication Feature",
            team_id=123,
            project_id=456
        )

        # With custom folder name
        create_requirement(
            api_key="your_api_key",
            title="Payment Integration",
            folder_name="Payment Features",
            details="Integrate Stripe payment gateway",
            severity="HIGH",
            priority="P1"
        )

        # With explicit folder
        create_requirement(
            api_key="your_api_key",
            title="Dashboard Update",
            folder_id=789,
            assignees="john@example.com, jane@example.com"
        )

        # From Figma designs
        create_requirement(
            api_key="your_api_key",
            title="New UI Component",
            source="FIGMA",
            details="Design from Figma prototype",
            severity="MEDIUM"
        )
    """
    # Validate required title parameter
    if not title or not title.strip():
        logger.error("create_requirement: title parameter is required")
        return {
            'status': 'failed',
            'error': 'title is required',
            'error_type': 'ValidationError',
            'message': 'Please provide a requirement title'
        }

    logger.info(f"create_requirement: Starting for title='{title}'")

    # Validate API key
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        logger.error(f"create_requirement: API key validation failed")
        return validation

    # Use common team/project selection flow
    context = select_team_project_context(
        api_key,
        team_id,
        project_id,
        'create_requirement',
        f', title="{title}"'
    )

    # If context selection is needed, return the selection prompt
    if context.get("status") == "selection_required":
        logger.info("create_requirement: Context selection required")
        return context

    # Extract validated context
    team_id = context["team_id"]
    project_id = context["project_id"]

    # Use app_id if provided, otherwise use project_id
    if app_id is not None:
        project_id = app_id
        logger.info(f"create_requirement: Using app_id={app_id} as project_id")

    # Get the correct team_id for this project from the project details
    logger.info(f"create_requirement: Fetching project details to verify team_id")
    project_details_response = make_api_request('GET', '/v1/projects/get', api_key, params={
        'team_id': team_id,
        'project_id': project_id
    })

    if project_details_response.get('status') == 'OK':
        project_team_id = project_details_response.get('project_details', {}).get('team_id')
        if project_team_id and project_team_id != team_id:
            logger.warning(f"create_requirement: Team ID mismatch - context team_id={team_id}, project team_id={project_team_id}. Using project's team_id.")
            team_id = project_team_id
    else:
        logger.warning(f"create_requirement: Could not verify team_id from project details, proceeding with context team_id={team_id}")

    logger.info(f"create_requirement: Using team_id={team_id}, project_id={project_id}")

    # If folder_id not provided, get or create a requirements folder
    if folder_id is None:
        logger.info(f"create_requirement: No folder_id provided, checking for existing requirements folders")

        # Get test repo folder structure for requirements
        folder_check_params = {
            'appId': str(project_id),
            'teamId': str(team_id),
            'folderId': '',
            'parentFolderId': '',
            'isGetReportList': 0,
            'folderType': 'REQUIREMENTS'
        }

        logger.debug(f"create_requirement: Calling testRepo/get with params: {folder_check_params}")
        folder_check_response = make_api_request(
            'GET',
            '/v1/testRepo/get',
            api_key,
            params=folder_check_params
        )

        if folder_check_response.get('status') == 'OK':
            folder_structure = folder_check_response.get('tcRepoStructure', [])
            logger.debug(f"create_requirement: Found folder structure with {len(folder_structure)} folders")

            if folder_structure and len(folder_structure) > 0:
                # Use the first available requirements folder
                folder_id = folder_structure[0].get('id')
                existing_folder_name = folder_structure[0].get('name', 'Unknown')
                logger.info(f"create_requirement: Found existing requirements folder '{existing_folder_name}', using folder_id={folder_id}")
            else:
                # No folders exist, create a new one
                logger.info(f"create_requirement: No requirements folders found, creating new folder '{folder_name}'")

                create_folder_payload = {
                    'appId': str(project_id),
                    'teamId': str(team_id),
                    'parentFolderId': '',
                    'folderName': folder_name,
                    'isRootFolder': 1,
                    'folderType': 'REQUIREMENTS'
                }

                logger.debug(f"create_requirement: Calling testRepo/add with payload: {create_folder_payload}")
                create_folder_response = make_api_request(
                    'POST',
                    '/v1/testRepo/add',
                    api_key,
                    data=create_folder_payload
                )

                if create_folder_response.get('status') == 'OK':
                    folder_id = create_folder_response.get('folderDetails', {}).get('id')
                    logger.info(f"create_requirement: Successfully created new requirements folder with folder_id={folder_id}")
                else:
                    error_msg = create_folder_response.get('message', 'Unknown error')
                    logger.error(f"create_requirement: Failed to create requirements folder: {error_msg}")
                    return {
                        'status': 'failed',
                        'error': 'Failed to create requirements folder',
                        'message': f'Could not create folder for requirements: {error_msg}',
                        'details': create_folder_response
                    }
        else:
            error_msg = folder_check_response.get('message', 'Unknown error')
            logger.error(f"create_requirement: Failed to check for existing folders: {error_msg}")
            return {
                'status': 'failed',
                'error': 'Failed to check for existing folders',
                'message': f'Could not verify folder structure: {error_msg}',
                'details': folder_check_response
            }
    else:
        logger.info(f"create_requirement: Using provided folder_id={folder_id}")

    # Verify we have a valid folder_id at this point
    if folder_id is None:
        logger.error(f"create_requirement: folder_id is still None after folder management logic")
        return {
            'status': 'failed',
            'error': 'Could not determine folder for requirement',
            'message': 'Failed to find or create a folder for the requirement. Please provide folder_id explicitly.'
        }

    logger.info(f"create_requirement: Proceeding with folder_id={folder_id}")

    # Resolve assignees (smart names/emails to IDs)
    assignee_ids_str = ""
    if assignees and assignees.strip():
        logger.info(f"create_requirement: Resolving assignees '{assignees}' for team_id={team_id}")

        try:
            resolution = _find_user_ids_by_names_or_emails(api_key, team_id, assignees)

            if resolution["status"] != "OK":
                logger.error(f"create_requirement: Failed to resolve assignees: {resolution.get('error')}")
                return resolution

            # Convert list to comma-separated string as expected by API
            user_ids_list = resolution["user_ids"].split(',')
            assignee_ids_str = ",".join(user_ids_list)
            logger.info(f"create_requirement: Resolved to user IDs: {assignee_ids_str}")
        except Exception as e:
            logger.error(f"create_requirement: Exception while resolving assignees: {str(e)}")
            return {
                'status': 'failed',
                'error': 'Failed to resolve assignees',
                'message': f'Error resolving assignee identifiers: {str(e)}'
            }

    # Validate and normalize priority
    priority = priority.upper() if isinstance(priority, str) else str(priority)
    logger.debug(f"create_requirement: Normalized priority to: {priority}")

    # Validate severity
    severity = severity.upper()
    allowed_severity = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    if severity not in allowed_severity:
        logger.error(f"create_requirement: Invalid severity: {severity}")
        return {
            'status': 'failed',
            'error': f'Invalid severity: {severity}',
            'message': f'Severity must be one of: {", ".join(allowed_severity)}'
        }

    # Validate type
    type = type.upper()
    allowed_types = ['EPIC', 'STORY', 'TASK', 'BUG']
    if type not in allowed_types:
        logger.error(f"create_requirement: Invalid type: {type}")
        return {
            'status': 'failed',
            'error': f'Invalid type: {type}',
            'message': f'Type must be one of: {", ".join(allowed_types)}'
        }

    # Validate status
    status = status.upper()
    allowed_status = ['NEW', 'IN_PROGRESS', 'COMPLETED', 'BLOCKED']
    if status not in allowed_status:
        logger.error(f"create_requirement: Invalid status: {status}")
        return {
            'status': 'failed',
            'error': f'Invalid status: {status}',
            'message': f'Status must be one of: {", ".join(allowed_status)}'
        }

    # Validate source - database allowed values
    source = source.upper()
    allowed_sources = [
        'JIRA', 'ASANA', 'GITHUB', 'CUSTOM', 'FILE_UPLOAD', 'API_DOCS',
        'IMAGES', 'ARCHITECTURE_IMAGES', 'DB_SCHEMA_IMAGES', 'WIREFRAME_IMAGES',
        'DESIGN_IMAGES', 'FLOW_IMAGES', 'FIGMA', 'GOOGLE_DOCS'
    ]
    if source not in allowed_sources:
        logger.error(f"create_requirement: Invalid source: {source}")
        return {
            'status': 'failed',
            'error': f'Invalid source: {source}',
            'message': f'Source must be one of: CUSTOM, JIRA, ASANA, GITHUB, FIGMA, GOOGLE_DOCS, FILE_UPLOAD, API_DOCS, or image types (IMAGES, ARCHITECTURE_IMAGES, DB_SCHEMA_IMAGES, WIREFRAME_IMAGES, DESIGN_IMAGES, FLOW_IMAGES)'
        }

    # Build payload matching API expectations
    payload = {
        "teamId": str(team_id),
        "team_id": str(team_id),        # Include both formats for compatibility
        "appId": str(project_id),
        "app_id": str(project_id),      # Include both formats for compatibility
        "folderId": str(folder_id),
        "folder_id": str(folder_id),    # Include both formats for compatibility
        "title": title,
        "details": details,
        "severity": severity,
        "priority": priority,
        "source": source,               # User-configurable requirement source (default: CUSTOM)
        "assignees": assignee_ids_str,
        "tags": tags,
        "isQuickAdd": isQuickAdd,
        "type": type,
        "overview": overview,
        "status": status,
        "sprintId": sprint_id if sprint_id else 0,
    }

    # Add optional parent_id if provided
    if parent_id is not None and parent_id > 0:
        payload["parentId"] = str(parent_id)
        logger.debug(f"create_requirement: Added parent_id: {parent_id}")

    logger.info(f"create_requirement: Submitting requirement to API")
    logger.debug(f"create_requirement: Payload keys: {list(payload.keys())}")

    response = make_api_request("POST", "/v1/requirement/add", api_key, data=payload)

    if response.get('status') == 'OK':
        # Add folder info to successful response for user reference
        response['folder_id_used'] = folder_id
        logger.info(f"create_requirement: Successfully created requirement in folder_id={folder_id}")

        # Log requirement ID if available
        if 'requirement_id' in response:
            logger.info(f"create_requirement: Created requirement_id={response['requirement_id']}")
    else:
        error_msg = response.get('message', 'Unknown error')
        logger.error(f"create_requirement: Failed to create requirement: {error_msg}")

    logger.info(f"create_requirement: END")
    return response


@mcp.tool(
    name="get_requirement_details",
    description="Get specific requirement details by ID. Returns full requirement data, parent details, and priority list. Interactive team/project selection available."
)
def get_requirement_details(
    api_key: str = Field(description="User's Bugasura API key"),
    requirement_id: int = Field(description="Requirement numeric ID"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier")
) -> dict:
    """
    Get specific requirement details.

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    Args:
        api_key: User's Bugasura API key (required)
        requirement_id: Requirement identifier (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        sprint_id: Optional sprint ID for context

    Returns:
        dict: Complete requirement details including:
              - requirementDetails: The main requirement data
              - parentRequirementDetails: Parent requirement if applicable
              - standardPriorityList: Priority settings for the project
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = select_team_project_context(
        api_key,
        team_id,
        project_id,
        'get_requirement_details',
        f', requirement_id={requirement_id}'
    )

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # GET request - build parameters
    # NOTE: API accepts both camelCase and snake_case variants
    params = {
        'requirementId': requirement_id,  # Can also use 'requirement_id'
        'appId': context['project_id'],    # Can also use 'app_id'
    }

    # Add sprint context if provided
    # NOTE: API uses 'report_id' for sprint identifier (legacy naming)
    if sprint_id is not None:
        params['sprintId'] = sprint_id  # Can also use 'report_id'

    response = make_api_request(
        'GET',
        '/v1/requirement/get',
        api_key,
        params=params
    )

    # Return full response with requirement details, parent details, and priority list
    return response


@mcp.tool(
    name="update_requirement",
    description="Update a requirement by ID with partial fields. Can update any field including title, details, severity, priority, tags, status, assignees, type, folder, sprint, overview, and parent requirement. Interactive team/project selection available."
)
def update_requirement(
    api_key: str = Field(description="User's Bugasura API key"),
    requirement_id: int = Field(description="Requirement numeric ID to update"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    title: Optional[str] = Field(default=None, description="Updated requirement title"),
    details: Optional[str] = Field(default=None, description="Updated detailed description"),
    severity: Optional[str] = Field(default=None, description="Updated severity level (e.g., LOW, MEDIUM, HIGH, CRITICAL)"),
    priority: Optional[str] = Field(default=None, description="Updated priority level (e.g., P0, P1, P2, P3, P4)"),
    assignees: Optional[str] = Field(default=None, description="Updated comma-separated assignee identifiers or names"),
    tags: Optional[str] = Field(default=None, description="Updated comma-separated tags"),
    folder_id: Optional[int] = Field(default=None, description="Updated folder identifier"),
    sprint_id: Optional[int] = Field(default=None, description="Updated sprint identifier"),
    type: Optional[str] = Field(default=None, description="Updated requirement type (e.g., EPIC, STORY, TASK)"),
    overview: Optional[str] = Field(default=None, description="Updated brief overview"),
    status: Optional[str] = Field(default=None, description="Updated requirement status (e.g., NEW, IN_PROGRESS, COMPLETED)"),
    parent_id: Optional[int] = Field(default=None, description="Updated parent requirement ID")
) -> dict:
    """
    Update a requirement. Only updates the fields that are provided.

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    **Smart Assignee Resolution**: The assignees parameter automatically converts
    user names or emails to user IDs. You can provide:
    - User IDs (e.g., "123")
    - Email addresses (e.g., "john@example.com")
    - Names or partial names (e.g., "John", "John Doe")
    - Mix of any of the above (e.g., "John, jane@example.com, 789")

    Args:
        api_key: User's Bugasura API key (required)
        requirement_id: Requirement identifier to update (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        title: Requirement title (optional)
        details: Requirement details/description (optional)
        severity: CRITICAL/HIGH/MEDIUM/LOW (optional)
        priority: Priority of the requirement (optional)
        assignees: Comma-separated names, emails, or user IDs (optional)
        tags: Comma-separated tags (optional)
        folder_id: Folder ID for organization (optional)
        sprint_id: Sprint/Report ID (optional)
        type: Requirement type - EPIC/STORY/TASK (optional)
        overview: Requirement overview (optional)
        status: Requirement status - NEW/IN_PROGRESS/COMPLETED/BLOCKED (optional)
        parent_id: Parent requirement ID for hierarchy (optional)

    Returns:
        dict: API response with update status

    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if isinstance(validation, list):
        return {'status': 'failed', 'error': 'Unexpected API response format', 'details': str(validation)}
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = select_team_project_context(
        api_key, team_id, project_id,
        'update_requirement',
        f', requirement_id={requirement_id}'
    )

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Step 1: Fetch existing requirement details
    # MANDATORY: We MUST fetch existing requirement to get folder_id and type if not provided
    # Backend requires folder_id (min=1) and type for updates
    logger.info(f"Fetching existing requirement details for requirement_id={requirement_id}")

    existing_req_response = make_api_request('GET', '/v1/requirement/get', api_key, params={
        'team_id': team_id,
        'app_id': project_id,
        'requirement_id': requirement_id
    })

    # Handle case where API might return a list instead of dict
    if isinstance(existing_req_response, list):
        if len(existing_req_response) == 0:
            return {
                'status': 'failed',
                'error': 'Requirement not found',
                'error_type': 'RequirementNotFound',
                'message': f"Requirement with ID {requirement_id} not found (empty response)"
            }
        existing_req_response = existing_req_response[0]

    # Check if fetch was successful
    if existing_req_response.get('status') != 'OK':
        logger.error(f"Failed to fetch existing requirement: {existing_req_response.get('message')}")
        return {
            'status': 'failed',
            'error': 'Could not fetch existing requirement details',
            'error_type': 'RequirementFetchError',
            'message': f"Unable to update requirement. Error: {existing_req_response.get('message', 'Unknown error')}",
            'details': existing_req_response
        }

    # Step 2: Extract existing requirement data
    req_data = existing_req_response.get('requirementDetails', {})

    # Handle case where requirementDetails is a list instead of dict
    if isinstance(req_data, list):
        if len(req_data) > 0:
            req_data = req_data[0]
            logger.info(f"Converted requirementDetails list to dict")
        else:
            req_data = {}
            logger.warning(f"requirementDetails was empty list, using empty dict")

    if not req_data:
        logger.error(f"No requirement data found for requirement_id={requirement_id}")
        return {
            'status': 'failed',
            'error': 'Requirement not found',
            'error_type': 'RequirementNotFound',
            'message': f"Requirement with ID {requirement_id} not found"
        }

    logger.info(f"Fetched existing requirement data. Preparing update...")

    # Validate enum fields if provided
    if type is not None:
        type = type.upper()
        valid_types = ['EPIC', 'STORY', 'TASK']
        if type not in valid_types:
            return {
                'status': 'failed',
                'error': 'Invalid requirement type',
                'message': f"Type must be one of: {', '.join(valid_types)}. Got: {type}"
            }

    if status is not None:
        status = status.upper()
        valid_statuses = ['NEW', 'IN_PROGRESS', 'COMPLETED', 'BLOCKED']
        if status not in valid_statuses:
            return {
                'status': 'failed',
                'error': 'Invalid requirement status',
                'message': f"Status must be one of: {', '.join(valid_statuses)}. Got: {status}"
            }

    if severity is not None:
        severity = severity.upper()
        valid_severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        if severity not in valid_severities:
            return {
                'status': 'failed',
                'error': 'Invalid severity',
                'message': f"Severity must be one of: {', '.join(valid_severities)}. Got: {severity}"
            }

    # Handle assignee resolution if provided
    resolved_assignees = None
    if assignees is not None:
        logger.info(f"update_requirement: Resolving assignee identifiers '{assignees}' for team_id={team_id}")
        resolution_result = _find_user_ids_by_names_or_emails(api_key, team_id, assignees)
        if resolution_result['status'] != 'OK':
            logger.error(f"update_requirement: Failed to resolve assignee identifiers: {resolution_result.get('error')}")
            return resolution_result

        resolved_assignees = resolution_result['user_ids']
        logger.info(f"update_requirement: Resolved assignees to user_ids: {resolved_assignees}")

    # Validate parent_id if provided (only if it's a positive integer)
    if parent_id is not None and parent_id > 0:
        logger.info(f"Validating parent_id={parent_id}")
        parent_req_response = make_api_request('GET', '/v1/requirement/get', api_key, params={
            'team_id': team_id,
            'app_id': project_id,
            'requirement_id': parent_id
        })

        if parent_req_response.get('status') == 'failed':
            logger.warning(f"Could not validate parent requirement {parent_id}, proceeding anyway")
            # Don't fail here - let the API validate

    # Step 3: Build payload with required fields
    # NOTE: Requirement endpoints use 'app_id' and 'requirement_id' (with underscore)
    payload = {
        "app_id": project_id,
        "requirement_id": requirement_id,
        "team_id": team_id
    }

    # MANDATORY FIELDS: folder_id and type
    # Backend validation requires folder_id (min=1) - cannot be empty
    # We must always send these fields (either new value or existing value)

    # folder_id - MANDATORY (backend min validation = 1)
    if folder_id is not None:
        payload['folder_id'] = folder_id
        logger.debug(f"Using provided folder_id: {folder_id}")
    elif req_data.get('folder_id'):
        payload['folder_id'] = req_data.get('folder_id')
        logger.debug(f"Using existing folder_id: {req_data.get('folder_id')}")
    else:
        # This should not happen since we validated req_data exists
        logger.error(f"No folder_id available for requirement {requirement_id}")
        return {
            'status': 'failed',
            'error': 'Missing mandatory field',
            'message': 'folder_id is required but not found in existing requirement data'
        }

    # type - Include existing value if not updating
    if type is not None:
        payload['type'] = type
        logger.debug(f"Updating type to: {type}")
    elif req_data.get('type'):
        payload['type'] = req_data.get('type')
        logger.debug(f"Using existing type: {req_data.get('type')}")

    # OPTIONAL FIELDS: Only add if user provided new values
    if title is not None:
        payload['title'] = title
        logger.debug(f"Updating title")
    if details is not None:
        payload['details'] = details
        logger.debug(f"Updating details")
    if severity is not None:
        payload['severity'] = severity
        logger.debug(f"Updating severity to: {severity}")
    if priority is not None:
        payload['priority'] = priority
        logger.debug(f"Updating priority to: {priority}")
    if tags is not None:
        payload['tags'] = tags
        logger.debug(f"Updating tags")
    if overview is not None:
        payload['overview'] = overview
        logger.debug(f"Updating overview")
    if status is not None:
        payload['status'] = status
        logger.debug(f"Updating status to: {status}")

    # Handle assignees - only add if user provided new assignees
    if resolved_assignees is not None:
        payload['assignees'] = resolved_assignees
        logger.debug(f"Updating assignees to: {resolved_assignees}")

    # Handle sprint_id - support both camelCase and snake_case
    if sprint_id is not None:
        payload['sprintId'] = sprint_id
        payload['report_id'] = sprint_id
        logger.debug(f"Updating sprint_id to: {sprint_id}")

    # Handle parent_id - support both camelCase and snake_case
    if parent_id is not None:
        payload['parentId'] = parent_id
        payload['parent_id'] = parent_id
        logger.debug(f"Updating parent_id to: {parent_id}")

    # Calculate fields being updated for logging
    update_fields = [k for k in payload.keys() if k not in ['app_id', 'requirement_id', 'team_id']]
    logger.info(f"Updating requirement {requirement_id} with {len(update_fields)} field(s): {', '.join(update_fields)}")

    # Step 5: Make the update request
    logger.info(f"Sending update request for requirement_id={requirement_id}")
    response = make_api_request('POST', '/v1/requirement/update', api_key, data=payload)

    # Add helpful information to response
    if response.get('status') == 'OK':
        response['updated_fields'] = update_fields
        logger.info(f"Successfully updated requirement {requirement_id}")
    else:
        logger.error(f"Failed to update requirement {requirement_id}: {response.get('message')}")

    return response


@mcp.tool(
    name="create_requirement_folder",
    description="Create a new folder for organizing requirements in a project. Folders help organize requirements into logical groups."
)
def create_requirement_folder(
    api_key: str = Field(description="User's Bugasura API key"),
    folder_name: str = Field(description="Name for the new folder"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    parent_folder_id: int = Field(default=0, description="Parent folder ID for nested folders (0 for root level)")
) -> dict:
    """
    Create a new folder for organizing requirements.

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    Args:
        api_key: User's Bugasura API key (required)
        folder_name: Name for the new folder (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        parent_folder_id: Parent folder ID for nested folders (default: 0 for root level)
                         Set to 0 or omit for root-level folders
                         Set to folder ID for nested folders

    Returns:
        dict: {
            'status': 'OK',
            'folder_id': 123,
            'folder_name': 'New Folder',
            'message': 'Folder created successfully'
        }

    Examples:
        # Create a root-level folder (parent_folder_id defaults to 0)
        create_requirement_folder(api_key, folder_name="Sprint 1 Requirements", team_id=456, project_id=789)

        # Create a nested folder under an existing folder
        create_requirement_folder(api_key, folder_name="User Stories", team_id=456, project_id=789, parent_folder_id=123)

        # Interactive context selection
        create_requirement_folder(api_key, folder_name="Product Features")
    """
    # Validate API key
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection
    context = select_team_project_context(api_key, team_id, project_id, 'create_requirement_folder', f', folder_name="{folder_name}"')

    if context.get('status') == 'selection_required':
        return context

    # Extract validated IDs
    team_id = context['team_id']
    project_id = context['project_id']

    # Validate folder_name
    if not folder_name or not folder_name.strip():
        return {
            'status': 'failed',
            'error': 'Folder name is required',
            'message': 'Please provide a valid folder name'
        }

    folder_name = folder_name.strip()

    # Check if folder with same name already exists at the same level
    logger.info(f"create_requirement_folder: Checking for duplicate folder name '{folder_name}' at parent_folder_id={parent_folder_id}")

    # Fetch existing folders to check for duplicates
    existing_folders_response = make_api_request('GET', '/v1/testRepo/get', api_key, params={
        'appId': project_id,
        'folderId': 0,
        'parentFolderId': 0,
        'folderType': 'REQUIREMENTS'
    })

    if existing_folders_response.get('status') == 'OK':
        existing_folders = existing_folders_response.get('foldersList', [])

        # Check for duplicate names at the same parent level
        for folder in existing_folders:
            if folder.get('parent_folder_id') == parent_folder_id and folder.get('folder_name', '').lower() == folder_name.lower():
                parent_msg = "root level" if parent_folder_id == 0 else f"under parent folder ID {parent_folder_id}"
                logger.warning(f"create_requirement_folder: Duplicate folder name '{folder_name}' found at {parent_msg}")
                return {
                    'status': 'failed',
                    'error': 'Duplicate folder name',
                    'error_type': 'DuplicateFolderName',
                    'message': f"A folder named '{folder_name}' already exists at {parent_msg}. Please use a different name.",
                    'existing_folder_id': folder.get('folder_id'),
                    'existing_folder_name': folder.get('folder_name'),
                    'suggestion': f"Try names like: '{folder_name} 2', '{folder_name} (New)', or a different name"
                }
    else:
        # If we can't fetch folders, log warning but continue (API will validate)
        logger.warning(f"create_requirement_folder: Could not fetch folders for duplicate check: {existing_folders_response.get('message')}")

    # Determine if this is a root folder
    # IMPORTANT: API expects empty string '' for root folders, not 0
    is_root_folder = 1 if parent_folder_id == 0 else 0
    parent_folder_id_str = '' if parent_folder_id == 0 else str(parent_folder_id)

    logger.info(f"create_requirement_folder: Creating folder '{folder_name}' for project_id={project_id}, parent_folder_id={parent_folder_id_str or 'root'}, is_root_folder={is_root_folder}")

    # Build payload for folder creation
    # NOTE: API validation expects empty string for root folders (line 344 in TestRepo.php)
    payload = {
        'appId': project_id,
        'folderName': folder_name,
        'parentFolderId': parent_folder_id_str,  # Empty string for root folders
        'isRootFolder': is_root_folder,
        'folderType': 'REQUIREMENTS'
    }

    # Call API to create folder
    response = make_api_request('POST', '/v1/testRepo/add', api_key, data=payload)

    if response.get('status') == 'OK':
        # Extract folder ID from folderDetails (API returns: folderDetails.id)
        folder_details = response.get('folderDetails', {})
        created_folder_id = folder_details.get('id')

        logger.info(f"create_requirement_folder: Successfully created folder '{folder_name}' with ID={created_folder_id}")
        return {
            'status': 'OK',
            'folder_id': created_folder_id,
            'folder_name': folder_name,
            'folder_details': folder_details,
            'message': f"Folder '{folder_name}' created successfully (ID: {created_folder_id})"
        }
    else:
        logger.error(f"create_requirement_folder: Failed to create folder '{folder_name}': {response.get('message')}")
        return response


@mcp.tool(
    name = "delete_requirement",
    description = "Delete requirement(s) permanently by numeric ID, requirement key (e.g., 'REQ5', 'MCP11'), or exact/partial title match. Supports single or multiple deletions. Uses 3-step matching: exact key → exact title → partial title. Interactive selection available."
)
def delete_requirement(
    api_key: str = Field(description="User's Bugasura API key"),
    requirement_identifier: str = Field(description="Requirement identifier: numeric ID (e.g., '123'), requirement key (e.g., 'REQ5', 'MCP11'), or requirement title text for matching"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    sprint_id: Optional[int] = Field(default=None, description="Sprint ID (optional - if provided, deletes from sprint; otherwise deletes from project)"),
    folder_id: Optional[int] = Field(default=None, description="Folder ID (optional)"),
    selected_requirement_ids: Optional[str] = Field(default=None, description="Comma-separated list of requirement IDs for bulk deletion (optional)")
) -> dict:
    """
    Delete requirement(s) from Bugasura by ID, requirement key, or title name.

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    WARNING: This action cannot be undone. The requirement and all its associated
    data will be permanently removed.

    Deletion Modes:
    - Sprint deletion: If sprint_id is provided, removes requirement from sprint only
    - Project deletion: If sprint_id is not provided, permanently deletes requirement from project
    - Bulk deletion: Use selected_requirement_ids for multiple deletions

    Args:
        api_key: User's Bugasura API key (required)
        requirement_identifier: Requirement ID (numeric), requirement key (e.g., "REQ5", "MCP11"), or title (string) to delete (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        sprint_id: Sprint identifier - if provided, removes from sprint; if not, deletes from project (optional)
        folder_id: Folder identifier (optional)
        selected_requirement_ids: Comma-separated requirement IDs for bulk deletion (optional)

    Returns:
        dict: {
            'status': 'OK',
            'message': 'Requirement deleted successfully'
        }

    Examples:
        # Delete a requirement by numeric ID from project
        delete_requirement(api_key, requirement_identifier="123", team_id=456, project_id=789)

        # Delete a requirement by key
        delete_requirement(api_key, requirement_identifier="REQ5", team_id=456, project_id=789)

        # Delete a requirement by title
        delete_requirement(api_key, requirement_identifier="User Authentication Feature", team_id=456, project_id=789)

        # Remove requirement from sprint (unlink, not delete)
        delete_requirement(api_key, requirement_identifier="REQ5", team_id=456, project_id=789, sprint_id=101)

        # Bulk delete multiple requirements
        delete_requirement(api_key, requirement_identifier="", team_id=456, project_id=789, selected_requirement_ids="123,124,125")

        # Delete with interactive context selection
        delete_requirement(api_key, requirement_identifier="REQ5")
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = select_team_project_context(api_key, team_id, project_id, 'delete_requirement', f', requirement_identifier={requirement_identifier}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Resolve requirement_identifier to requirement_id
    requirement_id = None
    requirement_ids_list = []

    # Handle bulk deletion case
    if selected_requirement_ids:
        # Parse comma-separated IDs
        try:
            requirement_ids_list = [int(rid.strip()) for rid in selected_requirement_ids.split(',') if rid.strip()]
            if not requirement_ids_list:
                return {
                    'status': 'failed',
                    'error': 'Invalid requirement IDs',
                    'message': 'selected_requirement_ids is empty or invalid'
                }
            logger.info(f"delete_requirement: Bulk deletion of {len(requirement_ids_list)} requirements")
        except ValueError as e:
            return {
                'status': 'failed',
                'error': 'Invalid requirement IDs',
                'message': f'selected_requirement_ids must be comma-separated numeric IDs: {str(e)}'
            }

    # Handle single requirement deletion
    if requirement_identifier:
        # Check if it's a numeric ID
        if requirement_identifier.isdigit():
            requirement_id = int(requirement_identifier)
            logger.info(f"delete_requirement: Using numeric requirement_id={requirement_id}")

            # Add to list if not already present (for consistency with API)
            if requirement_ids_list and requirement_id not in requirement_ids_list:
                requirement_ids_list.append(requirement_id)
            elif not requirement_ids_list:
                requirement_ids_list = [requirement_id]
        else:
            # It could be a requirement key (e.g., "REQ5", "MCP11") or a title - search for it
            logger.info(f"delete_requirement: Searching for requirement by key or title: '{requirement_identifier}'")

            # NOTE: Requirement endpoints use 'app_id' not 'project_id'
            params = {
                'team_id': str(team_id),
                'app_id': str(project_id),
                'start_at': 0,
                'max_results': 100  # Get more results for better matching
            }

            requirements_response = make_api_request('GET', '/v1/requirements/list', api_key, params=params)

            if requirements_response.get('status') != 'OK':
                return {
                    'status': 'failed',
                    'error': 'Failed to fetch requirements',
                    'message': requirements_response.get('message', 'Could not retrieve requirements list')
                }

            requirements = requirements_response.get('requirements', [])

            # Try exact match by requirement key (case-insensitive)
            # Requirement keys are usually in format like "REQ5", "MCP11", etc.
            matching_requirements = [req for req in requirements if req.get('requirement_key', '').upper() == requirement_identifier.upper()]

            if matching_requirements:
                logger.info(f"delete_requirement: Found requirement by key: {matching_requirements[0].get('requirement_key')}")
            else:
                # Try exact match by title (case-insensitive)
                matching_requirements = [req for req in requirements if req.get('title', '').lower() == requirement_identifier.lower()]

                if not matching_requirements:
                    # Try partial match by title
                    matching_requirements = [req for req in requirements if requirement_identifier.lower() in req.get('title', '').lower()]

            if not matching_requirements:
                return {
                    'status': 'failed',
                    'error': 'Requirement not found',
                    'message': f"No requirement found with key or title '{requirement_identifier}' in project {project_id}"
                }

            if len(matching_requirements) > 1:
                requirement_list = '\n'.join([f"  - ID: {req['requirement_id']}, Key: {req.get('requirement_key', 'N/A')}, Title: {req['title']}" for req in matching_requirements[:10]])
                return {
                    'status': 'failed',
                    'error': 'Multiple requirements found',
                    'message': f"Multiple requirements match '{requirement_identifier}'. Please use the requirement ID or unique requirement key instead:\n{requirement_list}"
                }

            requirement_id = matching_requirements[0]['requirement_id']
            logger.info(f"delete_requirement: Found requirement '{requirement_identifier}' with ID {requirement_id}")

            # Add to list if not already present
            if requirement_ids_list and requirement_id not in requirement_ids_list:
                requirement_ids_list.append(requirement_id)
            elif not requirement_ids_list:
                requirement_ids_list = [requirement_id]

    # Validate that we have at least one requirement to delete
    if not requirement_ids_list:
        return {
            'status': 'failed',
            'error': 'No requirements specified',
            'message': 'Either requirement_identifier or selected_requirement_ids must be provided'
        }

    # Build payload
    # NOTE: Requirement endpoints use 'app_id' not 'project_id'
    # The API expects 'selectedRequirementIds' (comma-separated string) and/or 'requirement_id'
    payload = {
        "app_id": project_id,
        "team_id": team_id
    }

    # Add requirement IDs to payload
    if len(requirement_ids_list) == 1:
        # Single deletion
        payload["requirement_id"] = requirement_ids_list[0]
        logger.info(f"Deleting requirement_id={requirement_ids_list[0]} for team_id={team_id}, project_id={project_id}")
    else:
        # Bulk deletion
        payload["selectedRequirementIds"] = ','.join(map(str, requirement_ids_list))
        logger.info(f"Bulk deleting {len(requirement_ids_list)} requirements for team_id={team_id}, project_id={project_id}")

    # Add optional parameters
    if sprint_id is not None:
        payload["report_id"] = sprint_id  # API uses 'report_id' for sprint_id
        logger.info(f"Deleting from sprint (report_id={sprint_id})")

    if folder_id is not None:
        payload["folder_id"] = folder_id

    # Make the API call
    response = make_api_request('POST', '/v1/requirement/delete', api_key, data=payload)

    # Handle response
    if response.get('status') == 'OK':
        # Check for partial success (some requirements failed)
        if 'errorCount' in response and response['errorCount'] > 0:
            logger.warning(f"Partial success: {response.get('message')}")
            return {
                'status': 'partial_success',
                'message': response.get('message'),
                'errors': response.get('errors', []),
                'error_count': response['errorCount']
            }

        logger.info(f"Successfully deleted requirement(s): {response.get('message')}")
        return response
    else:
        logger.error(f"Failed to delete requirement(s): {response.get('message')}")
        return response


# ============================================================================
# ASSIGNEE MANAGEMENT TOOLS
# ============================================================================
# Functions for managing assignees for issues and test cases

def _resolve_team_identifier(api_key: str, team_id: Optional[int], team_name: Optional[str]) -> dict:
    """
    Internal helper to resolve team_id from either team_id or team_name.
    This is NOT an MCP tool - it's a helper function that can be called from Python code.

    Args:
        api_key: User's Bugasura API key
        team_id: Team identifier (optional if team_name is provided)
        team_name: Team name to resolve (optional if team_id is provided)

    Returns:
        dict: {
            'status': 'OK',
            'team_id': int,
            'team_name': str
        }
        OR error dict: {
            'status': 'failed',
            'error': str,
            'error_type': str,
            'message': str
        }
    """
    # Both provided - use team_id
    if team_id is not None and team_name is not None:
        logger.info(f"_resolve_team_identifier: Both team_id={team_id} and team_name='{team_name}' provided, using team_id")
        return {
            'status': 'OK',
            'team_id': team_id,
            'team_name': team_name  # Pass through, will be validated by API
        }

    # team_id provided - use it directly
    if team_id is not None:
        logger.info(f"_resolve_team_identifier: Using provided team_id={team_id}")
        return {
            'status': 'OK',
            'team_id': team_id,
            'team_name': None
        }

    # team_name provided - resolve to team_id
    if team_name is not None and team_name.strip():
        logger.info(f"_resolve_team_identifier: Resolving team_name='{team_name}' to team_id")

        # Use find_team_by_name to search
        search_result = find_team_by_name(api_key=api_key, team_name=team_name)

        if search_result.get('status') != 'OK':
            logger.error(f"_resolve_team_identifier: Failed to search for team: {search_result.get('message')}")
            return {
                'status': 'failed',
                'error': 'Team search failed',
                'error_type': 'TeamSearchError',
                'message': f"Could not search for team '{team_name}': {search_result.get('message', 'Unknown error')}"
            }

        matches = search_result.get('matches', [])
        match_count = search_result.get('count', 0)

        if match_count == 0:
            logger.error(f"_resolve_team_identifier: No teams found matching '{team_name}'")
            return {
                'status': 'failed',
                'error': 'Team not found',
                'error_type': 'TeamNotFound',
                'message': f"No teams found matching '{team_name}'. Check the team name and try again."
            }

        if match_count > 1:
            logger.warning(f"_resolve_team_identifier: Multiple teams ({match_count}) found matching '{team_name}'")
            team_list = [f"{m['team_name']} (ID: {m['team_id']})" for m in matches]
            return {
                'status': 'failed',
                'error': 'Multiple teams found',
                'error_type': 'AmbiguousTeamError',
                'message': f"Multiple teams match '{team_name}'. Please be more specific or use team_id.",
                'matches': matches,
                'suggestion': f"Found: {', '.join(team_list)}"
            }

        # Exactly one match - use it
        resolved_team = matches[0]
        resolved_team_id = resolved_team['team_id']
        resolved_team_name = resolved_team['team_name']
        logger.info(f"_resolve_team_identifier: Resolved '{team_name}' to team_id={resolved_team_id} ('{resolved_team_name}')")

        return {
            'status': 'OK',
            'team_id': resolved_team_id,
            'team_name': resolved_team_name
        }

    # Neither provided
    logger.error("_resolve_team_identifier: Neither team_id nor team_name provided")
    return {
        'status': 'failed',
        'error': 'Missing team identifier',
        'error_type': 'ValidationError',
        'message': 'Please provide either team_id or team_name'
    }


def _fetch_team_members(api_key: str, team_id: int) -> dict:
    """
    Internal helper to fetch team members.
    This is NOT an MCP tool - it's a helper function that can be called from Python code.

    Args:
        api_key: User's Bugasura API key
        team_id: Team identifier

    Returns:
        dict: API response with team members
    """
    logger.info(f"_fetch_team_members: Fetching members for team_id={team_id}")

    # Call API to get team members directly (no validation to avoid recursive calls)
    logger.info(f"_fetch_team_members: Calling /v1/teamUsers/get for team_id={team_id}")
    response = make_api_request('GET', '/v1/teamUsers/get', api_key, params={
        'team_id': str(team_id)
    })

    if isinstance(response, dict) and response.get('status') == 'OK':
        member_count = len(response.get('team_users_details', []))
        logger.info(f"_fetch_team_members: Successfully fetched {member_count} team members")
    else:
        logger.error(f"_fetch_team_members: Failed to fetch team members. Response: {response}")

    return response


@mcp.tool(
    name="link_unlink_requirement_testcases",
    description="Link or unlink test cases to/from a requirement. Supports interactive team/project selection and bulk operations with comma-separated test case IDs."
)
def link_unlink_requirement_testcases(
    api_key: str = Field(description="User's Bugasura API key"),
    requirement_id: int = Field(description="Requirement numeric ID to link/unlink test cases"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    testcase_ids: Optional[str] = Field(default=None, description="Comma-separated test case IDs to link (e.g., '123,456,789'). Required for linking."),
    unlink_testcase_id: Optional[int] = Field(default=None, description="Single test case ID to unlink from requirement. Required for unlinking."),
    is_delete: bool = Field(default=False, description="Set to True to unlink test cases, False to link (default)"),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (optional)"),
    folder_id: Optional[int] = Field(default=None, description="Folder identifier (optional)")
) -> dict:
    """
    Link or unlink test cases to/from a requirement for traceability.

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    **Linking Test Cases** (is_delete=False):
    - Provide testcase_ids as comma-separated IDs (e.g., "123,456,789")
    - Links multiple test cases to the requirement in one operation
    - Creates traceability between requirements and test cases

    **Unlinking Test Cases** (is_delete=True):
    - Provide unlink_testcase_id with a single test case ID
    - Removes the link between requirement and test case
    - Does not delete the test case itself

    Args:
        api_key: User's Bugasura API key (required)
        requirement_id: Requirement identifier (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        testcase_ids: Comma-separated test case IDs to link (required for linking)
        unlink_testcase_id: Test case ID to unlink (required for unlinking)
        is_delete: True to unlink, False to link (default: False)
        sprint_id: Sprint identifier (optional)
        folder_id: Folder identifier (optional)

    Returns:
        dict: {
            'status': 'OK',
            'message': 'Test case(s) linked/unlinked successfully'
        }

    Examples:
        # Link multiple test cases to a requirement
        link_unlink_requirement_testcases(
            api_key,
            requirement_id=2036,
            testcase_ids="123,456,789"
        )

        # Link a single test case
        link_unlink_requirement_testcases(
            api_key,
            requirement_id=2036,
            testcase_ids="123"
        )

        # Unlink a test case from requirement
        link_unlink_requirement_testcases(
            api_key,
            requirement_id=2036,
            unlink_testcase_id=123,
            is_delete=True
        )

        # Link with explicit context
        link_unlink_requirement_testcases(
            api_key,
            requirement_id=2036,
            team_id=456,
            project_id=789,
            testcase_ids="123,456"
        )
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    if isinstance(validation, list):
        return {'status': 'failed', 'error': 'Unexpected API response format', 'details': str(validation)}
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = select_team_project_context(
        api_key, team_id, project_id,
        'link_unlink_requirement_testcases',
        f', requirement_id={requirement_id}'
    )

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Validate operation parameters
    if is_delete:
        # Unlinking operation
        if unlink_testcase_id is None:
            return {
                'status': 'failed',
                'error': 'Missing unlink_testcase_id',
                'message': 'unlink_testcase_id is required when is_delete=True'
            }

        logger.info(f"Unlinking test case {unlink_testcase_id} from requirement {requirement_id}")

        payload = {
            "app_id": project_id,
            "team_id": team_id,
            "requirement_id": requirement_id,
            "isDelete": 1,
            "deleteTestCaseId": unlink_testcase_id
        }

        if sprint_id is not None:
            payload["sprint_id"] = sprint_id
        if folder_id is not None:
            payload["folder_id"] = folder_id

    else:
        # Linking operation
        if not testcase_ids:
            return {
                'status': 'failed',
                'error': 'Missing testcase_ids',
                'message': 'testcase_ids is required when linking test cases (is_delete=False)'
            }

        logger.info(f"Linking test cases {testcase_ids} to requirement {requirement_id}")

        payload = {
            "app_id": project_id,
            "team_id": team_id,
            "requirement_id": requirement_id,
            "isDelete": 0,
            "testCaseId": testcase_ids  # API accepts comma-separated IDs
        }

        if sprint_id is not None:
            payload["sprint_id"] = sprint_id
        if folder_id is not None:
            payload["folder_id"] = folder_id

    # Make the API request
    logger.info(f"Sending {'unlink' if is_delete else 'link'} request for requirement_id={requirement_id}")
    response = make_api_request('POST', '/v1/requirement/linkUnlinkRequirementTestCases', api_key, data=payload)

    # Add helpful information to response
    if response.get('status') == 'OK':
        operation = 'unlinked' if is_delete else 'linked'
        logger.info(f"Successfully {operation} test case(s) for requirement {requirement_id}")
    else:
        logger.error(f"Failed to {'unlink' if is_delete else 'link'} test case(s): {response.get('message')}")

    return response


@mcp.tool(
    name = "list_team_members",
    description = "List all team members with user IDs, names, emails, and roles. Essential for finding user IDs when assigning work by name or email."
)
def list_team_members(
    api_key: str = Field(description="User's Bugasura API key"),
    team_id: int = Field(description="Team identifier")
) -> dict:
    """
    List all members of a team with their user IDs, names, and emails.

    Use this function to find user IDs when you have names or emails.
    This is essential for assigning issues or test cases to team members.

    Args:
        api_key: User's Bugasura API key (required)
        team_id: Team identifier (required)

    Returns:
        dict: {
            'status': 'OK',
            'message': 'Team users details fetched successfully',
            'team_users_details': [
                {
                    'user_id': int,
                    'email_id': str,
                    'name': str,
                    'team_name': str,
                    'is_owner': int,
                    'is_admin': int,
                    'account_active': int,
                    'is_invitation_accepted': int
                },
                ...
            ]
        }

    Examples:
        # List all team members
        members = list_team_members(api_key, team_id=123)

        # Find user ID by name
        for member in members['team_users_details']:
            if 'John' in member['name']:
                user_id = member['user_id']
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    # Handle case where API might return a list instead of dict
    if isinstance(validation, list):
        return {'status': 'failed', 'error': 'Unexpected API response format', 'details': str(validation)}
    if not validation.get('valid'):
        return validation

    # Use internal helper to fetch team members
    return _fetch_team_members(api_key, team_id)


def _find_user_ids_by_names_or_emails(api_key: str, team_id: int, identifiers: str) -> dict:
    """
    Internal helper to convert user names/emails to user IDs.

    Args:
        api_key: API key
        team_id: Team ID
        identifiers: Comma-separated names, emails, or user IDs

    Returns:
        dict with 'status' and either 'user_ids' (comma-separated) or 'error'
    """
    # Get team members using internal helper (not the MCP tool)
    logger.info(f"_find_user_ids: Getting team members for team_id={team_id}")
    members_response = _fetch_team_members(api_key, team_id)

    if isinstance(members_response, list):
        logger.error(f"_find_user_ids: list_team_members returned a list instead of dict")
        return {'status': 'failed', 'error': 'Could not fetch team members - unexpected response format', 'details': str(members_response)}

    if members_response.get('status') != 'OK':
        logger.error(f"_find_user_ids: list_team_members failed. Response: {members_response}")
        return {'status': 'failed', 'error': 'Could not fetch team members', 'details': members_response}

    team_members = members_response.get('team_users_details', [])
    logger.info(f"_find_user_ids: Got {len(team_members)} team members")

    if not team_members:
        logger.error(f"_find_user_ids: No team members found for team_id={team_id}")
        return {'status': 'failed', 'error': f'No team members found for team_id={team_id}'}

    # Parse the identifiers (can be names, emails, or IDs)
    # Filter out empty strings that may result from extra commas or spaces
    identifier_list = [i.strip() for i in identifiers.split(',') if i.strip()]

    if not identifier_list:
        return {'status': 'failed', 'error': 'No valid identifiers provided'}

    resolved_ids = []
    not_found = []

    logger.info(f"_find_user_ids: Searching for identifiers: {identifier_list}")

    for identifier in identifier_list:
        found = False
        logger.debug(f"_find_user_ids: Processing identifier '{identifier}'")

        # Try to match as user ID first (if it's numeric)
        if identifier.isdigit():
            user_id = int(identifier)
            if any(m['user_id'] == user_id for m in team_members):
                resolved_ids.append(str(user_id))
                found = True
                logger.info(f"_find_user_ids: Matched '{identifier}' as user ID: {user_id}")
                continue

        # Try to match by email (exact match)
        for member in team_members:
            if member['email_id'].lower() == identifier.lower():
                resolved_ids.append(str(member['user_id']))
                found = True
                logger.info(f"_find_user_ids: Matched '{identifier}' by email to user_id={member['user_id']} ({member['name']})")
                break

        if found:
            continue

        # Try to match by name (partial match, case-insensitive)
        for member in team_members:
            if identifier.lower() in member['name'].lower():
                resolved_ids.append(str(member['user_id']))
                found = True
                logger.info(f"_find_user_ids: Matched '{identifier}' by name to user_id={member['user_id']} ({member['name']})")
                break

        if not found:
            not_found.append(identifier)
            logger.warning(f"_find_user_ids: Could not find user matching '{identifier}'")

    if not_found:
        return {
            'status': 'failed',
            'error': f'Could not find users: {", ".join(not_found)}',
            'available_members': [{'name': m['name'], 'email': m['email_id'], 'user_id': m['user_id']} for m in team_members]
        }

    return {'status': 'OK', 'user_ids': ','.join(resolved_ids)}


def _resolve_issue_identifier_to_id(api_key: str, team_id: int, project_id: int, issue_id: str, function_name: str = "") -> dict:
    """
    Internal helper to resolve issue identifier (key or summary) to numeric issue ID.

    Supports:
    - Numeric IDs (returns as-is)
    - Issue keys (e.g., 'NEW3', 'BUG-123') - case-insensitive exact match
    - Issue summaries - exact or partial match

    Args:
        api_key: API key
        team_id: Team ID
        project_id: Project ID
        issue_id: Issue numeric ID or identifier
        function_name: Name of calling function (for logging)

    Returns:
        dict with 'status' and either 'issue_id' (int) or 'error'
    """
    log_prefix = f"{function_name}: " if function_name else ""

    # If already numeric, return as-is
    if str(issue_id).isdigit():
        return {'status': 'OK', 'issue_id': int(issue_id)}

    issue_identifier = str(issue_id)
    logger.info(f"{log_prefix}Resolving issue identifier '{issue_identifier}'")

    # Fetch issues from the project
    # Using a higher limit to handle larger projects (1000 instead of 100)
    # Note: For projects with >1000 issues, consider implementing pagination
    issues_response = make_api_request('GET', '/v1/issues/list', api_key, params={
        'team_id': str(team_id),
        'project_id': str(project_id),
        'start_at': 0,
        'max_results': 1000  # Increased from 100 to handle larger projects
    })

    if issues_response.get('status') != 'OK':
        logger.error(f"{log_prefix}Failed to fetch issues: {issues_response.get('message')}")
        return {
            'status': 'failed',
            'error': 'Failed to fetch issues',
            'message': issues_response.get('message', 'Could not retrieve issues list')
        }

    # Get issues list - try both possible field names
    issues = issues_response.get('issues', issues_response.get('issue_list', []))

    if not issues:
        logger.warning(f"{log_prefix}No issues found in project {project_id}")
        return {
            'status': 'failed',
            'error': 'No issues found',
            'message': f"No issues found in project {project_id}"
        }

    logger.info(f"{log_prefix}Found {len(issues)} issues in project")

    # Log first issue structure for debugging
    if issues:
        logger.debug(f"{log_prefix}Sample issue keys: {list(issues[0].keys())}")

    # Try exact match by issue key (case-insensitive)
    # The API may return issue keys in different field names depending on the endpoint
    # Common variations: 'issue_id', 'issue_key', 'bug_id', 'testresults_key'
    matching_issues = []
    for issue in issues:
        # Check all possible field names for issue key
        issue_key = (issue.get('issue_id') or
                    issue.get('issue_key') or
                    issue.get('bug_id') or
                    issue.get('testresults_key') or '')

        if issue_key.upper() == issue_identifier.upper():
            matching_issues.append(issue)
            break

    if matching_issues:
        # Use testresults_id as the canonical numeric ID
        issue_id = matching_issues[0].get('testresults_id') or matching_issues[0].get('issue_key')
        logger.info(f"{log_prefix}Found issue '{issue_identifier}' with ID {issue_id}")
        return {'status': 'OK', 'issue_id': issue_id}

    # Try exact match by summary/reason
    matching_issues = [i for i in issues
                      if (i.get('reason', '') or i.get('summary', '')).lower() == issue_identifier.lower()]

    if not matching_issues:
        # Try partial match by summary
        matching_issues = [i for i in issues
                          if issue_identifier.lower() in (i.get('reason', '') or i.get('summary', '')).lower()]

    if not matching_issues:
        logger.warning(f"{log_prefix}No match found for '{issue_identifier}'")
        # Log available issue keys for debugging
        available_keys = []
        for issue in issues[:5]:  # Show first 5
            key = (issue.get('issue_id') or issue.get('issue_key') or
                   issue.get('bug_id') or issue.get('testresults_key') or 'NO_KEY')
            available_keys.append(f"{key} (ID: {issue.get('testresults_id')})")

        logger.info(f"{log_prefix}Available issue keys (first 5): {', '.join(available_keys)}")

        return {
            'status': 'failed',
            'error': 'Issue not found',
            'message': f"No issue found with key or summary '{issue_identifier}' in project {project_id}",
            'hint': f"Try one of: {', '.join(available_keys[:3])}" if available_keys else "No issues available"
        }

    if len(matching_issues) > 1:
        issue_list = '\n'.join([
            f"  - ID: {i.get('testresults_id')}, Key: {i.get('issue_id', 'N/A')}, Summary: {i.get('reason', i.get('summary', 'N/A'))}"
            for i in matching_issues[:10]
        ])
        return {
            'status': 'failed',
            'error': 'Multiple issues found',
            'message': f"Multiple issues match '{issue_identifier}'. Please use the numeric ID or unique issue key instead:\n{issue_list}"
        }

    issue_id = matching_issues[0].get('testresults_id') or matching_issues[0].get('issue_key')
    logger.info(f"{log_prefix}Found issue '{issue_identifier}' with ID {issue_id}")
    return {'status': 'OK', 'issue_id': issue_id}


# ============================================================================
# TEAM USERS MANAGEMENT TOOLS
# ============================================================================
# Functions for managing the team members, fetching user IDs, etc.

@mcp.tool(
    name="add_team_members",
    description="Add team members by email addresses. Supports team_id or team_name. Sends invitation emails to new members."
)
def add_team_members(
    api_key: str = Field(description="User's Bugasura API key"),
    email_list: str = Field(description="Comma-separated email addresses to invite (e.g., 'john@example.com, jane@example.com')"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional if team_name provided)"),
    team_name: Optional[str] = Field(default=None, description="Team name to search for (optional if team_id provided)")
) -> dict:
    """
    Add new members to a team by sending email invitations.
    This function invites users to join a team. Invited users will receive
    an email invitation. If they don't have a Bugasura account, they'll be
    prompted to sign up.

    You can specify the team using either team_id or team_name.

    Args:
        api_key: User's Bugasura API key (required)
        email_list: Comma-separated email addresses to invite (required)
                   Example: "john@example.com, jane@example.com, user@domain.com"
        team_id: Team identifier (optional if team_name provided)
        team_name: Team name (optional if team_id provided, supports partial match)
    Returns:
        dict: {
            'status': 'OK',
            'message': 'Users invited successfully',
            'team_count_details': {
                'licences_allocated': int,    # Number of licenses used
                'licences_available': int     # Number of licenses remaining
            },
            'added_team_users_details': [
                {
                    'user_id': int,
                    'email_id': str,
                    'name': str
                },
                ...
            ]
        }
    Error Response:
        dict: {
            'status': 'ERROR' or 'failed',
            'message': 'Error description',
            'error': 'Detailed error message'
        }
    Examples:
        # Add single team member by team_id
        add_team_members(api_key, team_id=123, email_list="john@example.com")

        # Add multiple team members by team_id
        add_team_members(api_key, team_id=123,
                        email_list="john@example.com, jane@example.com, bob@example.com")

        # Add team member by team_name
        add_team_members(api_key, team_name="Acme Corp", email_list="john@example.com")

    Notes:
        - Invited users will receive email invitations
        - Users without Bugasura accounts will be prompted to sign up
        - The function tracks license allocation (allocated vs available)
        - Duplicate invitations are handled gracefully by the API
        - Only team admins/owners can add team members
        - Provide either team_id or team_name (team_name will be resolved to team_id)
    """
    # Validate API key before proceeding
    logger.info(f"add_team_members: Starting for team_id={team_id}, team_name='{team_name}'")
    validation = validate_api_key(api_key)

    # Handle case where API might return a list instead of dict
    if isinstance(validation, list):
        logger.error("add_team_members: API validation returned unexpected list format")
        return {
            'status': 'failed',
            'error': 'Unexpected API response format',
            'details': str(validation)
        }

    if not validation.get('valid'):
        logger.error(f"add_team_members: API key validation failed: {validation.get('error')}")
        return validation

    # Resolve team identifier (team_id or team_name)
    team_resolution = _resolve_team_identifier(api_key, team_id, team_name)
    if team_resolution.get('status') != 'OK':
        logger.error(f"add_team_members: Team resolution failed: {team_resolution.get('error')}")
        return team_resolution

    # Extract resolved team_id
    team_id = team_resolution['team_id']
    logger.info(f"add_team_members: Using team_id={team_id}")

    # Validate email_list
    if not email_list or not email_list.strip():
        logger.error("add_team_members: Empty email_list provided")
        return {
            'status': 'failed',
            'error': 'email_list cannot be empty',
            'error_type': 'ValidationError',
            'message': 'Please provide at least one email address to invite'
        }

    # Clean and validate email format
    email_list = email_list.strip()
    emails = [email.strip() for email in email_list.split(',') if email.strip()]

    if not emails:
        logger.error("add_team_members: No valid emails after parsing")
        return {
            'status': 'failed',
            'error': 'No valid email addresses provided',
            'error_type': 'ValidationError',
            'message': 'Please provide valid email addresses separated by commas'
        }

    # Basic email validation (simple check for @ symbol)
    invalid_emails = [email for email in emails if '@' not in email or '.' not in email.split('@')[1]]
    if invalid_emails:
        logger.error(f"add_team_members: Invalid email format detected: {invalid_emails}")
        return {
            'status': 'failed',
            'error': 'Invalid email format',
            'error_type': 'ValidationError',
            'message': f'Invalid email addresses: {", ".join(invalid_emails)}',
            'invalid_emails': invalid_emails
        }

    logger.info(f"add_team_members: Adding {len(emails)} email(s) to team_id={team_id}")

    # Build payload with required fields
    # IDs will be auto-converted to strings by make_api_request()
    payload = {
        "team_id": team_id,
        "email_id": email_list  # API expects comma-separated string
    }

    logger.debug(f"add_team_members: Payload prepared with {len(emails)} email(s)")

    # Make POST request to add team members endpoint
    response = make_api_request('POST', '/v1/teamUsers/add', api_key, data=payload)

    # Handle response
    if isinstance(response, dict):
        if response.get('status') == 'OK':
            logger.info(f"add_team_members: Successfully invited {len(emails)} user(s) to team {team_id}")

            # Log license information if available
            team_count = response.get('team_count_details', {})
            if team_count:
                logger.info(f"add_team_members: Licenses - Allocated: {team_count.get('licences_allocated')}, "
                          f"Available: {team_count.get('licences_available')}")

            # Log added users
            added_users = response.get('added_team_users_details', [])
            if added_users:
                logger.info(f"add_team_members: Added users: {[u.get('email_id') for u in added_users]}")
        else:
            logger.error(f"add_team_members: Failed to add team members. Response: {response}")
    else:
        logger.warning(f"add_team_members: Unexpected response type: {type(response)}")

    return response

@mcp.tool(
    name="update_team_member",
    description="Update team member permissions (admin/member role). Supports team_id or team_name. Only team admins can change user roles."
)
def update_team_member(
    api_key: str = Field(description="User's Bugasura API key"),
    user_id: int = Field(description="User ID to update (the team member whose role to change)"),
    is_admin: int = Field(description="Admin status: 1 for admin, 0 for regular member"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional if team_name provided)"),
    team_name: Optional[str] = Field(default=None, description="Team name to search for (optional if team_id provided)")
) -> dict:
    """
    Update a team member's admin status.
    This function allows team admins to promote members to admin or demote
    admins to regular members. Only existing team admins can change user roles.

    You can specify the team using either team_id or team_name.

    Args:
        api_key: User's Bugasura API key (required)
        user_id: User ID to update - the team member whose role to change (required)
        is_admin: Admin status - 1 for admin, 0 for regular member (required)
        team_id: Team identifier (optional if team_name provided)
        team_name: Team name (optional if team_id provided, supports partial match)
    Returns:
        dict: {
            'status': 'OK',
            'message': 'User type has been updated.'
        }
    Error Response:
        dict: {
            'status': 'ERROR' or 'failed',
            'message': 'Error description'
        }
    Examples:
        # Promote a member to admin by team_id
        update_team_member(api_key, team_id=123, user_id=456, is_admin=1)

        # Demote an admin to regular member by team_id
        update_team_member(api_key, team_id=123, user_id=456, is_admin=0)

        # Promote a member to admin by team_name
        update_team_member(api_key, team_name="Acme Corp", user_id=456, is_admin=1)

    Notes:
        - Only team admins/owners can update user roles
        - Cannot change the role of the team owner
        - The requesting user must be an admin of the specified team
        - Use list_team_members() to find user IDs if needed
        - Provide either team_id or team_name (team_name will be resolved to team_id)
    """
    # Validate API key before proceeding
    logger.info(f"update_team_member: Starting for team_id={team_id}, team_name='{team_name}', user_id={user_id}, is_admin={is_admin}")
    validation = validate_api_key(api_key)

    # Handle case where API might return a list instead of dict
    if isinstance(validation, list):
        logger.error("update_team_member: API validation returned unexpected list format")
        return {
            'status': 'failed',
            'error': 'Unexpected API response format',
            'details': str(validation)
        }

    if not validation.get('valid'):
        logger.error(f"update_team_member: API key validation failed: {validation.get('error')}")
        return validation

    # Resolve team identifier (team_id or team_name)
    team_resolution = _resolve_team_identifier(api_key, team_id, team_name)
    if team_resolution.get('status') != 'OK':
        logger.error(f"update_team_member: Team resolution failed: {team_resolution.get('error')}")
        return team_resolution

    # Extract resolved team_id
    team_id = team_resolution['team_id']
    logger.info(f"update_team_member: Using team_id={team_id}")

    # Validate user_id
    try:
        user_id = _validate_id(user_id, "user_id")
    except ValueError as e:
        logger.error(f"update_team_member: Invalid user_id: {str(e)}")
        return {
            'status': 'failed',
            'error': str(e),
            'error_type': 'ValidationError'
        }

    # Validate is_admin (must be 0 or 1)
    if is_admin not in [0, 1]:
        logger.error(f"update_team_member: Invalid is_admin value: {is_admin}")
        return {
            'status': 'failed',
            'error': 'is_admin must be 0 (member) or 1 (admin)',
            'error_type': 'ValidationError',
            'message': 'Please provide is_admin as 0 for regular member or 1 for admin'
        }

    logger.info(f"update_team_member: Updating user_id={user_id} in team_id={team_id} to is_admin={is_admin}")

    # Build payload with required fields
    # IDs will be auto-converted to strings by make_api_request()
    payload = {
        "team_id": team_id,
        "user_id": user_id,
        "is_admin": is_admin,
        "source": "API"
    }

    logger.debug(f"update_team_member: Payload prepared")

    # Make POST request to update team user endpoint
    response = make_api_request('POST', '/v1/teamUsers/update', api_key, data=payload)

    # Handle response
    if isinstance(response, dict):
        if response.get('status') == 'OK':
            role = "admin" if is_admin == 1 else "member"
            logger.info(f"update_team_member: Successfully updated user {user_id} to {role} in team {team_id}")
        else:
            logger.error(f"update_team_member: Failed to update team member. Response: {response}")
    else:
        logger.warning(f"update_team_member: Unexpected response type: {type(response)}")

    return response

@mcp.tool(
    name="delete_team_user",
    description="Remove a team member by user ID, email, or name. Supports team_id or team_name. Auto-resolves identifiers to user IDs. Owner cannot be removed."
)
def delete_team_user(
    api_key: str = Field(description="User's Bugasura API key"),
    user_identifier: str = Field(description="User to remove: user ID (e.g., '123'), email (e.g., 'john@example.com'), or name (e.g., 'John Doe')"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional if team_name provided)"),
    team_name: Optional[str] = Field(default=None, description="Team name to search for (optional if team_id provided)"),
    is_leave_team: int = Field(default=0, description="Set to 1 if user is leaving team themselves (default: 0 for admin removal)")
) -> dict:
    """
    Remove a user from a team.
    This function allows:
    - Team admins to remove other members
    - Users to leave a team themselves (is_leave_team=1)

    You can specify the team using either team_id or team_name.

    Automatically handles:
    - Converting user names/emails to user IDs
    - Unassigning all issues assigned to the user
    - Removing user comments
    - Cleaning up project integrations (JIRA credentials)
    - Recalculating license allocation

    **Smart User Resolution**: The user_identifier parameter automatically converts
    user names or emails to user IDs. You can provide:
    - User IDs (e.g., "123")
    - Email addresses (e.g., "john@example.com")
    - Names or partial names (e.g., "John", "John Doe")

    Args:
        api_key: User's Bugasura API key (required)
        user_identifier: User ID, email, or name to remove (required)
        team_id: Team identifier (optional if team_name provided)
        team_name: Team name (optional if team_id provided, supports partial match)
        is_leave_team: Set to 1 if user is leaving themselves (default: 0)
                      When 1, validates that the API key belongs to the user being removed
    Returns:
        dict: {
            'status': 'OK',
            'message': 'The user has been removed.' or 'You have been removed from the team.',
            'licencesAvailable': int,  # Remaining licenses
            'licencesAllocated': int   # Used licenses
        }
    Error Response:
        dict: {
            'status': 'ERROR' or 'failed',
            'message': 'Error description',
            'error': 'Detailed error message'
        }
    Restrictions:
        - Only team admins can remove other users
        - Users can remove themselves (is_leave_team=1)
        - Team owner CANNOT be removed
        - User must exist in the team
    Examples:
        # Admin removes user by email (using team_id)
        delete_team_user(api_key, team_id=123, user_identifier="john@example.com")

        # Admin removes user by name (using team_name)
        delete_team_user(api_key, team_name="Acme Corp", user_identifier="John Doe")

        # Admin removes user by ID (using team_id)
        delete_team_user(api_key, team_id=123, user_identifier="456")

        # User leaves team themselves (using team_name)
        delete_team_user(api_key, team_name="Acme Corp", user_identifier="john@example.com", is_leave_team=1)

    Notes:
        - Removing a user will unassign all their issues
        - All user comments will be removed
        - User's JIRA integration credentials will be cleared from projects
        - License count will be recalculated
        - Owner of the team cannot be removed (returns error)
        - Provide either team_id or team_name (team_name will be resolved to team_id)
    """
    # Validate API key before proceeding
    logger.info(f"delete_team_user: Starting for team_id={team_id}, team_name='{team_name}', user_identifier='{user_identifier}', is_leave_team={is_leave_team}")
    validation = validate_api_key(api_key)

    # Handle case where API might return a list instead of dict
    if isinstance(validation, list):
        logger.error("delete_team_user: API validation returned unexpected list format")
        return {
            'status': 'failed',
            'error': 'Unexpected API response format',
            'details': str(validation)
        }

    if not validation.get('valid'):
        logger.error(f"delete_team_user: API key validation failed: {validation.get('error')}")
        return validation

    # Resolve team identifier (team_id or team_name)
    team_resolution = _resolve_team_identifier(api_key, team_id, team_name)
    if team_resolution.get('status') != 'OK':
        logger.error(f"delete_team_user: Team resolution failed: {team_resolution.get('error')}")
        return team_resolution

    # Extract resolved team_id
    team_id = team_resolution['team_id']
    logger.info(f"delete_team_user: Using team_id={team_id}")

    # Validate user_identifier
    if not user_identifier or not user_identifier.strip():
        logger.error("delete_team_user: Empty user_identifier provided")
        return {
            'status': 'failed',
            'error': 'user_identifier cannot be empty',
            'error_type': 'ValidationError',
            'message': 'Please provide a user ID, email, or name to remove'
        }

    # Validate is_leave_team (must be 0 or 1)
    if is_leave_team not in [0, 1]:
        logger.error(f"delete_team_user: Invalid is_leave_team value: {is_leave_team}")
        return {
            'status': 'failed',
            'error': 'is_leave_team must be 0 (admin removal) or 1 (self leave)',
            'error_type': 'ValidationError',
            'message': 'Please provide is_leave_team as 0 or 1'
        }

    # Convert user identifier to user_id
    user_id = None
    team_user_email = None

    # Check if it's a numeric ID
    if user_identifier.isdigit():
        user_id = int(user_identifier)
        logger.info(f"delete_team_user: Using numeric user_id={user_id}")
    else:
        # It could be an email or name - resolve using smart identifier resolution
        logger.info(f"delete_team_user: Resolving user identifier '{user_identifier}' for team_id={team_id}")

        try:
            resolution_result = _find_user_ids_by_names_or_emails(api_key, team_id, user_identifier)
            logger.info(f"delete_team_user: Resolution result status: {resolution_result.get('status')}")

            if resolution_result['status'] != 'OK':
                logger.error(f"delete_team_user: Failed to resolve user identifier: {resolution_result.get('error')}")
                return {
                    'status': 'failed',
                    'error': resolution_result.get('error'),
                    'error_type': 'UserResolutionError',
                    'message': f"Could not find user matching '{user_identifier}' in team {team_id}",
                    'available_members': resolution_result.get('available_members', [])
                }

            # Extract user_id from comma-separated string (should be single user)
            user_ids_str = resolution_result['user_ids']
            user_ids_list = [int(uid.strip()) for uid in user_ids_str.split(',') if uid.strip()]

            if len(user_ids_list) != 1:
                logger.error(f"delete_team_user: Expected single user ID, got {len(user_ids_list)}")
                return {
                    'status': 'failed',
                    'error': 'Multiple users matched',
                    'error_type': 'AmbiguousUserError',
                    'message': f"Multiple users match '{user_identifier}'. Please be more specific or use user ID."
                }

            user_id = user_ids_list[0]
            logger.info(f"delete_team_user: Resolved '{user_identifier}' to user_id={user_id}")

            # Check if it's an email to pass to API (API accepts both user_id and email)
            if '@' in user_identifier:
                team_user_email = user_identifier

        except Exception as e:
            logger.critical(f"delete_team_user: Exception during resolution: {type(e).__name__}: {str(e)}", exc_info=True)
            return {
                'status': 'failed',
                'error': f'Internal error during user identifier resolution: {str(e)}',
                'error_type': type(e).__name__
            }

    # Build payload with required fields
    # The API accepts both snake_case and camelCase, but we'll use both for compatibility
    payload = {
        "team_id": team_id,
        "teamId": team_id,      # API also accepts camelCase
        "user_id": user_id,
        "teamUserId": user_id,  # API also accepts camelCase
        "isLeaveTeam": is_leave_team
    }

    # Add email if we have it (API can use either user_id or email)
    if team_user_email:
        payload["user_emaild"] = team_user_email  # Note: API has typo "user_emaild" not "user_email_id"
        payload["teamUserEmailId"] = team_user_email
        logger.debug(f"delete_team_user: Added email to payload: {team_user_email}")

    logger.info(f"delete_team_user: Removing user_id={user_id} from team_id={team_id}")
    logger.debug(f"delete_team_user: Payload prepared with {len(payload)} fields")

    # Make POST request to delete team user endpoint
    response = make_api_request('POST', '/v1/teamUsers/delete', api_key, data=payload)

    # Handle response
    if isinstance(response, dict):
        if response.get('status') == 'OK':
            logger.info(f"delete_team_user: Successfully removed user {user_id} from team {team_id}")

            # Log license information if available
            if 'licencesAvailable' in response or 'licencesAllocated' in response:
                logger.info(f"delete_team_user: Licenses - Allocated: {response.get('licencesAllocated')}, "
                          f"Available: {response.get('licencesAvailable')}")
        else:
            logger.error(f"delete_team_user: Failed to remove team member. Response: {response}")
    else:
        logger.warning(f"delete_team_user: Unexpected response type: {type(response)}")

    return response

# ============================================================================
# ASSIGNEE MANAGEMENT TOOLS
# ============================================================================
# Functions for managing assignees for issues and test cases
@mcp.tool(
    name = "add_issue_assignees",
    description = "Add assignees to an issue by issue ID, identifier (e.g., 'NEW3'), user IDs, email addresses, or names. Supports comma-separated values. Interactive team/project selection available."
)
def add_issue_assignees(
    api_key: str = Field(description="User's Bugasura API key"),
    issue_id: str = Field(description="Issue numeric ID or identifier (e.g., 'NEW3')"),
    assignees: str = Field(description="Comma-separated assignees: user IDs (e.g., '123'), emails (e.g., 'john@example.com'), or names (e.g., 'John Doe')"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)")
) -> dict:
    """
    Add assignees to an issue using names, emails, or user IDs.

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    This function automatically converts user names or emails to user IDs.
    You can provide:
    - User IDs (e.g., "123")
    - Email addresses (e.g., "john@example.com")
    - Names or partial names (e.g., "John", "John Doe")
    - Mix of any of the above (e.g., "John, jane@example.com, 789")

    Args:
        api_key: User's Bugasura API key (required)
        issue_id: Issue numeric ID (testresults_id) or identifier (e.g., 'NEW3') (required)
        assignees: Comma-separated names, emails, or user IDs (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)

    Returns:
        dict: API response with assignee add status

    Examples:
        # Add by name
        add_issue_assignees(api_key, issue_id=123, assignees="John Doe")

        # Add by identifier
        add_issue_assignees(api_key, issue_id="NEW3", assignees="John Doe")

        # Add by email
        add_issue_assignees(api_key, issue_id=123, assignees="john@example.com")

        # Add by user ID
        add_issue_assignees(api_key, issue_id=123, assignees="456")

        # Add multiple assignees (mixed formats)
        add_issue_assignees(api_key, issue_id=123, assignees="John, jane@example.com, 789")
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    # Handle case where API might return a list instead of dict
    if isinstance(validation, list):
        return {'status': 'failed', 'error': 'Unexpected API response format', 'details': str(validation)}
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = select_team_project_context(api_key, team_id, project_id, 'add_issue_assignees', f', issue_id={issue_id}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Resolve issue identifier to numeric ID if needed
    resolution_result = _resolve_issue_identifier_to_id(api_key, team_id, project_id, issue_id, "add_issue_assignees")
    if resolution_result['status'] != 'OK':
        return resolution_result
    issue_id = resolution_result['issue_id']

    # Convert names/emails to user IDs
    logger.info(f"add_issue_assignees: Resolving identifiers '{assignees}' for team_id={team_id}")
    try:
        resolution_result = _find_user_ids_by_names_or_emails(api_key, team_id, assignees)
        logger.info(f"add_issue_assignees: Resolution result status: {resolution_result.get('status')}")

        if resolution_result['status'] != 'OK':
            logger.error(f"add_issue_assignees: Failed to resolve identifiers: {resolution_result.get('error')}")
            return resolution_result

        assignee_ids = resolution_result['user_ids']
        logger.info(f"add_issue_assignees: Resolved to user_ids: {assignee_ids}")
    except Exception as e:
        logger.critical(f"add_issue_assignees: Exception during resolution: {type(e).__name__}: {str(e)}", exc_info=True)
        return {
            'status': 'failed',
            'error': f'Internal error during identifier resolution: {str(e)}',
            'error_type': type(e).__name__
        }

    # Call API to add assignees
    logger.info(f"add_issue_assignees: Adding assignees to issue_id={issue_id}, team_id={team_id}")
    response = make_api_request('POST', '/v1/issues/assignees/add', api_key, data={
        'team_id': str(team_id),
        'issue_key': str(issue_id),
        'assignees_list': assignee_ids
    })

    # Log the response
    if isinstance(response, dict):
        if response.get('status') == 'OK':
            logger.info(f"add_issue_assignees: Successfully added assignees to issue {issue_id}")
        else:
            logger.error(f"add_issue_assignees: Failed to add assignees. Response: {response}")

    return response


@mcp.tool(
    name="get_issue_assignees",
    description="Get the list of assignees for an issue. Returns assignee details including names, emails, user IDs, and profile images. Interactive team/project selection available."
)
def get_issue_assignees(
    api_key: str = Field(description="User's Bugasura API key"),
    issue_id: int = Field(description="Issue numeric ID (testresults_id)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)"),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (optional)")
) -> dict:
    """
    Get the list of assignees for a specific issue.
    Returns detailed information about all users assigned to an issue,
    including their names, emails, user IDs, profile images, and invitation status.
    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.
    Args:
        api_key: User's Bugasura API key (required)
        issue_id: Issue numeric ID (testresults_id) (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        sprint_id: Sprint identifier for context (optional)
    Returns:
        dict: {
            'status': 'OK',
            'message': 'Issue assignees details fetched successfully',
            'issue_assignees': [
                {
                    'name': str,              # Assignee's name (capitalized)
                    'email_id': str,          # Assignee's email address
                    'user_id': int,           # Assignee's user ID
                    'profile_image': str,     # CDN URL to profile image (empty if no image)
                    'is_invited_user': int    # 1 if user hasn't verified email, 0 if verified
                },
                ...
            ],
            'nrows': int                      # Number of assignees
        }
    Error Response:
        dict: {
            'status': 'ERROR' or 'failed',
            'message': 'Error description',
            'error': 'Detailed error message'
        }
    Examples:
        # Get assignees for an issue
        get_issue_assignees(api_key, issue_id=123, team_id=456, project_id=789)
        # Get assignees with sprint context
        get_issue_assignees(api_key, issue_id=123, team_id=456, project_id=789, sprint_id=101)
        # Get assignees with interactive selection
        get_issue_assignees(api_key, issue_id=123)
    Notes:
        - Returns empty list if issue has no assignees
        - Profile images are CDN URLs (empty string if no image)
        - is_invited_user=1 means user hasn't accepted invitation yet
        - Use this before add_issue_assignees() to see current assignees
    """
    # Validate API key before proceeding
    logger.info(f"get_issue_assignees: Starting for issue_id={issue_id}")
    validation = validate_api_key(api_key)

    # Handle case where API might return a list instead of dict
    if isinstance(validation, list):
        logger.error("get_issue_assignees: API validation returned unexpected list format")
        return {
            'status': 'failed',
            'error': 'Unexpected API response format',
            'details': str(validation)
        }

    if not validation.get('valid'):
        logger.error(f"get_issue_assignees: API key validation failed: {validation.get('error')}")
        return validation

    # Validate issue_id
    try:
        issue_id = _validate_id(issue_id, "issue_id")
    except ValueError as e:
        logger.error(f"get_issue_assignees: Invalid issue_id: {str(e)}")
        return {
            'status': 'failed',
            'error': str(e),
            'error_type': 'ValidationError'
        }

    # Use centralized context selection helper
    context = select_team_project_context(
        api_key, team_id, project_id,
        'get_issue_assignees',
        f', issue_id={issue_id}'
    )

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id
    team_id = context['team_id']

    # Build request parameters
    # The API uses GET method with query parameters
    params = {
        'team_id': team_id,
        'issue_key': issue_id,  # API expects 'issue_key' for issue_id
        'testResultsId': issue_id  # Also include alternate parameter name
    }

    # Add sprint_id if provided
    if sprint_id is not None:
        params['sprint_id'] = sprint_id

    logger.info(f"get_issue_assignees: Fetching assignees for issue_id={issue_id}, team_id={team_id}")
    logger.debug(f"get_issue_assignees: Request params: {params}")

    # Make GET request to get issue assignees endpoint
    response = make_api_request('GET', '/v1/issues/assignees/get', api_key, params=params)

    # Handle response
    if isinstance(response, dict):
        if response.get('status') == 'OK':
            assignee_count = response.get('nrows', 0)
            logger.info(f"get_issue_assignees: Successfully fetched {assignee_count} assignee(s) for issue {issue_id}")

            # Log assignee details for debugging
            if assignee_count > 0:
                assignees = response.get('issue_assignees', [])
                assignee_names = [a.get('name', 'Unknown') for a in assignees]
                logger.debug(f"get_issue_assignees: Assignees: {', '.join(assignee_names)}")
        else:
            logger.error(f"get_issue_assignees: Failed to fetch assignees. Response: {response}")
    else:
        logger.warning(f"get_issue_assignees: Unexpected response type: {type(response)}")

    return response


@mcp.tool(
    name = "remove_issue_assignees",
    description = "Remove assignees from an issue by user IDs, email addresses, or names (auto-resolves to IDs). Supports comma-separated values. Interactive team/project selection available."
)
def remove_issue_assignees(
    api_key: str = Field(description="User's Bugasura API key"),
    issue_id: str = Field(description="Issue numeric ID or identifier (e.g., 'NEW3')"),
    assignees: str = Field(description="Comma-separated assignees to remove: user IDs (e.g., '123'), emails (e.g., 'john@example.com'), or names (e.g., 'John Doe')"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)")
) -> dict:
    """
    Remove assignees from an issue using issue ID or identifier (e.g., 'NEW3').

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    This function automatically converts user names or emails to user IDs.
    You can provide:
    - User IDs (e.g., "123")
    - Email addresses (e.g., "john@example.com")
    - Names or partial names (e.g., "John", "John Doe")
    - Mix of any of the above (e.g., "John, jane@example.com, 789")

    Args:
        api_key: User's Bugasura API key (required)
        issue_id: Issue numeric ID or identifier (e.g., 'NEW3') (required)
        assignees: Comma-separated names, emails, or user IDs to remove (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)

    Returns:
        dict: API response with assignee removal status

    Examples:
        # Remove by name
        remove_issue_assignees(api_key, issue_id=123, assignees="John Doe")

        # Remove by identifier
        remove_issue_assignees(api_key, issue_id="NEW3", assignees="John Doe")

        # Remove by email
        remove_issue_assignees(api_key, issue_id=123, assignees="john@example.com")

        # Remove multiple assignees (mixed formats)
        remove_issue_assignees(api_key, issue_id=123, assignees="John, jane@example.com")
    """
    # Validate API key before proceeding
    validation = validate_api_key(api_key)
    # Handle case where API might return a list instead of dict
    if isinstance(validation, list):
        return {'status': 'failed', 'error': 'Unexpected API response format', 'details': str(validation)}
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = select_team_project_context(api_key, team_id, project_id, 'remove_issue_assignees', f', issue_id={issue_id}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Resolve issue identifier to numeric ID if needed
    resolution_result = _resolve_issue_identifier_to_id(api_key, team_id, project_id, issue_id, "remove_issue_assignees")
    if resolution_result['status'] != 'OK':
        return resolution_result
    issue_id = resolution_result['issue_id']

    # Convert names/emails to user IDs
    logger.info(f"remove_issue_assignees: Resolving identifiers '{assignees}' for team_id={team_id}")
    try:
        resolution_result = _find_user_ids_by_names_or_emails(api_key, team_id, assignees)
        logger.info(f"remove_issue_assignees: Resolution result status: {resolution_result.get('status')}")

        if resolution_result['status'] != 'OK':
            logger.error(f"remove_issue_assignees: Failed to resolve identifiers: {resolution_result.get('error')}")
            return resolution_result

        assignee_ids = resolution_result['user_ids']
        logger.info(f"remove_issue_assignees: Resolved to user_ids: {assignee_ids}")
    except Exception as e:
        logger.critical(f"remove_issue_assignees: Exception during resolution: {type(e).__name__}: {str(e)}", exc_info=True)
        return {
            'status': 'failed',
            'error': f'Internal error during identifier resolution: {str(e)}',
            'error_type': type(e).__name__
        }

    # Call API to remove assignees
    logger.info(f"remove_issue_assignees: Removing assignees from issue_id={issue_id}, team_id={team_id}")
    response = make_api_request('POST', '/v1/issues/assignees/remove', api_key, data={
        'team_id': str(team_id),
        'issue_key': str(issue_id),
        'assignees_list': assignee_ids
    })

    # Log the response
    if isinstance(response, dict):
        if response.get('status') == 'OK':
            logger.info(f"remove_issue_assignees: Successfully removed assignees from issue {issue_id}")
        else:
            logger.error(f"remove_issue_assignees: Failed to remove assignees. Response: {response}")

    return response


# ============================================================================
# MCP RESOURCES
# ============================================================================
# Resources provide static documentation and configuration information
# to MCP clients. These are accessible via the bugasura:// URI scheme.
# AI assistants can read these to understand how to use the API.

@mcp.resource("bugasura://config/settings")
def get_server_config() -> str:
    """Server configuration"""
    return json.dumps({
        "api_base_url": API_BASE, "version": "1.0.0",
        "auth": "api_key required as first parameter",
        "workflow": "list_teams() → list_projects() → work with data"
    }, indent=2)


@mcp.resource("bugasura://docs/severity-levels")
def get_severity_levels() -> str:
    """Severity levels reference"""
    return json.dumps({
        "levels": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "CRITICAL": "System crash, data loss, security issue",
        "HIGH": "Major functionality broken",
        "MEDIUM": "Issue with workaround",
        "LOW": "Minor/cosmetic"
    }, indent=2)


@mcp.resource("bugasura://docs/api-endpoints")
def get_api_endpoints() -> str:
    """API endpoints reference"""
    return json.dumps({
        "teams": ["GET /v1/teams/list"],
        "projects": ["GET /v1/projects/list", "GET /v1/projects/get"],
        "issues": ["GET /v1/issues/list", "GET /v1/issues/get", "POST /v1/issues/add", "POST /v1/issues/update", "POST /v1/issues/delete"],
        "issues_comments": ["GET /v1/issues/comments/list", "GET /v1/issues/comments/get", "POST /v1/issues/comments/add", "POST /v1/issues/comments/update", "POST /v1/issues/comments/delete"],
        "sprints": ["GET /v1/sprints/list", "GET /v1/sprints/get", "POST /v1/sprints/add", "POST /v1/sprints/update", "POST /v1/sprints/delete"],
        "testcases": ["GET /v1/testcases/list", "GET /v1/testcases/get", "POST /v1/testcases/add", "POST /v1/testcases/update", "POST /v1/testcases/delete"],
        "testcases_comments": ["GET /v1/testcasecomments/list", "GET /v1/testcasecomments/get", "POST /v1/testcasecomments/add", "POST /v1/testcasecomments/update", "POST /v1/testcasecomments/delete"],
        "requirements": ["GET /v1/requirements/list", "GET /v1/requirement/get", "POST /v1/requirement/add", "POST /v1/requirement/update", "POST /v1/requirement/delete"]
    }, indent=2)


@mcp.resource("bugasura://docs/getting-started")
def get_getting_started_guide() -> str:
    """Quick start guide"""
    return json.dumps({
        "1": "Get API key: Bugasura → User Settings → API Key",
        "2": "Get team_id: list_teams(api_key)",
        "3": "List projects: list_projects(api_key, team_id)",
        "4": "Create/manage issues, sprints, test cases"
    }, indent=2)


@mcp.prompt()
def setup_api_key() -> str:
    """
    Prompt to help AI assistants guide users through initial API key setup.

    This prompt instructs AI assistants to:
    1. Ask the user for their Bugasura API key (not use placeholder values)
    2. Guide them through getting their API key if they don't have it
    3. Validate the API key before proceeding

    IMPORTANT: AI assistants should NEVER use placeholder values like
    $BUGASURA_API_KEY or similar. Always ask the user for their actual API key.
    """
    return """
Welcome to Bugasura MCP! To get started, I need your Bugasura API key.

**IMPORTANT FOR AI ASSISTANTS**:
- DO NOT use placeholder values like $BUGASURA_API_KEY or similar
- ALWAYS ask the user for their actual API key
- Guide them through obtaining it if needed

**Instructions for Users**:

1. **Get Your API Key**:
   - Go to Bugasura web app (https://bugasura.io)
   - Navigate to: User Settings → API Key
   - Copy your API key

2. **Provide Your API Key**:
   Please provide your actual Bugasura API key (it will be validated before use).

3. **Next Steps**:
   Once you provide your API key, I will:
   - Validate it
   - Show you your available teams and projects
   - Help you create/manage issues, test cases, and sprints

**Security Note**: Your API key is never logged in full (only first 8 characters for debugging).

Please share your Bugasura API key to continue.
"""


@mcp.prompt()
def search_projects_guidance() -> str:
    """
    Guidance for AI assistants on how to handle project search/listing when user
    doesn't specify a team.

    This prompt instructs AI assistants on the best approach to discover projects
    across multiple teams.
    """
    return """
# Project Discovery Guidance for AI Assistants

When a user asks to "list projects", "find project", or "search for projects"
WITHOUT specifying a team:

## Best Approach - Use find_project_by_name()

If the user mentions a project name or keyword:
✓ Use: find_project_by_name(api_key, project_name)
  - Searches across ALL teams automatically
  - Returns project_id and team_id for each match
  - Supports partial, case-insensitive matching

Example user requests:
- "Find my mobile app project"
- "Search for projects with 'api' in the name"
- "Show me the authentication project"

## Alternative Approach - Use get_user_context()

If the user wants to see ALL projects (no search term):
✓ Use: get_user_context(api_key)
  - Returns all teams and their projects in one call
  - Shows complete project hierarchy
  - More efficient than calling list_teams() then list_projects() for each team

Example user requests:
- "List all my projects"
- "Show me all projects I have access to"
- "What projects are available?"

## When to Use list_projects()

ONLY use list_projects(api_key, team_id) when:
- User specifically mentions a team name or ID
- You've already identified the team_id from previous context
- User wants filtered/paginated results for a specific team

Example user requests:
- "List projects in the Acme Corp team"
- "Show me web projects for team 123"

## DO NOT:
❌ Ask user for team_id first when they just want to search/list projects
❌ Use list_projects() without team_id (it will fail)
❌ Make the user specify team when it's not necessary

## Best User Experience Flow:
1. User: "Find my mobile project"
2. AI: Calls find_project_by_name(api_key, "mobile")
3. AI: "I found 2 projects: Mobile App (Team: Acme Corp), Mobile Web (Team: Client XYZ)"
4. User can then work with the discovered project
"""


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """
    Run the MCP server with either STDIO or SSE transport.

    Transport Modes:
    1. STDIO (default): For local integration with MCP clients
       - Communication via stdin/stdout
       - MCP client spawns this as a subprocess
       - No network involved, direct IPC

    2. SSE: For remote deployment
       - Server-Sent Events over HTTP/HTTPS
       - Runs as a web service with uvicorn
       - Requires reverse proxy (Apache/Nginx) for HTTPS

    Command-line arguments control the mode and configuration.
    """
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Bugasura MCP Server')

    # Transport mode selection: stdio or sse
    parser.add_argument('--transport', choices=['stdio', 'sse'], default='stdio',
                        help='Transport type: stdio (local dev) or sse (production)')

    # SSE-specific arguments (ignored in stdio mode)
    parser.add_argument('--host', default='0.0.0.0',
                        help='Host to bind to for SSE (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8000,
                        help='Port to bind to for SSE (default: 8000)')

    # Parse provided arguments
    args = parser.parse_args()

    # Log server startup
    logger.info("=" * 60)
    logger.info("Bugasura MCP Server Starting")
    logger.info(f"API Base URL: {API_BASE}")
    logger.info(f"Transport Mode: {args.transport}")
    logger.info(f"Log Level: {log_level}")
    logger.info("=" * 60)

    # Print startup information to stderr (stdout is reserved for STDIO communication)
    print(f"Bugasura MCP Server | API: {API_BASE} | Transport: {args.transport}", file=sys.stderr)

    # Branch based on selected transport mode
    if args.transport == 'sse':
        # ===== SSE MODE =====
        # Run as a web service using uvicorn ASGI server
        logger.info(f"Starting SSE server on {args.host}:{args.port}")
        # print(f"Listening on http://{args.host}:{args.port}/sse", file=sys.stderr)
        # print(f"Configure MCP client with: https://your-domain/sse", file=sys.stderr)

        try:
            # Start uvicorn server with the Starlette ASGI app
            # Using direct reference to 'app' object instead of string "server:app"
            # This is safer and won't break if the module name changes
            uvicorn.run(
                app,                    # Direct reference to ASGI application object
                host=args.host,         # Bind address (0.0.0.0 = all interfaces)
                port=args.port,         # Port to listen on (default 8000)
                log_level="info"        # Logging verbosity
            )
        except Exception as e:
            logger.critical(f"Failed to start SSE server: {e}", exc_info=True)
            sys.exit(1)
    else:
        # ===== STDIO MODE =====
        # Run with STDIO transport for local MCP client integration
        # FastMCP handles all the MCP protocol details over stdin/stdout
        # This blocks until the connection is closed by the MCP client
        logger.info("Starting STDIO server (stdin/stdout communication)")
        try:
            mcp.run(transport='stdio')
        except KeyboardInterrupt:
            logger.info("Server stopped by user (Ctrl+C)")
        except Exception as e:
            logger.critical(f"Failed to start STDIO server: {e}", exc_info=True)
            sys.exit(1)


# Standard Python entry point
# Only execute main() when this file is run directly (not when imported)
if __name__ == "__main__":
    main()