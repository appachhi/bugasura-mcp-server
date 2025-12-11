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

    # Build base payload with required fields
    # IDs will be auto-converted to strings by make_api_request()
    payload = {
        "team_id": team_id,
        "sprint_id": sprint_id
    }

    # Add optional fields if provided
    optional = {
        'sprint_name': sprint_name,
        'start_date': start_date,
        'end_date': end_date,
        'duration': duration,  # Will be converted to string
        'sprint_status': sprint_status
    }

    # Only include non-None optional fields
    payload.update({k: v for k, v in optional.items() if v is not None})
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
# ASSIGNEE MANAGEMENT TOOLS
# ============================================================================
# Functions for managing assignees for issues and test cases

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


@mcp.tool(
    name = "add_issue_assignees",
    description = "Add assignees to an issue by user IDs, email addresses, or names (auto-resolves to IDs). Supports comma-separated values. Interactive team/project selection available."
)
def add_issue_assignees(
    api_key: str = Field(description="User's Bugasura API key"),
    issue_id: int = Field(description="Issue numeric ID"),
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
        issue_id: Issue numeric ID (testresults_id) (required)
        assignees: Comma-separated names, emails, or user IDs (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)

    Returns:
        dict: API response with assignee add status

    Examples:
        # Add by name
        add_issue_assignees(api_key, issue_id=123, assignees="John Doe")

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
    name = "remove_issue_assignees",
    description = "Remove assignees from an issue by user IDs, email addresses, or names (auto-resolves to IDs). Supports comma-separated values. Interactive team/project selection available."
)
def remove_issue_assignees(
    api_key: str = Field(description="User's Bugasura API key"),
    issue_id: int = Field(description="Issue numeric ID"),
    assignees: str = Field(description="Comma-separated assignees to remove: user IDs (e.g., '123'), emails (e.g., 'john@example.com'), or names (e.g., 'John Doe')"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided)")
) -> dict:
    """
    Remove assignees from an issue using names, emails, or user IDs.

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
        issue_id: Issue numeric ID (testresults_id) (required)
        assignees: Comma-separated names, emails, or user IDs to remove (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)

    Returns:
        dict: API response with assignee removal status

    Examples:
        # Remove by name
        remove_issue_assignees(api_key, issue_id=123, assignees="John Doe")

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

    # Convert names/emails to user IDs
    logger.info(f"remove_issue_assignees: Resolving identifiers '{assignees}' for team_id={team_id}")
    resolution_result = _find_user_ids_by_names_or_emails(api_key, team_id, assignees)
    if resolution_result['status'] != 'OK':
        logger.error(f"remove_issue_assignees: Failed to resolve identifiers: {resolution_result.get('error')}")
        return resolution_result

    assignee_ids = resolution_result['user_ids']
    logger.info(f"remove_issue_assignees: Resolved to user_ids: {assignee_ids}")

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
        "issues": ["GET /v1/issues/list", "GET /v1/issues/get", "POST /v1/issues/add", "POST /v1/issues/update"],
        "sprints": ["GET /v1/sprints/list", "GET /v1/sprints/get", "POST /v1/sprints/add", "POST /v1/sprints/update"],
        "testcases": ["GET /v1/testcases/list", "GET /v1/testcases/get", "POST /v1/testcases/add", "POST /v1/testcases/update"]
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