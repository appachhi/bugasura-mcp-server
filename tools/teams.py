"""Bugasura MCP tools: teams."""
from typing import Any, List, Literal, Optional

from fastmcp import Context
from pydantic import Field

from output_types import ToolResponse
from app import mcp
from auth import _fetch_user_context, _get_api_key, _invalidate_user_context_cache, validate_api_key
from client import (
    _paginate_upstream, _paginated, _prepare_post_params, _render_markdown,
    _respond, _validate_id, logger, make_api_request,
)
from helpers import (
    _fetch_team_members, _find_user_ids_by_names_or_emails,
    _resolve_issue_identifier_to_id, _resolve_team_identifier,
    filter_large_fields, select_team_project_context,
)

import json
import requests  # for except blocks referencing requests.RequestException


@mcp.tool(
    name = "bugasura_list_teams",
    description = "List all teams the user belongs to. Returns minimal team info for selection.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def list_teams(response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: \'json\' or \'markdown\'"), api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")) -> ToolResponse:
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
    # Resolve API key from parameter or environment
    api_key = _get_api_key(api_key)

    if not api_key:
        return _respond({
            'status': 'api_key_required',
            'error': 'No API key found. Please provide your Bugasura API key.',
            'error_type': 'ApiKeyMissing',
            'action': 'Please ask the user for their Bugasura API key. Once they provide it, retry the same tool call with the api_key parameter.',
            'help': 'To get your API key:\n'
                   '1. Go to https://bugasura.io\n'
                   '2. Navigate to User Settings → API Key\n'
                   '3. Copy your API key and provide it here'
        }, response_format)

    # Call Bugasura API to fetch user's teams and projects
    full_response = await make_api_request('GET', '/v1/teams/getApps', api_key)

    # Handle case where API might return a list instead of dict
    if isinstance(full_response, list):
        return _respond({
            'status': 'failed',
            'error': 'Unexpected API response format (received list instead of dict)',
            'error_type': 'ResponseFormatError',
            'response_preview': str(full_response[:2]) if len(full_response) > 0 else 'Empty list'
        }, response_format)

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

        # Return simplified response wrapped in the standard pagination envelope.
        # list_teams does not paginate — total = count, has_more = False.
        return _respond(_paginated(minimal_teams, total=len(minimal_teams), offset=0, teams=minimal_teams), response_format)

    # Return raw response if API call failed (includes error details)
    return _respond(full_response, response_format)


@mcp.tool(
    name="bugasura_get_team",
    description="Get detailed information about a specific team including settings, custom fields, and subscription details. Supports team_id or team_name.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def get_team(
    team_id: Optional[int] = Field(default=None, description="Team identifier (provide either team_id or team_name, ge=1)"),
    team_name: Optional[str] = Field(default=None, description="Team name to search for (provide either team_id or team_name)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)

    # Handle case where API might return a list instead of dict
    if isinstance(validation, list):
        logger.error("get_team: API validation returned unexpected list format")
        return _respond({
            'status': 'failed',
            'error': 'Unexpected API response format',
            'details': str(validation)
        }, response_format)

    if not validation.get('valid'):
        logger.error(f"get_team: API key validation failed: {validation.get('error')}")
        return _respond(validation, response_format)

    # Resolve team identifier (team_id or team_name)
    team_resolution = await _resolve_team_identifier(api_key, team_id, team_name)
    if team_resolution.get('status') != 'OK':
        logger.error(f"get_team: Team resolution failed: {team_resolution}")
        return _respond(team_resolution, response_format)

    team_id = team_resolution['team_id']

    logger.info(f"get_team: Fetching team details for team_id={team_id}")

    # Make GET request to get team endpoint
    response = await make_api_request('GET', '/v1/teams/get', api_key, params={
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

    return _respond(response, response_format)


@mcp.tool(
    name="bugasura_create_team",
    description="Create a new team. The user who creates the team becomes the team owner/admin.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def create_team(
    team_name: str = Field(description="Team name (required, 1-50 characters, min_length=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Create a new team.

    The user creating the team automatically becomes the team owner/admin.
    Team name must be unique within the user's teams.

    Args:
        api_key: User's Bugasura API key (required)
        team_name: Name for the new team (required, 1-50 characters)

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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)

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

    if len(team_name) > 50:
        logger.error(f"create_team: Team name too long: {len(team_name)} characters")
        return {
            'status': 'failed',
            'error': 'Team name too long',
            'error_type': 'ValidationError',
            'message': 'Team name must be 50 characters or less'
        }

    logger.info(f"create_team: Creating team '{team_name}'")

    # Build payload with required fields
    payload = {
        "team_name": team_name
    }

    logger.debug(f"create_team: Payload prepared")

    # Make POST request to create team endpoint
    response = await make_api_request('POST', '/v1/teams/add', api_key, data=payload)
    _invalidate_user_context_cache(api_key)

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
    name="bugasura_update_team",
    description="Update team name. Only team admins can update team details. Supports team_id or team_name to identify the team.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def update_team(
    new_team_name: str = Field(description="New team name (required, 1-50 characters, min_length=1)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (provide either team_id or team_name, ge=1)"),
    team_name: Optional[str] = Field(default=None, description="Current team name to search for (provide either team_id or team_name)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)

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
    team_resolution = await _resolve_team_identifier(api_key, team_id, team_name)
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

    if len(new_team_name) > 50:
        logger.error(f"update_team: New team name too long: {len(new_team_name)} characters")
        return {
            'status': 'failed',
            'error': 'Team name too long',
            'error_type': 'ValidationError',
            'message': 'Team name must be 50 characters or less'
        }

    logger.info(f"update_team: Updating team_id={team_id} to '{new_team_name}'")

    # Build payload with required fields
    payload = {
        "team_id": team_id,
        "team_name": new_team_name
    }

    logger.debug(f"update_team: Payload prepared")

    # Make POST request to update team endpoint
    response = await make_api_request('POST', '/v1/teams/update', api_key, data=payload)

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
    name="bugasura_delete_team",
    description="Delete team permanently. Only team admins can delete teams. WARNING: This deletes all associated projects, sprints, issues, and test cases. Supports team_id or team_name.",
    annotations={"readOnlyHint": False, "destructiveHint": True,  "idempotentHint": True,  "openWorldHint": True}
)
async def delete_team(
    team_id: Optional[int] = Field(default=None, description="Team identifier (provide either team_id or team_name, ge=1)"),
    team_name: Optional[str] = Field(default=None, description="Team name to search for (provide either team_id or team_name)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)

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
    team_resolution = await _resolve_team_identifier(api_key, team_id, team_name)
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
    response = await make_api_request('POST', '/v1/teams/delete', api_key, data=payload)
    _invalidate_user_context_cache(api_key)

    # Handle response
    if isinstance(response, dict):
        if response.get('status') == 'OK':
            logger.warning(f"delete_team: Successfully deleted team {team_id}")
        else:
            logger.error(f"delete_team: Failed to delete team. Response: {response}")
    else:
        logger.warning(f"delete_team: Unexpected response type: {type(response)}")

    return response


@mcp.tool(
    name = "bugasura_list_team_members",
    description = "List all team members with user IDs, names, emails, and roles. Essential for finding user IDs when assigning work by name or email.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def list_team_members(
    team_id: int = Field(description="Team identifier", ge=1),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    # Handle case where API might return a list instead of dict
    if isinstance(validation, list):
        return _respond({'status': 'failed', 'error': 'Unexpected API response format', 'details': str(validation)}, response_format)
    if not validation.get('valid'):
        return _respond(validation, response_format)

    # Use internal helper to fetch team members and wrap in pagination envelope
    upstream = await _fetch_team_members(api_key, team_id)
    return _respond(_paginate_upstream(upstream, items_key='team_users_details', offset=0), response_format)


@mcp.tool(
    name="bugasura_add_team_members",
    description="Add team members by email addresses. Supports team_id or team_name. Sends invitation emails to new members.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def add_team_members(
    email_list: str = Field(description="Comma-separated email addresses to invite (e.g., 'john@example.com, jane@example.com')"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional if team_name provided, ge=1)"),
    team_name: Optional[str] = Field(default=None, description="Team name to search for (optional if team_id provided)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)

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
    team_resolution = await _resolve_team_identifier(api_key, team_id, team_name)
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
    response = await make_api_request('POST', '/v1/teamUsers/add', api_key, data=payload)

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
    name="bugasura_update_team_member",
    description="Update team member permissions (admin/member role). Supports team_id or team_name. Only team admins can change user roles.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def update_team_member(
    user_id: int = Field(description="User ID to update (the team member whose role to change)"),
    is_admin: int = Field(description="Admin status: 1 for admin, 0 for regular member"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional if team_name provided, ge=1)"),
    team_name: Optional[str] = Field(default=None, description="Team name to search for (optional if team_id provided)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)

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
    team_resolution = await _resolve_team_identifier(api_key, team_id, team_name)
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
    response = await make_api_request('POST', '/v1/teamUsers/update', api_key, data=payload)

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
    name="bugasura_delete_team_user",
    description="Remove a team member by user ID, email, or name. Supports team_id or team_name. Auto-resolves identifiers to user IDs. Owner cannot be removed.",
    annotations={"readOnlyHint": False, "destructiveHint": True,  "idempotentHint": True,  "openWorldHint": True}
)
async def delete_team_user(
    user_identifier: str = Field(description="User to remove: user ID (e.g., '123'), email (e.g., 'john@example.com'), or name (e.g., 'John Doe')"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional if team_name provided, ge=1)"),
    team_name: Optional[str] = Field(default=None, description="Team name to search for (optional if team_id provided)"),
    is_leave_team: int = Field(default=0, description="Set to 1 if user is leaving team themselves (default: 0 for admin removal)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)

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
    team_resolution = await _resolve_team_identifier(api_key, team_id, team_name)
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
            resolution_result = await _find_user_ids_by_names_or_emails(api_key, team_id, user_identifier)
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

        except (KeyError, AttributeError, TypeError, ValueError, requests.RequestException) as e:
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
    response = await make_api_request('POST', '/v1/teamUsers/delete', api_key, data=payload)

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
