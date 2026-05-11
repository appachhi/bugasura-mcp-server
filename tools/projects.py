"""Bugasura MCP tools: projects."""
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
    name = "bugasura_list_projects",
    description = "List projects for a specific team with filtering and pagination. Supports platform, status, and search filters.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def list_projects(
    team_id: int = Field(description="Team identifier (required, ge=1)"),
    start_at: int = Field(default=0, description="Pagination offset (default: 0, ge=0)"),
    max_results: int = Field(default=10, description="Number of results to return (10-100, default: 10, ge=1, le=100)"),
    platform: Literal["ALL", "Android", "iOS", "Desktop", "API", "Multiple"] = Field(default="ALL", description="Filter by platform: 'ALL', 'Android', 'iOS', 'Desktop', 'Multiple' (case-sensitive)"),
    platform_type: Literal["ALL", "Apps", "Mobileweb", "Web", "API", "Multiple"] = Field(default="ALL", description="Filter by platform type: 'ALL', 'Apps', 'Mobileweb', 'Web', 'Multiple' (case-sensitive)"),
    status: str = Field(default="ACTIVE", description="Filter by status: 'ACTIVE', 'ARCHIVE', 'ALL' (case-insensitive)"),
    project_type: Literal["all", "contributed", "private", "public"] = Field(default="all", description="Filter by access: 'all', 'contributed', 'private', 'public' (case-insensitive)"),
    search_text: str = Field(default="", description="Search projects by name (case-insensitive partial match)"),
    source: str = Field(default="", description="Filter by creation source: 'PLATFORM', 'EXTENSION', 'API', 'IMPORT'"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    # Handle case where API might return a list instead of dict
    if isinstance(validation, list):
        return _respond({'status': 'failed', 'error': 'Unexpected API response format', 'details': str(validation)}, response_format)
    if not validation.get('valid'):
        return _respond(validation, response_format)

    # Validate and normalize platform (case-sensitive)
    valid_platforms = ['ALL', 'Android', 'iOS', 'Desktop', 'Multiple', '']
    if platform not in valid_platforms:
        return _respond({
            'status': 'failed',
            'error': f'Invalid platform value: "{platform}". Allowed values: {", ".join([v for v in valid_platforms if v != ""])}'
        }, response_format)

    # Validate and normalize platform_type (case-sensitive)
    valid_platform_types = ['ALL', 'Apps', 'Mobileweb', 'Web', 'Multiple', '']
    if platform_type not in valid_platform_types:
        return _respond({
            'status': 'failed',
            'error': f'Invalid platform_type value: "{platform_type}". Allowed values: {", ".join([v for v in valid_platform_types if v != ""])}'
        }, response_format)

    # Normalize status (case-insensitive, convert to uppercase)
    status = status.upper()
    valid_statuses = ['ACTIVE', 'ARCHIVE', 'DELETED']
    if status not in valid_statuses:
        return _respond({
            'status': 'failed',
            'error': f'Invalid status value. Allowed values (case-insensitive): {", ".join(valid_statuses)}'
        }, response_format)

    # Normalize project_type (case-insensitive, convert to lowercase)
    project_type = project_type.lower()
    valid_project_types = ['all', 'contributed', 'private', 'public']
    if project_type not in valid_project_types:
        return _respond({
            'status': 'failed',
            'error': f'Invalid project_type value. Allowed values (case-insensitive): {", ".join(valid_project_types)}'
        }, response_format)

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

    upstream = await make_api_request('GET', '/v1/projects/list', api_key, params=params)
    return _respond(_paginate_upstream(upstream, items_key='project_list', offset=start_at), response_format)


@mcp.tool(
    name = "bugasura_get_project_details",
    description = "Get detailed information about a specific project including workflow, tags, and settings.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def get_project_details(
    team_id: int = Field(description="Team identifier", ge=1),
    project_id: int = Field(description="Project identifier", ge=1),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """Get detailed information about a specific project."""
    # Validate API key before proceeding
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return _respond(validation, response_format)

    return _respond(await make_api_request('GET', '/v1/projects/get', api_key, params={'team_id': team_id, 'project_id': project_id}), response_format)


@mcp.tool(
    name = "bugasura_create_project",
    description = "Create a new project in a team. Projects organize test cases, issues, and sprints. Supports interactive team selection.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def create_project(
    project_name: str = Field(description="Project name (required, min_length=1)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    platform: Literal["ALL", "Android", "iOS", "Desktop", "API", "Multiple"] = Field(default="Multiple", description="Platform: 'Android', 'iOS', 'Desktop', 'API', 'Multiple' (default: Multiple)"),
    platform_type: Literal["ALL", "Apps", "Mobileweb", "Web", "API", "Multiple"] = Field(default="Multiple", description="Platform type: 'Apps', 'Mobileweb', 'Web', 'API', 'Multiple' (default: Multiple)"),
    is_public_project: bool = Field(default=False, description="Public visibility (default: False for private)"),
    is_public_issues: bool = Field(default=False, description="Allow public issue visibility (default: False)"),
    clean_public_project_name: str = Field(default="", description="Unique identifier for public projects (optional)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
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
        teams_response = await list_teams(api_key)
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
            'next_call': f'bugasura_create_project with api_key, project_name="{project_name}", team_id=<selected_team_id>'
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
    result = await make_api_request('POST', '/v1/projects/add', api_key, data=data)
    _invalidate_user_context_cache(api_key)

    if result.get('status') == 'OK':
        logger.info(f"Successfully created project: {project_name} in team {team_id}")
    else:
        logger.error(f"Failed to create project: {result.get('message')}")

    return result


@mcp.tool(
    name = "bugasura_update_project",
    description = "Update project details including name, issue prefix, and visibility settings. Supports project_id or project_name. Team admin privileges may be required.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def update_project(
    project_id: Optional[int] = Field(default=None, description="Project identifier (provide either project_id or search_project_name, ge=1)"),
    search_project_name: Optional[str] = Field(default=None, description="Project name to search for (provide either project_id or search_project_name)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    new_project_name: Optional[str] = Field(default=None, description="New project name (optional)"),
    issue_prefix: Optional[str] = Field(default=None, description="New issue prefix (e.g., 'BUG', 'ISS') (optional)"),
    is_public_project: Optional[bool] = Field(default=None, description="Public visibility (optional)"),
    clean_public_project_name: Optional[str] = Field(default=None, description="Unique identifier for public projects (optional)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
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
        search_result = await find_project_by_name(api_key, search_project_name)

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
        teams_response = await list_teams(api_key)
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
            'next_call': f'bugasura_update_project with api_key, project_id={resolved_project_id}, team_id=<selected_team_id>, ...'
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
    result = await make_api_request('POST', '/v1/projects/update', api_key, data=data)

    if result.get('status') == 'OK':
        logger.info(f"Successfully updated project {project_id} in team {team_id}")
    else:
        logger.error(f"Failed to update project: {result.get('message')}")

    return result


@mcp.tool(
    name = "bugasura_delete_project",
    description = "Delete project permanently. WARNING: This deletes all associated sprints, issues, and test cases. Supports project_id or project_name. Team admin privileges required.",
    annotations={"readOnlyHint": False, "destructiveHint": True,  "idempotentHint": True,  "openWorldHint": True}
)
async def delete_project(
    project_id: Optional[int] = Field(default=None, description="Project identifier (provide either project_id or project_name, ge=1)"),
    project_name: Optional[str] = Field(default=None, description="Project name to search for (provide either project_id or project_name)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
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
        search_result = await find_project_by_name(api_key, project_name)

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
        teams_response = await list_teams(api_key)
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
            'next_call': f'bugasura_delete_project with api_key, project_id={resolved_project_id}, team_id=<selected_team_id>'
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
    result = await make_api_request('POST', '/v1/projects/delete', api_key, data=data)
    _invalidate_user_context_cache(api_key)

    if result.get('status') == 'OK':
        logger.warning(f"Project {resolved_project_id} in team {resolved_team_id} deleted successfully")
    else:
        logger.error(f"Failed to delete project: {result.get('message')}")

    return result
