"""Bugasura MCP tools: discovery."""
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
    name = "bugasura_get_user_context",
    description = "Get complete user context including all teams and their projects. Returns comprehensive information for discovery and finding team_id/project_id values.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def get_user_context(response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: \'json\' or \'markdown\'"), api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")) -> ToolResponse:
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
    # Resolve API key from parameter or environment
    api_key = _get_api_key(api_key)
    return _respond(await _fetch_user_context(api_key), response_format)


@mcp.tool(
    name = "bugasura_find_project_by_name",
    description = "Find projects by name across ALL teams. Searches case-insensitive, partial match. Returns team_id and project_id for use in other operations.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def find_project_by_name(
    project_name: str = Field(description="Project name to search for (case-insensitive, partial match supported, min_length=1)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
        return _respond({
            'status': 'failed',
            'error': 'project_name cannot be empty'
        }, response_format)

    # Resolve API key from parameter or environment
    api_key = _get_api_key(api_key)

    # Get user context using internal helper
    context = await _fetch_user_context(api_key)
    if context.get('status') != 'OK':
        return _respond(context, response_format)

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

    return _respond(_paginated(matches, total=len(matches), offset=0,
                      query=project_name, matches=matches), response_format)


@mcp.tool(
    name = "bugasura_find_team_by_name",
    description = "Find teams by name (case-insensitive, partial match). Returns team_id and project count for teams the user belongs to.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def find_team_by_name(
    team_name: str = Field(description="Team name to search for (case-insensitive, partial match supported, min_length=1)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
        return _respond({
            'status': 'failed',
            'error': 'team_name cannot be empty'
        }, response_format)

    # Resolve API key from parameter or environment
    api_key = _get_api_key(api_key)

    # Get user context using internal helper
    context = await _fetch_user_context(api_key)
    if context.get('status') != 'OK':
        return _respond(context, response_format)

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

    return _respond(_paginated(matches, total=len(matches), offset=0,
                      query=team_name, matches=matches), response_format)
