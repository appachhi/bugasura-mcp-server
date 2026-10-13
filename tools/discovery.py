"""Bugasura MCP tools: discovery."""
from typing import Literal

from pydantic import Field

from core.app import mcp
from utils.auth import fetch_user_context, get_api_key
from utils.formatting import paginated, respond
from utils.output_types import ToolResponse
from utils.resolvers import search_projects_by_name


@mcp.tool(
    name = "bugasura_get_user_context",
    title = "Get User Context",
    description = "Get complete user context including all teams and their projects. Returns comprehensive information for discovery and finding team_id/project_id values.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def get_user_context(response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: \'json\' or \'markdown\'")) -> ToolResponse:
    """
    Get complete user context including all teams and their projects.

    This is a convenience tool that returns comprehensive information about
    all teams and projects the user has access to. It's useful for:
    - Initial setup/discovery
    - Finding team_id and project_id values for subsequent operations
    - Understanding the user's organizational structure

    Args:

    Returns:
        dict: {
            'status': 'OK',
            'teams': [
                {
                    'team_id': int,
                    'team_name': str,
                    'role': str,
                    'is_expired': int,   # 1 = subscription lapsed, team is unusable
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
    api_key = get_api_key()
    return respond(await fetch_user_context(api_key), response_format)


@mcp.tool(
    name = "bugasura_find_project_by_name",
    title = "Find Project by Name",
    description = "Find projects by name across ALL teams. Searches case-insensitive, partial match. Returns team_id and project_id for use in other operations.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def find_project_by_name(
    project_name: str = Field(description="Project name to search for (case-insensitive, partial match supported, min_length=1)", min_length=1),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
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
        return respond({
            'status': 'failed',
            'error': 'project_name cannot be empty'
        }, response_format)

    # Resolve API key from parameter or environment
    api_key = get_api_key()

    search = await search_projects_by_name(api_key, project_name)
    if search.get('status') != 'OK':
        return respond(search, response_format)
    matches = search['matches']

    return respond(paginated(matches, total=len(matches), offset=0,
                      query=project_name, matches=matches), response_format)


@mcp.tool(
    name = "bugasura_find_team_by_name",
    title = "Find Team by Name",
    description = "Find teams by name (case-insensitive, partial match). Returns team_id and project count for teams the user belongs to.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def find_team_by_name(
    team_name: str = Field(description="Team name to search for (case-insensitive, partial match supported, min_length=1)", min_length=1),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
) -> ToolResponse:
    """
    Find teams by name that the user belongs to.

    This is a convenience tool that searches for teams matching the given name
    (case-insensitive, partial match). Useful when you know the team name but
    not the team_id.

    Args:
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
                    'project_count': int,
                    'is_expired': int   # 1 = subscription lapsed, team is unusable
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
        return respond({
            'status': 'failed',
            'error': 'team_name cannot be empty'
        }, response_format)

    # Resolve API key from parameter or environment
    api_key = get_api_key()

    # Get user context using internal helper
    context = await fetch_user_context(api_key)
    if context.get('status') != 'OK':
        return respond(context, response_format)

    # Search for matching teams
    matches = []
    search_term = team_name.lower().strip()

    for team in context['teams']:
        if search_term in team.get('team_name', '').lower():
            matches.append({
                'team_id': team.get('team_id'),
                'team_name': team.get('team_name'),
                'role': team.get('role'),
                'project_count': len(team.get('projects', [])),
                'is_expired': team.get('is_expired')
            })

    return respond(paginated(matches, total=len(matches), offset=0,
                      query=team_name, matches=matches), response_format)
