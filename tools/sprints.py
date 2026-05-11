"""Bugasura MCP tools: sprints."""
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
    name = "bugasura_list_sprints",
    description = "List all sprints for a project. Supports interactive team/project selection if IDs not provided.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def list_sprints(
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return _respond(validation, response_format)

    # Use centralized context selection helper
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_list_sprints')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return _respond(context, response_format)

    # Context validated - proceed with operation
    upstream = await make_api_request('GET', '/v1/sprints/list', api_key, params={
        'team_id': context['team_id'],
        'project_id': context['project_id']
    })
    return _respond(_paginate_upstream(upstream, offset=0), response_format)


@mcp.tool(
    name = "bugasura_get_sprint_details",
    description = "Get detailed sprint information and statistics. Supports interactive team/project selection.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def get_sprint_details(
    sprint_id: int = Field(description="Sprint identifier", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return _respond(validation, response_format)

    # Use centralized context selection helper
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_get_sprint_details', f', sprint_id={sprint_id}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return _respond(context, response_format)

    # Context validated - proceed with operation
    return _respond(await make_api_request('GET', '/v1/sprints/get', api_key, params={
        'team_id': context['team_id'],
        'project_id': context['project_id'],
        'sprint_id': sprint_id
    }), response_format)


@mcp.tool(
    name = "bugasura_create_sprint",
    description = "Create a new sprint for a project. Requires sprint_name (5-250 chars). Supports dates, duration, and status. Interactive team/project selection available.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def create_sprint(
    sprint_name: str = Field(description="Name of the sprint (5-250 characters required, min_length=1)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    start_date: Optional[str] = Field(default=None, description="Sprint start date in YYYY-MM-DD format (optional)"),
    end_date: Optional[str] = Field(default=None, description="Sprint end date in YYYY-MM-DD format (optional)"),
    duration: Optional[int] = Field(default=None, description="Sprint duration in days (optional)"),
    sprint_status: Literal["SCHEDULED", "IN PROGRESS", "CANCELLED", "COMPLETED"] = Field(default="IN PROGRESS", description="Sprint status: 'SCHEDULED', 'IN PROGRESS', 'CANCELLED', 'COMPLETED' (default: IN PROGRESS)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_create_sprint', f', sprint_name="{sprint_name}"')

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
    return await make_api_request('POST', '/v1/sprints/add', api_key, data=payload)


@mcp.tool(
    name = "bugasura_update_sprint",
    description = "Update sprint details (partial updates supported). Can update name, dates, duration, or status. Interactive team/project selection available.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def update_sprint(
    sprint_id: int = Field(description="Sprint identifier", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    sprint_name: Optional[str] = Field(default=None, description="New sprint name (5-250 characters, optional)"),
    start_date: Optional[str] = Field(default=None, description="New start date in YYYY-MM-DD format (optional)"),
    end_date: Optional[str] = Field(default=None, description="New end date in YYYY-MM-DD format (optional)"),
    duration: Optional[int] = Field(default=None, description="New duration in days (optional)"),
    sprint_status: Optional[Literal["SCHEDULED", "IN PROGRESS", "CANCELLED", "COMPLETED"]] = Field(default=None, description="New status: 'SCHEDULED', 'IN PROGRESS', 'CANCELLED', 'COMPLETED' (optional)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_update_sprint', f', sprint_id={sprint_id}')

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
    existing_sprint_response = await make_api_request('GET', '/v1/sprints/list', api_key, params={
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
    return await make_api_request('POST', '/v1/sprints/update', api_key, data=payload)


@mcp.tool(
    name = "bugasura_delete_sprint",
    description = "Delete a sprint permanently by numeric ID or exact name match. Supports interactive team/project selection.",
    annotations={"readOnlyHint": False, "destructiveHint": True,  "idempotentHint": True,  "openWorldHint": True}
)
async def delete_sprint(
    sprint_identifier: str = Field(description="Sprint identifier: numeric ID (e.g., '123') or exact sprint name (e.g., 'Sprint 15')"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_delete_sprint', f', sprint_identifier={sprint_identifier}')

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
        sprints_response = await make_api_request('GET', '/v1/sprints/list', api_key, params={
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
    return await make_api_request('POST', '/v1/sprints/delete', api_key, data=payload)
