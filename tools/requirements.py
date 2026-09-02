"""Bugasura MCP tools: requirements."""
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
    name="bugasura_list_requirements",
    description=(
        "List requirements for a project with pagination and filtering. Returns requirement summaries "
        "with support for folders, sprints, sorting, and search. Interactive team/project selection "
        "available. Each requirement's `id` is the REQ number the user sees in Bugasura (REQ1, REQ2...) "
        "— show the user that id and the title, exactly as the requirements page does; `requirement_id` "
        "is the internal id for other tools and must not be shown."
    ),
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def list_requirements(
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier for filtering requirements", ge=1),
    folder_id: str = Field(default="", description="Folder identifier (empty string fetches all root requirements)"),
    sort_by: str = Field(default="", description="Sort order for requirements"),
    search_text: str = Field(default="", description="Search text to filter requirements"),
    is_first_load: int = Field(default=0, description="Flag indicating first load (0 or 1)"),
    total_loaded_count: int = Field(default=0, description="Total count of requirements already loaded"),
    page_name: str = Field(default="", description="Page name for context-specific logic"),
    report_id: str = Field(default="", description="Report identifier for filtering"),
    req_type: str = Field(default="", description="Requirement type filter"),
    status: str = Field(default="", description="Requirement status filter"),
    start_at: int = Field(default=0, description="Pagination offset (default: 0, ge=0)"),
    max_results: int = Field(default=10, description="Number of results to return (default: 10, ge=1, le=100)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment."),
    ctx: Optional[Context] = None,
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get("valid"):
        return _respond(validation, response_format)

    # Use centralized context selection helper
    context = await select_team_project_context(api_key, team_id, project_id, "list_requirements")

    # If context selection is needed, return the selection prompt
    if "status" in context and context["status"] == "selection_required":
        return _respond(context, response_format)

    # If context selection failed, return the error
    if "status" in context and context["status"] == "failed":
        return _respond(context, response_format)

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
    if ctx is not None:
        await ctx.report_progress(0.5, total=1.0, message=f"Fetching requirements for project {context['project_id']}")
    response = await make_api_request(
        "GET",
        "/v1/requirements/list",
        api_key,
        params=params
    )

    # Filter out large unnecessary fields to reduce payload size, then wrap in envelope
    response = filter_large_fields(response)

    # Show `id` as the REQ number the requirements page renders; `requirement_id` stays as is.
    requirements_list = response.get('requirementsList')
    groups = (requirements_list.values() if isinstance(requirements_list, dict)
              else [requirements_list])
    for group in groups:
        if not isinstance(group, list):
            continue
        for requirement in group:
            if isinstance(requirement, dict) and requirement.get('id') not in (None, ''):
                requirement['id'] = f"REQ{requirement['id']}"

    # Name the list explicitly: requirementsList is a dict, so the first list picked was the priorities.
    return _respond(_paginate_upstream(response, items_key='requirementsList', offset=start_at),
                    response_format)


@mcp.tool(
    name="bugasura_list_requirement_folders",
    description="List all requirement folders for a project with hierarchical structure. Use this to view available folders before creating requirements or to check if a folder name already exists.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def list_requirement_folders(
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    parent_folder_id: Optional[int] = Field(default=None, description="Filter by parent folder ID (optional - omit to get all folders)"),
    include_hierarchy: bool = Field(default=True, description="Include full folder hierarchy (default: True)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return _respond(validation, response_format)

    # Use centralized context selection
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_list_requirement_folders')

    if context.get('status') == 'selection_required':
        return _respond(context, response_format)

    # Extract validated IDs
    team_id = context['team_id']
    project_id = context['project_id']

    logger.info(f"list_requirement_folders: Fetching requirement folders for project_id={project_id}, parent_folder_id={parent_folder_id}")

    # Build request parameters
    params = {
        'appId': str(project_id),
        'teamId': str(team_id),
        'folderId': '',
        'parentFolderId': '',
        'isGetReportList': 0,
        'folderType': 'REQUIREMENTS',
    }

    # Make API request to get folders
    response = await make_api_request('GET', '/v1/testRepo/get', api_key, params=params)

    if response.get('status') != 'OK':
        logger.error(f"list_requirement_folders: Failed to fetch folders: {response.get('message')}")
        return _respond({
            'status': 'failed',
            'error': 'Failed to fetch requirement folders',
            'message': response.get('message', 'Could not retrieve folder list')
        }, response_format)

    # Extract folders from response (API returns hierarchical structure under 'tcRepoStructure')
    all_folders = response.get('tcRepoStructure', [])

    # Filter folders if parent_folder_id is specified
    filtered_folders = []
    if parent_folder_id is not None:
        for folder in all_folders:
            if folder.get('parent_id') == parent_folder_id:
                filtered_folders.append(folder)
        logger.info(f"list_requirement_folders: Filtered {len(filtered_folders)} folders with parent_folder_id={parent_folder_id}")
    else:
        filtered_folders = all_folders
        logger.info(f"list_requirement_folders: Retrieved {len(filtered_folders)} total folders")

    # Build clean response
    folders_list = []
    for folder in filtered_folders:
        folder_info = {
            'folder_id': folder.get('id'),
            'folder_name': folder.get('name'),
            'parent_folder_id': folder.get('parent_id'),
            'tc_count': folder.get('tc_count', 0),
            'req_count': folder.get('req_count', 0),
        }

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

    return _respond(_paginated(folders_list, total=len(folders_list), offset=0,
                      folders=folders_list,
                      project_id=project_id, team_id=team_id, message=message), response_format)


@mcp.tool(
    name="bugasura_create_requirement",
    description="Create a new requirement in Bugasura with automatic folder management. If no folder exists for requirements, creates a default folder first. Supports smart assignee resolution and interactive team/project selection.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def create_requirement(
    title: str = Field(description="Requirement title"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    app_id: Optional[int] = Field(default=None, description="Application identifier"),
    details: str = Field(default="", description="Detailed description of the requirement"),
    overview: str = Field(default="", description="Brief overview of the requirement"),
    priority: Literal["P0", "P1", "P2", "P3", "P4"] = Field(default="P2", description="Priority level (e.g., P0, P1, P2, P3, P4)"),
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(default="MEDIUM", description="Severity level (e.g., LOW, MEDIUM, HIGH, CRITICAL)"),
    source: str = Field(default="CUSTOM", description="Requirement source (e.g., CUSTOM, JIRA, ASANA, GITHUB, FIGMA, GOOGLE_DOCS) (default: CUSTOM)"),
    assignees: Optional[str] = Field(default=None, description="Comma-separated assignee identifiers or names (supports smart resolution)"),
    folder_id: Optional[int] = Field(default=None, description="Folder identifier - if not provided, uses or creates default folder", ge=1),
    folder_name: str = Field(default="Requirements", description="Folder name to use/create if folder_id not provided (default: 'Requirements')"),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier", ge=1),
    type: str = Field(default="EPIC", description="Requirement type (e.g., EPIC, STORY, TASK)"),
    status: str = Field(default="NEW", description="Requirement status (e.g., NEW, IN_PROGRESS, COMPLETED)"),
    parent_id: Optional[int] = Field(default=None, description="Parent requirement ID for hierarchical structure"),
    tags: str = Field(default="", description="Comma-separated tags for categorization"),
    isQuickAdd: int = Field(default=0, description="Quick add flag (0 or 1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        logger.error(f"create_requirement: API key validation failed")
        return validation

    # Use common team/project selection flow
    context = await select_team_project_context(
        api_key,
        team_id,
        project_id,
        'bugasura_create_requirement',
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
    project_details_response = await make_api_request('GET', '/v1/projects/get', api_key, params={
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
        folder_check_response = await make_api_request(
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
                create_folder_response = await make_api_request(
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
            resolution = await _find_user_ids_by_names_or_emails(api_key, team_id, assignees)

            if resolution["status"] != "OK":
                logger.error(f"create_requirement: Failed to resolve assignees: {resolution.get('error')}")
                return resolution

            # Convert list to comma-separated string as expected by API
            user_ids_list = resolution["user_ids"].split(',')
            assignee_ids_str = ",".join(user_ids_list)
            logger.info(f"create_requirement: Resolved to user IDs: {assignee_ids_str}")
        except (KeyError, AttributeError, TypeError, ValueError, requests.RequestException) as e:
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
        "sprintId": sprint_id if sprint_id else "",
    }

    # Add optional parent_id if provided
    if parent_id is not None and parent_id > 0:
        payload["parentId"] = str(parent_id)
        logger.debug(f"create_requirement: Added parent_id: {parent_id}")

    logger.info(f"create_requirement: Submitting requirement to API")
    logger.debug(f"create_requirement: Payload keys: {list(payload.keys())}")

    response = await make_api_request("POST", "/v1/requirement/add", api_key, data=payload)

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
    name="bugasura_get_requirement_details",
    description="Get specific requirement details by ID. Returns full requirement data, parent details, and priority list. Interactive team/project selection available.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def get_requirement_details(
    requirement_id: int = Field(description="Requirement numeric ID"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier", ge=1),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return _respond(validation, response_format)

    # Use centralized context selection helper
    context = await select_team_project_context(
        api_key,
        team_id,
        project_id,
        'bugasura_get_requirement_details',
        f', requirement_id={requirement_id}'
    )

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return _respond(context, response_format)

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

    response = await make_api_request(
        'GET',
        '/v1/requirement/get',
        api_key,
        params=params
    )

    # Return full response with requirement details, parent details, and priority list
    return _respond(response, response_format)


@mcp.tool(
    name="bugasura_update_requirement",
    description="Update a requirement by ID with partial fields. Can update any field including title, details, severity, priority, tags, status, assignees, type, folder, sprint, overview, and parent requirement. Interactive team/project selection available.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def update_requirement(
    requirement_id: int = Field(description="Requirement numeric ID to update"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    title: Optional[str] = Field(default=None, description="Updated requirement title"),
    details: Optional[str] = Field(default=None, description="Updated detailed description"),
    severity: Optional[str] = Field(default=None, description="Updated severity level (e.g., LOW, MEDIUM, HIGH, CRITICAL)"),
    priority: Optional[str] = Field(default=None, description="Updated priority level (e.g., P0, P1, P2, P3, P4)"),
    assignees: Optional[str] = Field(default=None, description="Updated comma-separated assignee identifiers or names"),
    tags: Optional[str] = Field(default=None, description="Updated comma-separated tags"),
    folder_id: Optional[int] = Field(default=None, description="Updated folder identifier", ge=1),
    sprint_id: Optional[int] = Field(default=None, description="Updated sprint identifier", ge=1),
    type: Optional[str] = Field(default=None, description="Updated requirement type (e.g., EPIC, STORY, TASK)"),
    overview: Optional[str] = Field(default=None, description="Updated brief overview"),
    status: Optional[str] = Field(default=None, description="Updated requirement status (e.g., NEW, IN_PROGRESS, COMPLETED)"),
    parent_id: Optional[int] = Field(default=None, description="Updated parent requirement ID"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if isinstance(validation, list):
        return {'status': 'failed', 'error': 'Unexpected API response format', 'details': str(validation)}
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = await select_team_project_context(
        api_key, team_id, project_id,
        'bugasura_update_requirement',
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

    existing_req_response = await make_api_request('GET', '/v1/requirement/get', api_key, params={
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
        resolution_result = await _find_user_ids_by_names_or_emails(api_key, team_id, assignees)
        if resolution_result['status'] != 'OK':
            logger.error(f"update_requirement: Failed to resolve assignee identifiers: {resolution_result.get('error')}")
            return resolution_result

        resolved_assignees = resolution_result['user_ids']
        logger.info(f"update_requirement: Resolved assignees to user_ids: {resolved_assignees}")

    # Validate parent_id if provided (only if it's a positive integer)
    if parent_id is not None and parent_id > 0:
        logger.info(f"Validating parent_id={parent_id}")
        parent_req_response = await make_api_request('GET', '/v1/requirement/get', api_key, params={
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
    response = await make_api_request('POST', '/v1/requirement/update', api_key, data=payload)

    # Add helpful information to response
    if response.get('status') == 'OK':
        response['updated_fields'] = update_fields
        logger.info(f"Successfully updated requirement {requirement_id}")
    else:
        logger.error(f"Failed to update requirement {requirement_id}: {response.get('message')}")

    return response


@mcp.tool(
    name="bugasura_create_requirement_folder",
    description="Create a new folder for organizing requirements in a project. Folders help organize requirements into logical groups.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def create_requirement_folder(
    folder_name: str = Field(description="Name for the new folder"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    parent_folder_id: int = Field(default=0, description="Parent folder ID for nested folders (0 for root level)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_create_requirement_folder', f', folder_name="{folder_name}"')

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

    # Resolve correct team_id from project details (project may belong to a different team than the user's default)
    project_details_response = await make_api_request('GET', '/v1/projects/get', api_key, params={
        'team_id': team_id,
        'project_id': project_id,
    })
    if project_details_response.get('status') == 'OK':
        project_team_id = project_details_response.get('project_details', {}).get('team_id')
        if project_team_id and project_team_id != team_id:
            logger.warning(f"create_requirement_folder: Team ID mismatch - context team_id={team_id}, project team_id={project_team_id}. Using project's team_id.")
            team_id = project_team_id

    # Check if folder with same name already exists at the same level
    logger.info(f"create_requirement_folder: Checking for duplicate folder name '{folder_name}' at parent_folder_id={parent_folder_id}")

    # Fetch existing folders to check for duplicates
    existing_folders_response = await make_api_request('GET', '/v1/testRepo/get', api_key, params={
        'appId': str(project_id),
        'teamId': str(team_id),
        'folderId': '',
        'parentFolderId': '',
        'isGetReportList': 0,
        'folderType': 'REQUIREMENTS',
    })

    if existing_folders_response.get('status') == 'OK':
        existing_folders = existing_folders_response.get('tcRepoStructure', [])

        # Check for duplicate names at the same parent level
        for folder in existing_folders:
            if folder.get('parent_id') == parent_folder_id and folder.get('name', '').lower() == folder_name.lower():
                parent_msg = "root level" if parent_folder_id == 0 else f"under parent folder ID {parent_folder_id}"
                logger.warning(f"create_requirement_folder: Duplicate folder name '{folder_name}' found at {parent_msg}")
                return {
                    'status': 'failed',
                    'error': 'Duplicate folder name',
                    'error_type': 'DuplicateFolderName',
                    'message': f"A folder named '{folder_name}' already exists at {parent_msg}. Please use a different name.",
                    'existing_folder_id': folder.get('id'),
                    'existing_folder_name': folder.get('name'),
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
        'appId': str(project_id),
        'teamId': str(team_id),
        'folderName': folder_name,
        'parentFolderId': parent_folder_id_str,
        'isRootFolder': is_root_folder,
        'folderType': 'REQUIREMENTS',
    }

    # Call API to create folder
    response = await make_api_request('POST', '/v1/testRepo/add', api_key, data=payload)

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
    name = "bugasura_delete_requirement",
    description = "Delete requirement(s) permanently by numeric ID, requirement key (e.g., 'REQ5', 'MCP11'), or exact/partial title match. Supports single or multiple deletions. Uses 3-step matching: exact key → exact title → partial title. Interactive selection available.",
    annotations={"readOnlyHint": False, "destructiveHint": True,  "idempotentHint": True,  "openWorldHint": True}
)
async def delete_requirement(
    requirement_identifier: str = Field(description="Requirement identifier: numeric ID (e.g., '123'), requirement key (e.g., 'REQ5', 'MCP11'), or requirement title text for matching"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    sprint_id: Optional[int] = Field(default=None, description="Sprint ID (optional - if provided, deletes from sprint; otherwise deletes from project, ge=1)"),
    folder_id: Optional[int] = Field(default=None, description="Folder ID (optional, ge=1)"),
    selected_requirement_ids: Optional[str] = Field(default=None, description="Comma-separated list of requirement IDs for bulk deletion (optional)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_delete_requirement', f', requirement_identifier={requirement_identifier}')

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

            requirements_response = await make_api_request('GET', '/v1/requirements/list', api_key, params=params)

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
    response = await make_api_request('POST', '/v1/requirement/delete', api_key, data=payload)

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


@mcp.tool(
    name="bugasura_link_unlink_requirement_testcases",
    description="Link or unlink test cases to/from a requirement. Supports interactive team/project selection and bulk operations with comma-separated test case IDs.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def link_unlink_requirement_testcases(
    requirement_id: int = Field(description="Requirement numeric ID to link/unlink test cases"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    testcase_ids: Optional[str] = Field(default=None, description="Comma-separated test case IDs to link (e.g., '123,456,789'). Required for linking."),
    unlink_testcase_id: Optional[int] = Field(default=None, description="Single test case ID to unlink from requirement. Required for unlinking."),
    is_delete: bool = Field(default=False, description="Set to True to unlink test cases, False to link (default)"),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (optional, ge=1)"),
    folder_id: Optional[int] = Field(default=None, description="Folder identifier (optional, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if isinstance(validation, list):
        return {'status': 'failed', 'error': 'Unexpected API response format', 'details': str(validation)}
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = await select_team_project_context(
        api_key, team_id, project_id,
        'bugasura_link_unlink_requirement_testcases',
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
    response = await make_api_request('POST', '/v1/requirement/linkUnlinkRequirementTestCases', api_key, data=payload)

    # Add helpful information to response
    if response.get('status') == 'OK':
        operation = 'unlinked' if is_delete else 'linked'
        logger.info(f"Successfully {operation} test case(s) for requirement {requirement_id}")
    else:
        logger.error(f"Failed to {'unlink' if is_delete else 'link'} test case(s): {response.get('message')}")

    return response
