"""Bugasura MCP tools: issues."""
import json
from typing import List, Literal, Optional

from fastmcp import Context
from pydantic import Field

from config.config import logger
from core.app import mcp
from utils.attachments import (
    ATTACH_FILE_PATHS_DESCRIPTION, ATTACH_UPLOAD_ID_DESCRIPTION, attachment_names_csv,
    close_upload_files, open_attachments, send_with_attachments,
)
from utils.auth import get_api_key, validate_api_key
from utils.client import make_api_request
from utils.formatting import paginate_upstream, respond, filter_large_fields
from utils.output_types import ToolResponse
from utils.resolvers import (
    IdOrName, find_user_ids_by_names_or_emails, resolve_issue_identifier_to_id, resolve_issue_ref,
    select_team_project_context,
)


@mcp.tool(
    name = "bugasura_create_issue",
    title = "Create Issue",
    description = "Create a new issue/bug with required summary. Supports severity, status, environment details, tags, assignees, custom fields and file attachments (screenshots, logs, recordings: pass upload_id from bugasura_create_upload_link(purpose='attachment')). An issue is always a failure: to report that a sprint test case passed or failed, use bugasura_report_test_case_result. Interactive team/project/sprint selection available.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def create_issue(
    summary: str = Field(description="Issue summary/title (required, min_length=1)", min_length=1),
    team_id: Optional[IdOrName] = Field(default=None, description="Team id or name (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (optional - will prompt if not provided, ge=1)", ge=1),
    description: str = Field(default="", description="Detailed issue description (optional, supports HTML)"),
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(default="MEDIUM", description="Severity: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW' (default: MEDIUM)"),
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
    custom_fields: str = Field(default="", description="JSON string of custom field values (optional)"),
    upload_id: Optional[str] = Field(default=None, description=ATTACH_UPLOAD_ID_DESCRIPTION),
    file_paths: List[str] = Field(default=[], description=ATTACH_FILE_PATHS_DESCRIPTION),
) -> ToolResponse:
    """
    Create a new issue/bug in Bugasura.

    Interactive flow: If team_id/project_id/sprint_id are not provided, this function
    will return available options for the user to select from. The AI assistant will
    guide the user through the selection process.

    Args:
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
        upload_id / file_paths: Files to attach once the issue exists (/v1/issues/attachments/add)

    Returns:
        dict: API response containing:
            - issue_key: Numeric ID (testresults_id)
            - issue_id: Human-readable ID (e.g., "JUS6")
            - status: "OK" or error status
        OR a selection prompt if team_id/project_id/sprint_id not provided
    """
    # Validate API key before proceeding
    api_key = get_api_key()
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper for team and project
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_create_issue', f', summary="{summary}"')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Step 3: If sprint_id not provided, fetch and return sprint options for the selected project
    if sprint_id is None:
        # Call API directly instead of using the MCP tool function
        sprints_response = await make_api_request('GET', '/v1/sprints/list', api_key, params={
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
            'instruction': f'Please call bugasura_create_issue again with sprint_id parameter. Example: bugasura_create_issue(team_id={team_id}, project_id={project_id}, sprint_id=<selected_sprint_id>, summary="{summary}")'
        }

    # All context parameters provided - proceed with issue creation

    # IMPORTANT: Validate that the sprint exists and belongs to this project
    # The backend will fail with "Error getting testplan report" if sprint_id is invalid
    logger.info(f"create_issue: Validating sprint_id={sprint_id} for project_id={project_id}")
    sprint_validation = await make_api_request('GET', '/v1/sprints/list', api_key, params={
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

    # Open the attachments first, so a bad file fails before the issue exists
    opened = open_attachments(file_paths, upload_id)
    if opened.get('status') != 'OK':
        return opened

    # Make POST request to create issue endpoint
    # data= parameter sends as form-encoded data (application/x-www-form-urlencoded)
    try:
        response = await make_api_request('POST', '/v1/issues/add', api_key, data=payload)
    except BaseException:
        close_upload_files(opened['files'])
        raise
    if not opened['files']:
        return response
    # /issues/add returns the new issue under issue_details, not at the top level
    issue_key = (response.get('issue_details') or {}).get('issue_key')
    if response.get('status') != 'OK' or not issue_key:
        close_upload_files(opened['files'])
        return response

    # Attached in a second call: /issues/attachments/add records every file type, while
    # /issues/add only appears to keep images from its multipart files
    attached = await _attach_issue_files(api_key, team_id, issue_key, opened, upload_id)
    if attached.get('status') == 'OK':
        for key in ('attached_files', 'not_attached', 'attachment_errors', 'warning'):
            if key in attached:
                response[key] = attached[key]
    else:
        response['attachment_error'] = attached.get('message') or attached.get('error')
        response['message'] = (f"{response.get('message', 'Issue created')}. The attachments could not be "
                               f"added; retry with bugasura_add_issue_attachments"
                               f"{' and the same upload_id' if upload_id else ''}.")
    return response


async def _attach_issue_files(api_key: str, team_id: int, issue_key, opened: dict,
                              upload_id: Optional[str]) -> dict:
    """POST /v1/issues/attachments/add with already opened files (one field per file)."""
    logger.info(f"Attaching {len(opened['files'])} file(s) to issue {issue_key}")
    return await send_with_attachments('POST', '/v1/issues/attachments/add', api_key, opened, upload_id, data={
        'team_id': team_id,
        'issue_key': issue_key,
        'source': 'API',
    })


@mcp.tool(
    name = "bugasura_add_issue_attachments",
    title = "Add Issue Attachments",
    description = (
        "Attach files (screenshots, logs, recordings, documents) to an existing issue. "
        "On the hosted server get an upload link with bugasura_create_upload_link(purpose='attachment'), "
        "let the user upload the file(s), then pass its upload_id here. Local STDIO servers can pass "
        "file_paths instead. Never read or encode the file yourself."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def add_issue_attachments(
    issue_id: IdOrName = Field(description="Issue id or key, e.g. 107294 or 'JUS3'"),
    upload_id: Optional[str] = Field(default=None, description=ATTACH_UPLOAD_ID_DESCRIPTION),
    file_paths: List[str] = Field(default=[], description=ATTACH_FILE_PATHS_DESCRIPTION),
    team_id: Optional[IdOrName] = Field(default=None, description="Team id or name (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
) -> ToolResponse:
    """
    Attach files to an issue via POST /v1/issues/attachments/add.

    Each file is its own multipart field. The API skips files over the team's attachment
    size limit (10 MB, or 200 MB on paid plans) and lists them in `errorMessage`; it renames
    stored files (spaces become underscores, clashes get a numeric prefix), so read the
    final names back with bugasura_get_issue.

    Returns:
        dict: {'status': 'OK', 'message': str, 'attached_files': [str], 'errorMessage'?: [str]}
        OR a selection prompt / failure envelope.
    """
    api_key = get_api_key()
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_add_issue_attachments',
                                                f', issue_id={issue_id}')
    if context.get('status') == 'selection_required':
        return context

    issue_id, error = await resolve_issue_ref(api_key, context, issue_id, 'bugasura_add_issue_attachments')
    if error:
        return error

    if not file_paths and not upload_id:
        return {
            'status': 'failed',
            'error': 'No files provided',
            'error_type': 'ValidationError',
            'message': ("Call bugasura_create_upload_link(purpose='attachment'), give the user the link, and "
                        "call this tool again with its upload_id once they have uploaded the file(s)."),
        }
    opened = open_attachments(file_paths, upload_id)
    if opened.get('status') != 'OK':
        return opened

    response = await _attach_issue_files(api_key, context['team_id'], issue_id, opened, upload_id)
    if response.get('status') == 'OK':
        response['next_step'] = "Tell the user which files were attached; mention any listed in errorMessage."
    return response


@mcp.tool(
    name = "bugasura_delete_issue_attachments",
    title = "Delete Issue Attachments",
    description = (
        "Permanently delete attachments from an issue by file name — the attachments[].name values "
        "bugasura_get_issue returns. Confirm the exact files with the user first; they cannot be "
        "recovered. Comment attachments are not touched (edit the comment instead)."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": True}
)
async def delete_issue_attachments(
    issue_id: IdOrName = Field(description="Issue id or key, e.g. 107294 or 'JUS3'"),
    file_names: List[str] = Field(description="Attachment file names to delete, exactly as bugasura_get_issue lists them in attachments[].name", min_length=1),
    team_id: Optional[IdOrName] = Field(default=None, description="Team id or name (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
) -> ToolResponse:
    """
    Delete issue attachments via POST /v1/issues/attachments/delete.

    The names are checked against the issue's current attachments (/v1/issues/attachments/get)
    first, so a typo comes back with the real names instead of a partial delete.

    Returns:
        dict: {'status': 'OK', 'message': str, 'deleted_files': [str]}
        OR a selection prompt / failure envelope (unknown names list `available_files`).
    """
    api_key = get_api_key()
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_delete_issue_attachments',
                                                f', issue_id={issue_id}')
    if context.get('status') == 'selection_required':
        return context

    issue_id, error = await resolve_issue_ref(api_key, context, issue_id, 'bugasura_delete_issue_attachments')
    if error:
        return error
    team_id = context['team_id']

    names = [name.strip() for name in file_names if name and name.strip()]
    # The API splits file_names on commas
    if not names or any(',' in name for name in names):
        return {
            'status': 'failed',
            'error': 'Invalid file names',
            'error_type': 'ValidationError',
            'message': "Pass each attachment name as its own list item, exactly as bugasura_get_issue lists it.",
        }

    current = await make_api_request('GET', '/v1/issues/attachments/get', api_key, params={
        'team_id': team_id, 'issue_key': issue_id})
    if current.get('status') != 'OK':
        return current
    available = [a.get('name') for a in current.get('issue_attachments') or [] if a.get('name')]
    unknown = [name for name in names if name not in available]
    if unknown:
        return {
            'status': 'failed',
            'error': 'Attachment not found',
            'error_type': 'NotFound',
            'message': (f"Issue {issue_id} has no attachment named {', '.join(repr(n) for n in unknown)}, so "
                        f"nothing was deleted. Pick from available_files."),
            'available_files': available,
        }

    logger.info(f"delete_issue_attachments: Deleting {len(names)} attachment(s) from issue {issue_id}")
    response = await make_api_request('POST', '/v1/issues/attachments/delete', api_key, data={
        'team_id': team_id,
        'issue_key': issue_id,
        'file_names': ','.join(names),
    })
    # A partial failure is still OK upstream, with the failed names only in errorMessage text
    if response.get('status') == 'OK':
        if response.get('errorMessage'):
            response['next_step'] = ("Some files were not deleted (see errorMessage). Check what is left "
                                     "with bugasura_get_issue before retrying.")
        else:
            response['deleted_files'] = names
    return response


@mcp.tool(
    name = "bugasura_get_issue",
    title = "Get Issue",
    description = "Get detailed issue information by numeric ID. Returns full issue details including comments and attachments. Interactive team/project selection available.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def get_issue(
    issue_id: IdOrName = Field(description="Issue id or key, e.g. 107294 or 'JUS3'"),
    team_id: Optional[IdOrName] = Field(default=None, description="Team id or name (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
) -> ToolResponse:
    """
    Get issue details by numeric ID (testresults_id).

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    Args:
        issue_id: Issue id or key (e.g. 107294 or 'JUS3') (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)

    Returns:
        dict: Complete issue details including comments, attachments, history

    Note:
        Use bugasura_list_issues() to find the issue_id if you don't know it.
    """
    # Validate API key before proceeding
    api_key = get_api_key()
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return respond(validation, response_format)

    # Use centralized context selection helper
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_get_issue', f', issue_id={issue_id}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return respond(context, response_format)

    issue_id, error = await resolve_issue_ref(api_key, context, issue_id, 'bugasura_get_issue')
    if error:
        return respond(error, response_format)

    # GET request - integers are fine (auto-converted to strings in URL)
    response = await make_api_request('GET', '/v1/issues/get', api_key, params={
        'team_id': context['team_id'],
        'project_id': context['project_id'],
        'issue_key': issue_id
    })

    # Integration settings/mappings can run to 100KB+ and are not issue data
    return respond(filter_large_fields(response), response_format)


@mcp.tool(
    name = "bugasura_update_issue",
    title = "Update Issue",
    description = "Update an existing issue (partial updates supported). Can update any field including summary, description, severity, status, tags, assignees, environment, and custom fields. Interactive selection available.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def update_issue(
    issue_id: IdOrName = Field(description="Issue id or key, e.g. 107294 or 'JUS3' (to update)"),
    team_id: Optional[IdOrName] = Field(default=None, description="Team id or name (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (optional, ge=1)", ge=1),
    summary: Optional[str] = Field(default=None, description="New issue summary/title (optional)"),
    description: Optional[str] = Field(default=None, description="New description (optional, supports HTML)"),
    severity: Optional[Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]] = Field(default=None, description="New severity: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW' (optional)"),
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
    project_testcase_ids: Optional[str] = Field(default=None, description="Linked test case IDs, comma-separated (optional)"),
) -> ToolResponse:
    """
    Update an existing issue. Only updates the fields that are provided.

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    This function fetches the existing issue details first, then merges
    the updates with existing data to ensure all required fields (like report_id/sprint_id)
    are present.

    Args:
        issue_id: Issue id or key (e.g. 107294 or 'JUS3') (required)
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
    api_key = get_api_key()
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_update_issue', f', issue_id={issue_id}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    issue_id, error = await resolve_issue_ref(api_key, context, issue_id, 'bugasura_update_issue')
    if error:
        return error

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Step 1: Fetch existing issue details to get required fields like report_id
    logger.info(f"Fetching existing issue details for issue_id={issue_id}")
    existing_issue_response = await make_api_request('GET', '/v1/issues/get', api_key, params={
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
    return await make_api_request('POST', '/v1/issues/update', api_key, data=payload)


@mcp.tool(
    name = "bugasura_delete_issue",
    title = "Delete Issue",
    description = "Move an issue to Trash (restorable from the web app) by numeric ID, issue key (e.g., 'ISS09'), or exact/partial summary match. Uses 3-step matching: exact key → exact summary → partial summary. Interactive selection available.",
    annotations={"readOnlyHint": False, "destructiveHint": True,  "idempotentHint": True,  "openWorldHint": True}
)
async def delete_issue(
    issue_identifier: str = Field(description="Issue identifier: numeric ID (e.g., '123'), issue key (e.g., 'ISS09'), or summary text for matching"),
    team_id: Optional[IdOrName] = Field(default=None, description="Team id or name (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (optional - narrows search scope, ge=1)", ge=1),
) -> ToolResponse:
    """
    Delete an issue/bug from Bugasura by ID, issue key, or summary/title.

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    The issue is moved to Trash with its comments, attachments and history, and can be
    restored from the web app.

    Args:
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
    api_key = get_api_key()
    validation = await validate_api_key(api_key)
    # Handle case where API might return a list instead of dict
    if isinstance(validation, list):
        return {'status': 'failed', 'error': 'Unexpected API response format', 'details': str(validation)}
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_delete_issue', f', issue_identifier={issue_identifier}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    resolved = await resolve_issue_identifier_to_id(api_key, team_id, project_id, issue_identifier,
                                                    "delete_issue", sprint_id=sprint_id)
    if resolved.get('status') != 'OK':
        return resolved
    issue_id = resolved['issue_id']

    # Build payload
    payload = {
        "team_id": team_id,
        "issue_key": issue_id
    }

    logger.info(f"Deleting issue_id={issue_id} for team_id={team_id}, project_id={project_id}")
    return await make_api_request('POST', '/v1/issues/delete', api_key, data=payload)


@mcp.tool(
    name = "bugasura_list_issues",
    title = "List Issues",
    description = (
        "List issues for a project with optional sprint or run-level filter and pagination. "
        "Returns issue summaries with key details. "
        "Provide sprint_id to scope to a sprint; add test_run_execution_run_id to scope to a specific run execution. "
        "Provide testcase_id to list only the issues reported against that test case (combines with sprint/run). "
        "Issues are failures only; for passes use bugasura_list_test_cases with test_case_status. "
        "Interactive team/project selection available."
    ),
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def list_issues(
    team_id: Optional[IdOrName] = Field(default=None, description="Team id or name (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
    sprint_id: Optional[int] = Field(default=None, description="Sprint ID (report_id) to filter issues by sprint (optional, ge=1)", ge=1),
    test_run_execution_run_id: Optional[int] = Field(default=None, description="Test run execution ID. When provided, scopes issues to that specific run only. Obtain from bugasura_list_test_runs."),
    testcase_id: Optional[int] = Field(default=None, description="Test case ID (test_case_id from bugasura_list_test_cases). When provided, lists only issues linked to that test case (optional, ge=1).", ge=1),
    start_at: int = Field(default=0, description="Pagination offset (default: 0, ge=0)", ge=0),
    max_results: int = Field(default=10, description="Number of results to return (default: 10, ge=1, le=100)", ge=1, le=100),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    ctx: Optional[Context] = None,
) -> ToolResponse:
    api_key = get_api_key()
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return respond(validation, response_format)

    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_list_issues')
    if 'status' in context and context['status'] == 'selection_required':
        return respond(context, response_format)

    project_id = context['project_id']
    max_results = max(1, min(100, max_results))

    if ctx is not None:
        await ctx.report_progress(0.25, total=1.0, message=f"Fetching issues for project {project_id}")

    page_to_load = (start_at // max_results) + 1
    params = {
        'appId': project_id,
        'isGetIssueList': 1,
        'isGetStatsCount': 1,
        'pageToLoad': page_to_load,
        'customMaxIssuesPerPage': max_results,
    }
    if sprint_id:
        params['reportId'] = sprint_id
    if test_run_execution_run_id:
        params['testRunsExecutionRunId'] = test_run_execution_run_id
    if testcase_id:
        # The web app's issue filter; it matches the test case links made when a result is reported.
        params['filterConfig'] = json.dumps([{'filterType': 'basic', 'fieldName': 'project_test_case_id',
                                              'value': str(testcase_id), 'separator': 'AND', 'isCustomField': 0}])

    response = await make_api_request('GET', '/issues/getListDetails', api_key, params=params)

    if ctx is not None:
        await ctx.report_progress(0.75, total=1.0, message="Normalizing response")

    if not isinstance(response, dict) or response.get('status') != 'OK':
        return respond(response, response_format)

    issue_list_details = response.get('issueListDetails') or {}
    raw_issues = issue_list_details.get('bugsList') or []
    total_count = (issue_list_details.get('bugsStats') or {}).get('totalBugCount')

    issues = [
        {
            'issue_key': bug.get('testresults_id'),
            'issue_id': bug.get('issue_id'),
            'summary': bug.get('summary', ''),
            'description': bug.get('description', ''),
            'status': bug.get('bug_status'),
            'issue_type': bug.get('failure_type'),
            'tags': bug.get('bug_types'),
            'severity': bug.get('severity'),
            'priority': bug.get('priority'),
            'created_date': bug.get('created_dt'),
            'last_modified_date': bug.get('last_modified'),
            'creator_id': bug.get('creator_id'),
            'sprint_id': bug.get('report_id'),
            'sprint_name': bug.get('report_name'),
            'project_id': bug.get('app_id'),
            'project_name': bug.get('app_name'),
            'team_id': bug.get('team_id'),
            'is_public': bug.get('is_public'),
        }
        for bug in raw_issues
    ]
    normalized = {'status': 'OK', 'issue_list': issues, 'total_rows': total_count or len(issues)}
    return respond(paginate_upstream(normalized, items_key='issue_list', offset=start_at, max_results=max_results), response_format)


@mcp.tool(
    name="bugasura_list_issue_comments",
    title="List Issue Comments",
    description="List all comments for a specific issue. Returns comment history with user details, timestamps, and content. Supports interactive team/project/issue selection.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def list_issue_comments(
    issue_id: Optional[IdOrName] = Field(default=None, description="Issue id or key, e.g. 107294 or 'JUS3' (optional - will prompt if not provided)"),
    team_id: Optional[IdOrName] = Field(default=None, description="Team id or name (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
    creator_id: Optional[int] = Field(default=None, description="Filter by comment author ID (optional)"),
    get_user_comments_only: bool = Field(default=False, description="If True, return only user comments (exclude system comments)"),
    start_at: int = Field(default=0, description="Pagination offset (default: 0, ge=0)", ge=0),
    max_results: int = Field(default=10, description="Number of results to return (10-100, default: 10, ge=1, le=100)", ge=1, le=100),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    ctx: Optional[Context] = None,
) -> ToolResponse:
    """
    List all comments for a specific issue with pagination and filtering.
    Interactive flow: If team_id/project_id/issue_id are not provided, this function
    will guide you through selection:
    1. Select team (if not provided)
    2. Select project (if not provided)
    3. Select issue (if not provided)
    Args:
        issue_id: Issue id or key (e.g. 107294 or 'JUS3') (optional - will prompt if not provided)
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
    api_key = get_api_key()
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return respond(validation, response_format)

    # Step 1 & 2: Use centralized context selection helper for team and project
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_list_issue_comments')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return respond(context, response_format)

    issue_id, error = await resolve_issue_ref(api_key, context, issue_id, 'bugasura_list_issue_comments')
    if error:
        return respond(error, response_format)

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Step 3: If issue_id not provided, fetch and return issue options
    if issue_id is None:
        logger.info(f"list_issue_comments: No issue_id provided, fetching issues for project_id={project_id}")

        # Fetch issues for the selected project
        issues_response = await make_api_request('GET', '/v1/issues/list', api_key, params={
            'team_id': team_id,
            'project_id': project_id,
            'start_at': 0,
            'max_results': 50  # Get enough issues for selection
        })

        if issues_response.get('status') != 'OK':
            return respond(issues_response, response_format)

        issues = issues_response.get('issue_list', [])

        if not issues:
            return respond({
                'status': 'failed',
                'error': 'No issues found in the selected project.',
                'suggestion': 'Please create an issue first using create_issue() tool.'
            }, response_format)

        return respond({
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
            'instruction': f'Please call bugasura_list_issue_comments again with issue_id parameter. Example: bugasura_list_issue_comments(team_id={team_id}, project_id={project_id}, issue_id=<selected_issue_id>)'
        }, response_format)

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
    if ctx is not None:
        await ctx.report_progress(0.5, total=1.0, message=f"Fetching comments for issue {issue_id}")
    response = await make_api_request('GET', '/v1/issues/comments/list', api_key, params=params)

    # Add helpful information to response
    if response.get('status') == 'OK':
        comments = response.get('comment_list', [])
        response['total_comments'] = len(comments)
        logger.info(f"list_issue_comments: Retrieved {len(comments)} comments for issue {issue_id}")
    else:
        logger.error(f"list_issue_comments: Failed to fetch comments: {response.get('message')}")

    response = filter_large_fields(response)
    return respond(paginate_upstream(response, items_key='comment_list', offset=start_at, max_results=max_results), response_format)


@mcp.tool(
    name="bugasura_get_issue_comment",
    title="Get Issue Comment",
    description="Get details of a specific comment by comment ID. Returns full comment data including text, user info, and timestamps. Supports interactive team/project/issue selection.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def get_issue_comment(
    comment_id: Optional[int] = Field(default=None, description="Comment numeric ID (optional - will prompt if not provided, ge=1)", ge=1),
    issue_id: Optional[IdOrName] = Field(default=None, description="Issue id or key, e.g. 107294 or 'JUS3' (optional - will prompt if not provided)"),
    team_id: Optional[IdOrName] = Field(default=None, description="Team id or name (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
) -> ToolResponse:
    """
    Get details of a specific comment.
    Interactive flow: If team_id/project_id/issue_id are not provided, this function
    will guide you through selection:
    1. Select team (if not provided)
    2. Select project (if not provided)
    3. Select issue (if not provided)
    Args:
        comment_id: Comment identifier (required)
        issue_id: Issue id or key (e.g. 107294 or 'JUS3') (optional - will prompt if not provided)
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
    api_key = get_api_key()
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return respond(validation, response_format)

    # Step 1 & 2: Use centralized context selection helper for team and project
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_get_issue_comment', f', comment_id={comment_id}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return respond(context, response_format)

    issue_id, error = await resolve_issue_ref(api_key, context, issue_id, 'bugasura_get_issue_comment')
    if error:
        return respond(error, response_format)

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Step 3: If issue_id not provided, fetch and return issue options
    if issue_id is None:
        logger.info(f"get_issue_comment: No issue_id provided, fetching issues for project_id={project_id}")

        # Fetch issues for the selected project
        issues_response = await make_api_request('GET', '/v1/issues/list', api_key, params={
            'team_id': team_id,
            'project_id': project_id,
            'start_at': 0,
            'max_results': 50  # Get enough issues for selection
        })

        if issues_response.get('status') != 'OK':
            return respond(issues_response, response_format)

        issues = issues_response.get('issue_list', [])


        if not issues:
            return respond({
                'status': 'failed',
                'error': 'No issues found in the selected project.',
                'suggestion': 'Please create an issue first using create_issue() tool.'
            }, response_format)

        return respond({
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
            'instruction': f'Please call bugasura_get_issue_comment again with issue_id parameter. Example: bugasura_get_issue_comment(comment_id={comment_id}, team_id={team_id}, project_id={project_id}, issue_id=<selected_issue_id>)'
        }, response_format)

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
    response = await make_api_request('GET', '/v1/issues/comments/get', api_key, params=params)

    # Add helpful information to response
    if response.get('status') == 'OK':
        logger.info(f"get_issue_comment: Successfully retrieved comment {comment_id}")
    else:
        logger.error(f"get_issue_comment: Failed to fetch comment: {response.get('message')}")

    return respond(response, response_format)


@mcp.tool(
    name="bugasura_add_issue_comment",
    title="Add Issue Comment",
    description="Add a comment to an issue. Supports text, mentions and file attachments (pass upload_id from bugasura_create_upload_link(purpose='attachment'); comment text is still required). Interactive team/project/issue selection available.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def add_issue_comment(
    comment: str = Field(description="Comment text content (required, 1-65535 characters, supports HTML, min_length=1)"),
    issue_id: Optional[IdOrName] = Field(default=None, description="Issue id or key, e.g. 107294 or 'JUS3' (optional - will prompt if not provided)"),
    team_id: Optional[IdOrName] = Field(default=None, description="Team id or name (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
    is_public_comment: int = Field(default=1, description="Comment visibility: 1 for public (default), 0 for private"),
    source: str = Field(default="API", description="Comment source (default: API)"),
    upload_id: Optional[str] = Field(default=None, description=ATTACH_UPLOAD_ID_DESCRIPTION),
    file_paths: List[str] = Field(default=[], description=ATTACH_FILE_PATHS_DESCRIPTION),
) -> ToolResponse:
    """
    Add a comment to an issue with support for mentions, formatting and attachments.
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
        comment: Comment text content (required, 1-65535 characters)
                 - Supports HTML formatting
                 - Use @username to mention team members
                 - Will be automatically HTML-encoded by API for security
        issue_id: Issue id or key (e.g. 107294 or 'JUS3') (optional - will prompt if not provided)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        is_public_comment: Comment visibility (default: 1)
                          - 1: Public comment (visible to all team members and guests)
                          - 0: Private comment (visible only to team members)
        source: Comment source tracking (default: "API")
                Common values: "API", "PLATFORM", "EXTENSION", "IMPORT"
        upload_id / file_paths: Files attached to the comment (sent in the same request)
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
    api_key = get_api_key()
    validation = await validate_api_key(api_key)
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
    context = await select_team_project_context(
        api_key, team_id, project_id, 
        'bugasura_add_issue_comment', 
        f', comment="{comment[:50]}..."'  # Show truncated comment in instruction
    )

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    issue_id, error = await resolve_issue_ref(api_key, context, issue_id, 'bugasura_add_issue_comment')
    if error:
        return error

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Step 3: If issue_id not provided, fetch and return issue options
    if issue_id is None:
        logger.info(f"add_issue_comment: No issue_id provided, fetching issues for project_id={project_id}")

        # Fetch issues for the selected project
        issues_response = await make_api_request('GET', '/v1/issues/list', api_key, params={
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
            'instruction': f'Please call bugasura_add_issue_comment again with issue_id parameter. Example: bugasura_add_issue_comment(comment="{comment[:30]}...", team_id={team_id}, project_id={project_id}, issue_id=<selected_issue_id>)'
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

    opened = open_attachments(file_paths, upload_id)
    if opened.get('status') != 'OK':
        return opened

    # Make POST request to create comment endpoint
    logger.info(f"add_issue_comment: Sending request with {len(comment)} character comment, is_public={is_public_comment}, "
                f"{len(opened['files'])} attachment(s)")
    response = await send_with_attachments('POST', '/v1/issues/comments/add', api_key, opened, upload_id, data=payload)

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
    name="bugasura_update_issue_comment",
    title="Update Issue Comment",
    description="Update an existing issue comment, optionally adding attachments (upload_id from bugasura_create_upload_link(purpose='attachment')). Supports full interactive selection - prompts for team/project/issue/comment if not provided. Guides user through entire flow.",
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False,  "openWorldHint": True}
)
async def update_issue_comment(
    comment: str = Field(default="", description="Updated comment text (required when comment_id provided, 1-65535 characters, supports HTML, min_length=1)"),
    comment_id: Optional[int] = Field(default=None, description="Comment numeric ID to update (optional - will prompt if not provided, ge=1)", ge=1),
    issue_id: Optional[IdOrName] = Field(default=None, description="Issue id or key, e.g. 107294 or 'JUS3' (optional - will prompt if not provided)"),
    team_id: Optional[IdOrName] = Field(default=None, description="Team id or name (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
    comment_attachment_names: str = Field(default="", description="Comma-separated attachment filenames (optional, preserves existing if empty)"),
    upload_id: Optional[str] = Field(default=None, description=ATTACH_UPLOAD_ID_DESCRIPTION + " The files are added to the comment's existing attachments."),
    file_paths: List[str] = Field(default=[], description=ATTACH_FILE_PATHS_DESCRIPTION),
) -> ToolResponse:
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
        comment: Updated comment text (required when updating, 1-65535 characters)
                 - Supports HTML formatting
                 - Use @username to mention team members
                 - Will be automatically HTML-encoded by API for security
        comment_id: Comment identifier (optional - will prompt if not provided)
        issue_id: Issue id or key (e.g. 107294 or 'JUS3') (optional - will prompt if not provided)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        comment_attachment_names: Comma-separated attachment filenames to preserve (optional)
                                 - If empty, existing attachments are preserved
                                 - If provided, only listed attachments are kept
        upload_id / file_paths: New files to add to the comment
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
    api_key = get_api_key()
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Step 1 & 2: Use centralized context selection helper for team and project
    context = await select_team_project_context(
        api_key, team_id, project_id,
        'bugasura_update_issue_comment',
        f', comment="{comment[:50] if comment else ""}..."' if comment else ''
    )

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    issue_id, error = await resolve_issue_ref(api_key, context, issue_id, 'bugasura_update_issue_comment')
    if error:
        return error

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Step 3: If issue_id not provided, fetch and return issue options
    if issue_id is None:
        logger.info(f"update_issue_comment: No issue_id provided, fetching issues for project_id={project_id}")

        issues_response = await make_api_request('GET', '/v1/issues/list', api_key, params={
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
            'instruction': f'Please call bugasura_update_issue_comment again with issue_id parameter. Example: bugasura_update_issue_comment(comment="{comment[:30] if comment else ""}...", team_id={team_id}, project_id={project_id}, issue_id=<selected_issue_id>)'
        }

    # Step 4: NEW - If comment_id not provided, fetch and return comment options
    if comment_id is None:
        logger.info(f"update_issue_comment: No comment_id provided, fetching comments for issue_id={issue_id}")

        # Fetch all comments for the selected issue
        comments_response = await make_api_request('GET', '/v1/issues/comments/list', api_key, params={
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
                'suggestion': 'Use bugasura_add_issue_comment() to add a comment first.',
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
            'instruction': f'Please call bugasura_update_issue_comment again with comment_id parameter. Example: bugasura_update_issue_comment(comment="Your updated text here", comment_id=<selected_comment_id>, issue_id={issue_id}, team_id={team_id}, project_id={project_id})'
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
    comment_attachment_names = attachment_names_csv(comment_attachment_names)
    if comment_attachment_names:
        payload["commentAttachmentNames"] = comment_attachment_names
        logger.info(f"update_issue_comment: Preserving specific attachments: {comment_attachment_names}")

    opened = open_attachments(file_paths, upload_id)
    if opened.get('status') != 'OK':
        return opened

    # Make POST request to update comment endpoint
    logger.info(f"update_issue_comment: Sending request to update comment {comment_id}")
    response = await send_with_attachments('POST', '/v1/issues/comments/update', api_key, opened, upload_id, data=payload)

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
    name="bugasura_delete_issue_comment",
    title="Delete Issue Comment",
    description="Delete an issue comment (its content is removed and a 'deleted by' placeholder stays in the thread). Supports full interactive selection - prompts for team/project/issue/comment if not provided. Shows deletion warnings.",
    annotations={"readOnlyHint": False, "destructiveHint": True,  "idempotentHint": True,  "openWorldHint": True}
)
async def delete_issue_comment(
    comment_id: Optional[int] = Field(default=None, description="Comment numeric ID to delete (optional - will prompt if not provided, ge=1)", ge=1),
    issue_id: Optional[IdOrName] = Field(default=None, description="Issue id or key, e.g. 107294 or 'JUS3' (optional - will prompt if not provided)"),
    team_id: Optional[IdOrName] = Field(default=None, description="Team id or name (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
) -> ToolResponse:
    """
    Delete an issue comment (content removed, placeholder kept) with full interactive flow.
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
        comment_id: Comment identifier (optional - will prompt if not provided)
        issue_id: Issue id or key (e.g. 107294 or 'JUS3') (optional - will prompt if not provided)
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
    api_key = get_api_key()
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Step 1 & 2: Use centralized context selection helper for team and project
    context = await select_team_project_context(
        api_key, team_id, project_id,
        'bugasura_delete_issue_comment',
        f', comment_id={comment_id}' if comment_id else ''
    )

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    issue_id, error = await resolve_issue_ref(api_key, context, issue_id, 'bugasura_delete_issue_comment')
    if error:
        return error

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Step 3: If issue_id not provided, fetch and return issue options
    if issue_id is None:
        logger.info(f"delete_issue_comment: No issue_id provided, fetching issues for project_id={project_id}")

        issues_response = await make_api_request('GET', '/v1/issues/list', api_key, params={
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
            'instruction': f'Please call bugasura_delete_issue_comment again with issue_id parameter. Example: bugasura_delete_issue_comment(team_id={team_id}, project_id={project_id}, issue_id=<selected_issue_id>)'
        }

    # Step 4: NEW - If comment_id not provided, fetch and return comment options
    if comment_id is None:
        logger.info(f"delete_issue_comment: No comment_id provided, fetching comments for issue_id={issue_id}")

        # Fetch all comments for the selected issue
        comments_response = await make_api_request('GET', '/v1/issues/comments/list', api_key, params={
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
            'instruction': f'To proceed with PERMANENT deletion, call: bugasura_delete_issue_comment(comment_id=<selected_comment_id>, issue_id={issue_id}, team_id={team_id}, project_id={project_id})'
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
    response = await make_api_request('POST', '/v1/issues/comments/delete', api_key, data=payload)

    # Add helpful information to response
    if response.get('status') == 'OK':
        logger.info(f"delete_issue_comment: Successfully deleted comment {comment_id}")

        # The API keeps a "deleted by" placeholder in the thread instead of removing the row.
        response['note'] = ("The comment's content was removed; a 'This comment is deleted by ...' "
                            "placeholder stays in the issue's comment list.")
        response['operation'] = 'delete'

        # Log if attachments were deleted
        if response.get('commentContent'):
            logger.info(f"delete_issue_comment: Comment replaced with deletion message: {response['commentContent']}")
            response['replaced_with'] = response['commentContent']

        response['deletion_summary'] = {
            'comment_id': comment_id,
            'issue_id': issue_id,
            'deleted_successfully': True,
        }
    else:
        logger.error(f"delete_issue_comment: Failed to delete comment: {response.get('message')}")

    return response


@mcp.tool(
    name = "bugasura_add_issue_assignees",
    title = "Add Issue Assignees",
    description = "Add assignees to an issue by issue ID, identifier (e.g., 'NEW3'), user IDs, email addresses, or names. Supports comma-separated values. Interactive team/project selection available.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def add_issue_assignees(
    issue_id: str = Field(description="Issue numeric ID or identifier (e.g., 'NEW3')"),
    assignees: str = Field(description="Comma-separated assignees: user IDs (e.g., '123'), emails (e.g., 'john@example.com'), or names (e.g., 'John Doe')"),
    team_id: Optional[IdOrName] = Field(default=None, description="Team id or name (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
    ctx: Optional[Context] = None,
) -> ToolResponse:
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
    api_key = get_api_key()
    validation = await validate_api_key(api_key)
    # Handle case where API might return a list instead of dict
    if isinstance(validation, list):
        return {'status': 'failed', 'error': 'Unexpected API response format', 'details': str(validation)}
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_add_issue_assignees', f', issue_id={issue_id}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Resolve issue identifier to numeric ID if needed
    if ctx is not None:
        await ctx.report_progress(0.2, total=1.0, message="Resolving issue identifier")
    resolution_result = await resolve_issue_identifier_to_id(api_key, team_id, project_id, issue_id, "add_issue_assignees")
    if resolution_result['status'] != 'OK':
        return resolution_result
    issue_id = resolution_result['issue_id']

    # Convert names/emails to user IDs
    logger.info(f"add_issue_assignees: Resolving identifiers '{assignees}' for team_id={team_id}")
    if ctx is not None:
        await ctx.report_progress(0.5, total=1.0, message=f"Resolving {assignees.count(',') + 1} assignee identifier(s)")
    try:
        resolution_result = await find_user_ids_by_names_or_emails(api_key, team_id, assignees)
        logger.info(f"add_issue_assignees: Resolution result status: {resolution_result.get('status')}")

        if resolution_result['status'] != 'OK':
            logger.error(f"add_issue_assignees: Failed to resolve identifiers: {resolution_result.get('error')}")
            return resolution_result

        assignee_ids = resolution_result['user_ids']
        logger.info(f"add_issue_assignees: Resolved to user_ids: {assignee_ids}")
    except (KeyError, AttributeError, TypeError, ValueError) as e:
        logger.critical(f"add_issue_assignees: Exception during resolution: {type(e).__name__}: {str(e)}", exc_info=True)
        return {
            'status': 'failed',
            'error': 'Internal error during identifier resolution.',
            'error_type': 'InternalError'
        }

    # Call API to add assignees
    logger.info(f"add_issue_assignees: Adding assignees to issue_id={issue_id}, team_id={team_id}")
    response = await make_api_request('POST', '/v1/issues/assignees/add', api_key, data={
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
    name="bugasura_get_issue_assignees",
    title="Get Issue Assignees",
    description="Get the list of assignees for an issue. Returns assignee details including names, emails, user IDs, and profile images. Interactive team/project selection available.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def get_issue_assignees(
    issue_id: IdOrName = Field(description="Issue id or key, e.g. 107294 or 'JUS3'"),
    team_id: Optional[IdOrName] = Field(default=None, description="Team id or name (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (optional, ge=1)", ge=1),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
) -> ToolResponse:
    """
    Get the list of assignees for a specific issue.
    Returns detailed information about all users assigned to an issue,
    including their names, emails, user IDs, profile images, and invitation status.
    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.
    Args:
        issue_id: Issue id or key (e.g. 107294 or 'JUS3') (required)
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
    api_key = get_api_key()
    validation = await validate_api_key(api_key)

    # Handle case where API might return a list instead of dict
    if isinstance(validation, list):
        logger.error("get_issue_assignees: API validation returned unexpected list format")
        return respond({
            'status': 'failed',
            'error': 'Unexpected API response format',
            'details': str(validation)
        }, response_format)

    if not validation.get('valid'):
        logger.error(f"get_issue_assignees: API key validation failed: {validation.get('error')}")
        return respond(validation, response_format)

    # Use centralized context selection helper
    context = await select_team_project_context(
        api_key, team_id, project_id,
        'bugasura_get_issue_assignees',
        f', issue_id={issue_id}'
    )

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return respond(context, response_format)

    issue_id, error = await resolve_issue_ref(api_key, context, issue_id, 'bugasura_get_issue_assignees')
    if error:
        return respond(error, response_format)

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
    response = await make_api_request('GET', '/v1/issues/assignees/get', api_key, params=params)

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

    return respond(response, response_format)


@mcp.tool(
    name = "bugasura_remove_issue_assignees",
    title = "Remove Issue Assignees",
    description = "Remove assignees from an issue by user IDs, email addresses, or names (auto-resolves to IDs). Supports comma-separated values. Interactive team/project selection available.",
    annotations={"readOnlyHint": False, "destructiveHint": True,  "idempotentHint": True,  "openWorldHint": True}
)
async def remove_issue_assignees(
    issue_id: str = Field(description="Issue numeric ID or identifier (e.g., 'NEW3')"),
    assignees: str = Field(description="Comma-separated assignees to remove: user IDs (e.g., '123'), emails (e.g., 'john@example.com'), or names (e.g., 'John Doe')"),
    team_id: Optional[IdOrName] = Field(default=None, description="Team id or name (optional - will prompt if not provided)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
    ctx: Optional[Context] = None,
) -> ToolResponse:
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
    api_key = get_api_key()
    validation = await validate_api_key(api_key)
    # Handle case where API might return a list instead of dict
    if isinstance(validation, list):
        return {'status': 'failed', 'error': 'Unexpected API response format', 'details': str(validation)}
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_remove_issue_assignees', f', issue_id={issue_id}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Resolve issue identifier to numeric ID if needed
    if ctx is not None:
        await ctx.report_progress(0.2, total=1.0, message="Resolving issue identifier")
    resolution_result = await resolve_issue_identifier_to_id(api_key, team_id, project_id, issue_id, "remove_issue_assignees")
    if resolution_result['status'] != 'OK':
        return resolution_result
    issue_id = resolution_result['issue_id']

    # Convert names/emails to user IDs
    logger.info(f"remove_issue_assignees: Resolving identifiers '{assignees}' for team_id={team_id}")
    if ctx is not None:
        await ctx.report_progress(0.5, total=1.0, message=f"Resolving {assignees.count(',') + 1} assignee identifier(s)")
    try:
        resolution_result = await find_user_ids_by_names_or_emails(api_key, team_id, assignees)
        logger.info(f"remove_issue_assignees: Resolution result status: {resolution_result.get('status')}")

        if resolution_result['status'] != 'OK':
            logger.error(f"remove_issue_assignees: Failed to resolve identifiers: {resolution_result.get('error')}")
            return resolution_result

        assignee_ids = resolution_result['user_ids']
        logger.info(f"remove_issue_assignees: Resolved to user_ids: {assignee_ids}")
    except (KeyError, AttributeError, TypeError, ValueError) as e:
        logger.critical(f"remove_issue_assignees: Exception during resolution: {type(e).__name__}: {str(e)}", exc_info=True)
        return {
            'status': 'failed',
            'error': 'Internal error during identifier resolution.',
            'error_type': 'InternalError'
        }

    # Call API to remove assignees
    logger.info(f"remove_issue_assignees: Removing assignees from issue_id={issue_id}, team_id={team_id}")
    response = await make_api_request('POST', '/v1/issues/assignees/remove', api_key, data={
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
