"""Bugasura MCP tools: project test data (environments, variables, files, file categories).

A project's test data lives in scopes: the project-wide "Globals" scope plus any number of
named environments (Staging, Production, ...). Each scope holds variables (key/value pairs)
and files; every scope starts with the default variables baseUrl and apiBaseUrl.

Environments, variables and files accept a numeric ID or a name. Wherever an environment is
expected, "Globals" names the global scope.

Files are public CDN objects: the listing carries each file's full URL (`json_file_path`),
which is the download link. Uploads send the files themselves as multipart `testData[]` parts
to /v1/projectTestDataFiles/add, which stores them on the CDN.
"""
import asyncio, contextlib, json, mimetypes, os, unicodedata, httpx
from typing import Any, List, Literal, Optional

from pydantic import Field

from config.config import (
    logger, TEST_DATA_APP_BUILD_CATEGORY, TEST_DATA_APP_BUILD_EXTS,
    TEST_DATA_CATEGORY_DESCRIPTION_MAX_LENGTH, TEST_DATA_DB_META_KEYS, TEST_DATA_DEFAULT_FILE_CATEGORIES,
    TEST_DATA_DEFAULT_VARIABLE_KEYS, TEST_DATA_DESCRIPTION_MAX_LENGTH, TEST_DATA_FILE_EXTS,
    TEST_DATA_GLOBALS_SCOPE, TEST_DATA_MAX_FILE_SIZE_MB, TEST_DATA_MAX_FILES_PER_UPLOAD,
    TEST_DATA_MAX_INLINE_CONTENT_BYTES, TEST_DATA_MAX_UPLOAD_TOTAL_MB, TEST_DATA_NAME_MAX_LENGTH,
    TEST_DATA_OFFICE_VIEWER_EXTS, TEST_DATA_OFFICE_VIEWER_URL, TEST_DATA_TEXT_EXTS,
    TEST_DATA_UPLOAD_CONFIRM_ATTEMPTS, TEST_DATA_UPLOAD_CONFIRM_INTERVAL_SECONDS,
    TEST_DATA_UPLOAD_TIMEOUT_BASE_SECONDS, TEST_DATA_UPLOAD_TIMEOUT_MAX_SECONDS,
    TEST_DATA_UPLOAD_TIMEOUT_SECONDS_PER_MB, TEST_DATA_VALUE_MAX_LENGTH,
)
from core.app import mcp
from core.uploads import discard, staged_paths
from utils.auth import current_user_id, get_api_key, validate_api_key
from utils.client import in_http_request, make_api_request
from utils.files import create_folder, local_path_rejected, remove_created_folder, resolve_save_destination
from utils.formatting import paginate_upstream, respond
from utils.output_types import ToolResponse
from utils.resolvers import IdOrName, select_team_project_context
from utils.urls import (
    download_url_to_path, download_url_tmp, fetch_url_bytes, infer_filename_from_url_path,
    normalise_share_url,
)


_ENVIRONMENT_FIELD = ("Environment: numeric ID, environment name, or 'Globals' for the "
                      "project-wide global scope (default: 'Globals')")
# Writes need a scope: the API takes an environmentId or isGlobal=1
_ENVIRONMENT_SCOPE_FIELD = ("Environment: numeric ID, environment name, or 'Globals' for the "
                            "project-wide global scope (required)")


# ---------------------------------------------------------------------------
# Environments
# ---------------------------------------------------------------------------

@mcp.tool(
    name = "bugasura_list_test_data_environments",
    title = "List Test Data Environments",
    description = "List a project's test data environments (Staging, Production, ...) with their baseUrl / apiBaseUrl values. Optionally include the project-wide 'Globals' scope.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def list_test_data_environments(
    team_id: IdOrName = Field(description="Team id or name (required)"),
    project_id: int = Field(description="Project identifier (required)", ge=1),
    include_globals: bool = Field(default=False, description="Also return the project-wide 'Globals' scope as a row (default: False)"),
    start_at: int = Field(default=0, ge=0, description="Pagination offset (default: 0)"),
    max_results: int = Field(default=50, ge=1, le=100, description="Number of results to return (default: 50, max 100)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
) -> ToolResponse:
    """
    List the test data environments of a project.

    Args:
        team_id: Team identifier (required)
        project_id: Project identifier (required)
        include_globals: Also return the 'Globals' scope as a row (default: False)
        start_at: Pagination offset (default: 0)
        max_results: Page size (default: 50, max 100)

    Returns:
        dict: {
            'status': 'OK', 'total', 'count', 'offset', 'has_more', 'next_offset',
            'items': [{
                'proj_test_data_env_id': int,   # '' for the Globals row
                'environment_name': str,        # 'Globals' for the global scope
                'base_url': str | None,         # value of the baseUrl variable
                'api_base_url': str | None,     # value of the apiBaseUrl variable
                'creator_name': str, 'created_date': str, 'last_modified': str, ...
            }]
        } OR a failure envelope.

    Examples:
        # List environments
        list_test_data_environments(team_id=7, project_id=70)

        # Include the Globals scope
        list_test_data_environments(team_id=7, project_id=70, include_globals=True)
    """
    context = await _test_data_context(team_id, project_id, 'bugasura_list_test_data_environments')
    if context.get('status') != 'OK':
        return respond(context, response_format)

    environments, error = await _fetch_environments(context, include_globals)
    if error:
        return respond(error, response_format)
    # Upstream returns the whole list; page it here
    return respond(paginate_upstream({'status': 'OK', 'environments': environments}, items_key='environments',
                                     offset=start_at, max_results=max_results, local=True), response_format)


@mcp.tool(
    name = "bugasura_get_test_data_environment",
    title = "Get Test Data Environment",
    description = "Get one test data environment (by ID or name, or 'Globals') with all its active variables and files.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def get_test_data_environment(
    team_id: IdOrName = Field(description="Team id or name (required)"),
    project_id: int = Field(description="Project identifier (required)", ge=1),
    environment: str = Field(default=TEST_DATA_GLOBALS_SCOPE, description=_ENVIRONMENT_FIELD, min_length=1),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
) -> ToolResponse:
    """
    Get a test data environment with its active variables and files.

    Args:
        environment: Environment ID, name, or 'Globals' (default: 'Globals')
        team_id: Team identifier (required)
        project_id: Project identifier (required)

    Returns:
        dict: {
            'status': 'OK',
            'environment': {...environment row...},
            'variables': [{'proj_test_data_id', 'variable', 'value', 'description',
                           'is_active', 'is_default_variable', ...}],
            'files': [{'proj_test_data_file_id', 'file_name', 'category', 'file_type',
                       'file_size' (KB), 'json_file_path' (download URL), ...}],
            'variable_count': int,
            'file_count': int
        } OR a failure envelope.

    Examples:
        get_test_data_environment(environment="Staging", team_id=7, project_id=70)
        get_test_data_environment(environment="Globals", team_id=7, project_id=70)
    """
    context = await _test_data_context(team_id, project_id, 'bugasura_get_test_data_environment',
                                       f', environment="{environment}"')
    if context.get('status') != 'OK':
        return respond(context, response_format)

    environments, error = await _fetch_environments(context, include_globals=True)
    if error:
        return respond(error, response_format)
    environment_row, error = _match(environments, TEST_DATA_GLOBALS_SCOPE if _is_globals(environment) else environment,
                                    'proj_test_data_env_id', 'environment_name', 'environment')
    if error:
        return respond(error, response_format)

    params = {'appId': str(context['project_id']), 'teamId': str(context['team_id'])}
    if environment_row.get('is_global'):
        params['isGetGlobalTestData'] = 1
    else:
        params['environmentId'] = str(environment_row['proj_test_data_env_id'])
        params['isGetGlobalTestData'] = 0
    details = await make_api_request('GET', '/v1/projectTestDataEnvironmentsDetails/get', context['api_key'], params=params)
    if details.get('status') != 'OK':
        return respond(details, response_format)

    variables = _clean_rows(details.get('testDataVariableDetails'))
    files = _clean_rows(details.get('testDataFilesDetails'))
    return respond({
        'status': 'OK',
        'environment': environment_row,
        'variables': variables,
        'files': files,
        'variable_count': len(variables),
        'file_count': len(files),
    }, response_format)


@mcp.tool(
    name = "bugasura_create_test_data_environment",
    title = "Create Test Data Environment",
    description = "Create a test data environment (e.g. 'Staging') in a project. It starts with empty baseUrl and apiBaseUrl variables. The name 'Globals' is reserved.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def create_test_data_environment(
    team_id: IdOrName = Field(description="Team id or name (required)"),
    project_id: int = Field(description="Project identifier (required)", ge=1),
    environment_name: str = Field(description="Name of the new environment (1-250 characters, unique in the project, not 'Globals')", min_length=1, max_length=TEST_DATA_NAME_MAX_LENGTH),
) -> ToolResponse:
    """
    Create a test data environment.

    The backend creates the default variables baseUrl and apiBaseUrl (empty) in the new
    environment; set them with bugasura_update_test_data_variable.

    Args:
        environment_name: Name of the environment (1-250 characters, unique, not 'Globals')
        team_id: Team identifier (required)
        project_id: Project identifier (required)

    Returns:
        dict: {
            'status': 'OK',
            'message': 'Environment created successfully',
            'environmentDetails': {'proj_test_data_env_id', 'app_id', 'environment_name', ...},
            'next_step': str
        } OR a failure envelope.

    Examples:
        create_test_data_environment(environment_name="Staging", team_id=7, project_id=70)
    """
    context = await _test_data_context(team_id, project_id, 'bugasura_create_test_data_environment',
                                       f', environment_name="{environment_name}"')
    if context.get('status') != 'OK':
        return context

    environment_name = environment_name.strip()
    error = _length_error('Environment name', environment_name, TEST_DATA_NAME_MAX_LENGTH)
    if error:
        return error
    if _is_globals(environment_name):
        return _failure_envelope(f"Reserved environment name: '{environment_name}'",
                     f"'{TEST_DATA_GLOBALS_SCOPE}' is the project-wide global scope and cannot be used as an environment name.")

    logger.info(f"create_test_data_environment: Creating test data environment '{environment_name}' for project_id={context['project_id']}")
    result = await make_api_request('POST', '/v1/projectTestDataEnvironments/add', context['api_key'], data={
        'appId': str(context['project_id']),
        'teamId': str(context['team_id']),
        'environmentName': environment_name,
    })
    if result.get('status') == 'OK':
        result['next_step'] = (f"Set the environment's {' / '.join(TEST_DATA_DEFAULT_VARIABLE_KEYS)} with "
                               f"bugasura_update_test_data_variable(environment=\"{environment_name}\", ...), "
                               f"and add more with bugasura_create_test_data_variable.")
    return result


@mcp.tool(
    name = "bugasura_rename_test_data_environment",
    title = "Rename Test Data Environment",
    description = "Rename a test data environment (by ID or name). The 'Globals' scope cannot be renamed.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def rename_test_data_environment(
    team_id: IdOrName = Field(description="Team id or name (required)"),
    project_id: int = Field(description="Project identifier (required)", ge=1),
    environment: str = Field(description="Environment to rename: numeric ID or name", min_length=1),
    new_environment_name: str = Field(description="New name (1-250 characters, unique in the project, not 'Globals')", min_length=1, max_length=TEST_DATA_NAME_MAX_LENGTH),
) -> ToolResponse:
    """
    Rename a test data environment.

    Args:
        environment: Environment ID or name (required)
        new_environment_name: New name (1-250 characters, unique, not 'Globals')
        team_id: Team identifier (required)
        project_id: Project identifier (required)

    Returns:
        dict: {
            'status': 'OK',
            'message': 'Environment updated successfully' | 'No changes detected.',
            'environmentDetails': {..., 'environment_name': <new name>, 'previous_name': str}
        } OR a failure envelope.

    Examples:
        rename_test_data_environment(environment="Staging", new_environment_name="QA", team_id=7, project_id=70)
    """
    context = await _test_data_context(team_id, project_id, 'bugasura_rename_test_data_environment',
                                       f', environment="{environment}", new_environment_name="{new_environment_name}"')
    if context.get('status') != 'OK':
        return context

    new_environment_name = new_environment_name.strip()
    error = _length_error('Environment name', new_environment_name, TEST_DATA_NAME_MAX_LENGTH)
    if error:
        return error
    if _is_globals(environment):
        return _failure_envelope('The Globals scope cannot be renamed',
                     f"'{TEST_DATA_GLOBALS_SCOPE}' is the project-wide global scope, not an environment. Pass an environment ID or name.")
    if _is_globals(new_environment_name):
        return _failure_envelope(f"Reserved environment name: '{new_environment_name}'",
                     f"'{TEST_DATA_GLOBALS_SCOPE}' is the project-wide global scope and cannot be used as an environment name.")

    environment_row, error = await _resolve_environment(context, environment, exact=True)
    if error:
        return error
    # The API compares names case-insensitively and answers "no changes" without saving a case-only rename
    if environment_row['environment_name'].lower() == new_environment_name.lower():
        if environment_row['environment_name'] == new_environment_name:
            return {'status': 'OK', 'message': f"The environment is already named '{new_environment_name}'.",
                    'environmentDetails': environment_row}
        return _failure_envelope('Case-only rename not supported',
                     f"Bugasura treats '{environment_row['environment_name']}' and '{new_environment_name}' as the "
                     f"same name, so a rename that only changes letter case is not saved. Tell the user; a rename "
                     f"to a different name, then back, works.")

    result = await make_api_request('POST', '/v1/projectTestDataEnvironments/update', context['api_key'], data={
        'appId': str(context['project_id']),
        'teamId': str(context['team_id']),
        'environmentId': str(environment_row['proj_test_data_env_id']),
        'environmentName': new_environment_name,
    })
    # The endpoint echoes the row as it was before the rename
    if result.get('status') == 'OK' and isinstance(result.get('environmentDetails'), dict):
        result['environmentDetails']['previous_name'] = environment_row['environment_name']
        result['environmentDetails']['environment_name'] = new_environment_name
    return result


@mcp.tool(
    name = "bugasura_duplicate_test_data_environment",
    title = "Duplicate Test Data Environment",
    description = "Create a new test data environment as a copy of an existing one (or of the 'Globals' scope): all its variables and files are copied. Every copied variable is active in the new environment, including ones deactivated in the source.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def duplicate_test_data_environment(
    team_id: IdOrName = Field(description="Team id or name (required)"),
    project_id: int = Field(description="Project identifier (required)", ge=1),
    source_environment: str = Field(description="Environment to copy: numeric ID, name, or 'Globals'", min_length=1),
    new_environment_name: str = Field(description="Name of the new environment (1-250 characters, unique in the project, not 'Globals')", min_length=1, max_length=TEST_DATA_NAME_MAX_LENGTH),
) -> ToolResponse:
    """
    Duplicate a test data environment (variables and files) under a new name.

    Args:
        source_environment: Environment ID, name, or 'Globals' to copy from
        new_environment_name: Name of the new environment (1-250 characters, unique, not 'Globals')
        team_id: Team identifier (required)
        project_id: Project identifier (required)

    Returns:
        dict: {
            'status': 'OK',
            'message': 'Environment duplicated successfully',
            'environmentDetails': {'proj_test_data_env_id', 'environment_name', ...},
            'source_environment': str
        } OR a failure envelope.

    Examples:
        # Copy Staging into a new UAT environment
        duplicate_test_data_environment(source_environment="Staging", new_environment_name="UAT", team_id=7, project_id=70)

        # Seed a new environment from the global test data
        duplicate_test_data_environment(source_environment="Globals", new_environment_name="Production", team_id=7, project_id=70)
    """
    context = await _test_data_context(team_id, project_id, 'bugasura_duplicate_test_data_environment',
                                       f', source_environment="{source_environment}", new_environment_name="{new_environment_name}"')
    if context.get('status') != 'OK':
        return context

    new_environment_name = new_environment_name.strip()
    error = _length_error('Environment name', new_environment_name, TEST_DATA_NAME_MAX_LENGTH)
    if error:
        return error
    # The duplicate endpoint skips the reserved-name check the add endpoint has
    if _is_globals(new_environment_name):
        return _failure_envelope(f"Reserved environment name: '{new_environment_name}'",
                     f"'{TEST_DATA_GLOBALS_SCOPE}' is the project-wide global scope and cannot be used as an environment name.")

    environment_row, error = await _resolve_environment(context, source_environment, exact=True)
    if error:
        return error

    payload = {
        'appId': str(context['project_id']),
        'teamId': str(context['team_id']),
        'newEnvironmentName': new_environment_name,
    }
    if environment_row:
        payload['sourceEnvironmentId'] = str(environment_row['proj_test_data_env_id'])
    else:
        payload['isGlobalEnvironmentDuplicate'] = '1'

    logger.info(f"duplicate_test_data_environment: Duplicating test data scope '{_scope_label(environment_row)}' as '{new_environment_name}' "
                f"for project_id={context['project_id']}")
    result = await make_api_request('POST', '/v1/projectTestDataEnvironments/duplicate', context['api_key'], data=payload)
    if result.get('status') == 'OK':
        result['source_environment'] = _scope_label(environment_row)
    return result


@mcp.tool(
    name = "bugasura_delete_test_data_environment",
    title = "Delete Test Data Environment",
    description = "Permanently delete a test data environment (by ID or name) together with ALL its variables and files. Cannot be undone. Refused while the environment holds custom variables or files unless delete_contents=true.",
    annotations={"readOnlyHint": False, "destructiveHint": True,  "idempotentHint": True,  "openWorldHint": True}
)
async def delete_test_data_environment(
    team_id: IdOrName = Field(description="Team id or name (required)"),
    project_id: int = Field(description="Project identifier (required)", ge=1),
    environment: str = Field(description="Environment to delete: numeric ID or name ('Globals' cannot be deleted)", min_length=1),
    delete_contents: bool = Field(default=False, description="Required (true) when the environment still holds custom variables or files; they are deleted with it (default: False)"),
) -> ToolResponse:
    """
    Permanently delete a test data environment with all its variables and files.

    Only the environment's creator, a team admin or a project admin may delete it.
    Test runs that used the environment keep running without it.

    Args:
        environment: Environment ID or name (required; 'Globals' cannot be deleted)
        delete_contents: Must be true when the environment holds custom variables or files
        team_id: Team identifier (required)
        project_id: Project identifier (required)

    Returns:
        dict: {
            'status': 'OK',
            'message': 'Environment deleted successfully',
            'environment_name': str,
            'deleted_variables': int,
            'deleted_files': int
        } OR a failure envelope (the refusal lists what would be deleted).

    Examples:
        # Delete an empty environment
        delete_test_data_environment(environment="Old QA", team_id=7, project_id=70)

        # Delete an environment and everything in it
        delete_test_data_environment(environment="Old QA", delete_contents=True, team_id=7, project_id=70)
    """
    context = await _test_data_context(team_id, project_id, 'bugasura_delete_test_data_environment',
                                       f', environment="{environment}"')
    if context.get('status') != 'OK':
        return context

    if _is_globals(environment):
        return _failure_envelope('The Globals scope cannot be deleted',
                     f"'{TEST_DATA_GLOBALS_SCOPE}' is the project-wide global scope, not an environment. "
                     f"Delete its variables or files individually instead.")

    environment_row, error = await _resolve_environment(context, environment, exact=True)
    if error:
        return error
    environment_id = str(environment_row['proj_test_data_env_id'])
    environment_name = environment_row['environment_name']

    # Count what goes with it; the default baseUrl/apiBaseUrl variables do not need the opt-in.
    # Not the details endpoint: it leaves out inactive variables, which the delete removes too
    variables, error = await _fetch_variables(context, environment_row)
    if error:
        return error
    files, _, error = await _fetch_files(context, environment_row)
    if error:
        return error
    variables = [v for v in variables if not v.get('is_global')]
    files = [f for f in files if not f.get('is_global')]
    custom_variables = [v for v in variables if not v.get('is_default_variable')]
    if (custom_variables or files) and not delete_contents:
        return _failure_envelope(f"Environment '{environment_name}' is not empty",
                     f"Environment '{environment_name}' holds {len(custom_variables)} custom variable(s) and "
                     f"{len(files)} file(s), which would be permanently deleted with it. Confirm with the user, "
                     f"then call again with delete_contents=true.",
                     'ConfirmationRequired',
                     variables=[v.get('variable') for v in custom_variables],
                     files=[f.get('file_name') for f in files])

    logger.info(f"delete_test_data_environment: Deleting test data environment '{environment_name}' (id={environment_id}) "
                f"for project_id={context['project_id']}")
    result = await make_api_request('POST', '/v1/projectTestDataEnvironments/delete', context['api_key'], data={
        'appId': str(context['project_id']),
        'teamId': str(context['team_id']),
        'environmentId': environment_id,
    })
    if result.get('status') == 'OK':
        result.update({'environment_name': environment_name, 'deleted_variables': len(variables),
                       'deleted_files': len(files)})
    return result


# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------

@mcp.tool(
    name = "bugasura_list_test_data_variables",
    title = "List Test Data Variables",
    description = "List the test data variables (key/value pairs) of an environment or of the 'Globals' scope, optionally filtered by key or active state.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def list_test_data_variables(
    team_id: IdOrName = Field(description="Team id or name (required)"),
    project_id: int = Field(description="Project identifier (required)", ge=1),
    environment: str = Field(default=TEST_DATA_GLOBALS_SCOPE, description=_ENVIRONMENT_FIELD, min_length=1),
    include_globals: bool = Field(default=False, description="With an environment, also return the global variables (default: False)"),
    variable_key: Optional[str] = Field(default=None, description="Return only the variable with this exact key (case-sensitive, optional)"),
    active: Literal["all", "active", "inactive"] = Field(default="all", description="Filter by state: 'all', 'active' or 'inactive' (default: all)"),
    start_at: int = Field(default=0, ge=0, description="Pagination offset (default: 0)"),
    max_results: int = Field(default=50, ge=1, le=100, description="Number of results to return (default: 50, max 100)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
) -> ToolResponse:
    """
    List the test data variables of a scope.

    Args:
        environment: Environment ID, name, or 'Globals' (default: 'Globals')
        include_globals: With an environment, also return the global variables
        variable_key: Exact (case-sensitive) key filter (optional)
        active: 'all' | 'active' | 'inactive' (default: 'all')
        team_id: Team identifier (required)
        project_id: Project identifier (required)
        start_at: Pagination offset (default: 0)
        max_results: Page size (default: 50, max 100)

    Returns:
        dict: {
            'status': 'OK', 'total', 'count', 'offset', 'has_more', 'next_offset',
            'scope': str,
            'items': [{
                'proj_test_data_id': int,
                'variable': str, 'value': str | None, 'description': str | None,
                'is_global': 0|1, 'environment_name': str | None,
                'is_active': 0|1, 'is_default_variable': 0|1,
                'creator_name': str, 'last_modified': str, ...
            }]
        } OR a failure envelope.

    Examples:
        list_test_data_variables(environment="Staging", team_id=7, project_id=70)
        list_test_data_variables(environment="Globals", variable_key="baseUrl", team_id=7, project_id=70)
    """
    context = await _test_data_context(team_id, project_id, 'bugasura_list_test_data_variables',
                                       f', environment="{environment}"')
    if context.get('status') != 'OK':
        return respond(context, response_format)

    environment_row, error = await _resolve_environment(context, environment)
    if error:
        return respond(error, response_format)
    variables, error = await _fetch_variables(context, environment_row, include_globals, variable_key)
    if error:
        return respond(error, response_format)

    if active != 'all':
        wanted = 1 if active == 'active' else 0
        variables = [v for v in variables if int(v.get('is_active') or 0) == wanted]
    # Upstream returns the whole list; page it here
    return respond(paginate_upstream({'status': 'OK', 'scope': _scope_label(environment_row), 'variables': variables},
                                     items_key='variables', offset=start_at, max_results=max_results, local=True),
                   response_format)


@mcp.tool(
    name = "bugasura_create_test_data_variable",
    title = "Create Test Data Variable",
    description = "Add a test data variable (key/value) to an environment or to the 'Globals' scope. Keys use letters, numbers, underscores or dashes and are unique per scope.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def create_test_data_variable(
    team_id: IdOrName = Field(description="Team id or name (required)"),
    project_id: int = Field(description="Project identifier (required)", ge=1),
    variable_key: str = Field(description="Variable key: letters, numbers, underscores or dashes, 1-250 characters (e.g. 'loginEmail')", min_length=1, max_length=TEST_DATA_NAME_MAX_LENGTH),
    environment: str = Field(description=_ENVIRONMENT_SCOPE_FIELD, min_length=1),
    value: str = Field(default="", description="Variable value (0-5000 characters)", max_length=TEST_DATA_VALUE_MAX_LENGTH),
    description: str = Field(default="", description="What the variable is for (0-500 characters, optional)", max_length=TEST_DATA_DESCRIPTION_MAX_LENGTH),
) -> ToolResponse:
    """
    Create a test data variable in an environment or the Globals scope.

    Args:
        variable_key: Key (letters, numbers, underscores, dashes; 1-250 characters; unique per scope)
        value: Value (0-5000 characters)
        description: Description (0-500 characters)
        environment: Environment ID, name, or 'Globals' (required)
        team_id: Team identifier (required)
        project_id: Project identifier (required)

    Returns:
        dict: {
            'status': 'OK',
            'message': 'Test data created successfully',
            'testDataDetails': {'proj_test_data_id', 'variable', 'value', 'description',
                                'is_global', 'proj_test_data_env_id', 'is_active', ...},
            'scope': str
        } OR a failure envelope.

    Examples:
        create_test_data_variable(variable_key="loginEmail", value="qa@example.com",
                                  environment="Staging", team_id=7, project_id=70)
    """
    context = await _test_data_context(team_id, project_id, 'bugasura_create_test_data_variable',
                                       f', variable_key="{variable_key}", environment="{environment}"')
    if context.get('status') != 'OK':
        return context

    variable_key = variable_key.strip()
    error = (_variable_key_error(variable_key)
             or _length_error('Variable value', value, TEST_DATA_VALUE_MAX_LENGTH, required=False)
             or _length_error('Description', description, TEST_DATA_DESCRIPTION_MAX_LENGTH, required=False))
    if error:
        return error

    environment_row, error = await _resolve_environment(context, environment, exact=True)
    if error:
        return error

    payload = _scope_params(context, environment_row)
    payload.update({
        'isGlobal': '0' if environment_row else '1',
        'variableKey': variable_key,
        'variableValue': value,
        'description': description,
    })
    result = await make_api_request('POST', '/v1/projectTestData/add', context['api_key'], data=payload)
    if result.get('status') == 'OK':
        result['scope'] = _scope_label(environment_row)
    return result


@mcp.tool(
    name = "bugasura_update_test_data_variable",
    title = "Update Test Data Variable",
    description = "Update a test data variable (by ID or key) in an environment or the 'Globals' scope: change its value, key, description, or activate/deactivate it. Only the fields you pass change.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def update_test_data_variable(
    team_id: IdOrName = Field(description="Team id or name (required)"),
    project_id: int = Field(description="Project identifier (required)", ge=1),
    variable: str = Field(description="Variable to update: numeric ID or exact key (e.g. 'baseUrl')", min_length=1),
    environment: str = Field(description=_ENVIRONMENT_SCOPE_FIELD, min_length=1),
    value: Optional[str] = Field(default=None, description="New value (1-5000 characters). A value cannot be cleared to empty.", max_length=TEST_DATA_VALUE_MAX_LENGTH),
    new_variable_key: Optional[str] = Field(default=None, description="Rename the key (letters, numbers, underscores, dashes; not allowed for baseUrl/apiBaseUrl)", max_length=TEST_DATA_NAME_MAX_LENGTH),
    description: Optional[str] = Field(default=None, description="New description (0-500 characters; not allowed for baseUrl/apiBaseUrl)", max_length=TEST_DATA_DESCRIPTION_MAX_LENGTH),
    is_active: Optional[bool] = Field(default=None, description="Activate (true) or deactivate (false) the variable"),
) -> ToolResponse:
    """
    Update a test data variable. Fields not passed keep their current value.

    The default variables baseUrl and apiBaseUrl can only have their value and active
    state changed, as in the web app.

    Args:
        variable: Variable ID or exact key (required)
        environment: Environment ID, name, or 'Globals' the variable belongs to (required)
        value: New value (1-5000 characters; the backend cannot store an empty value on update)
        new_variable_key: New key (optional)
        description: New description (optional)
        is_active: Activate / deactivate (optional)
        team_id: Team identifier (required)
        project_id: Project identifier (required)

    Returns:
        dict: {
            'status': 'OK',
            'message': 'Test data updated successfully',
            'testDataDetails': {...updated variable...},
            'scope': str
        } OR a failure envelope.

    Examples:
        # Point Staging at a new host
        update_test_data_variable(variable="baseUrl", value="https://staging.example.com",
                                  environment="Staging", team_id=7, project_id=70)

        # Deactivate a global variable
        update_test_data_variable(variable="legacyToken", is_active=False, environment="Globals",
                                  team_id=7, project_id=70)
    """
    context = await _test_data_context(team_id, project_id, 'bugasura_update_test_data_variable',
                                       f', variable="{variable}", environment="{environment}"')
    if context.get('status') != 'OK':
        return context

    if value is None and new_variable_key is None and description is None and is_active is None:
        return _failure_envelope('Nothing to update',
                     'Pass at least one of value, new_variable_key, description or is_active.')
    if value is not None:
        if value == '':
            return _failure_envelope('Empty value not supported',
                         'The backend ignores an empty value on update, so a value cannot be cleared. '
                         'Set a placeholder value or deactivate the variable with is_active=false.')
        error = _length_error('Variable value', value, TEST_DATA_VALUE_MAX_LENGTH)
        if error:
            return error
    if new_variable_key is not None:
        new_variable_key = new_variable_key.strip()
        error = _variable_key_error(new_variable_key)
        if error:
            return error
    if description is not None:
        error = _length_error('Description', description, TEST_DATA_DESCRIPTION_MAX_LENGTH, required=False)
        if error:
            return error

    environment_row, error = await _resolve_environment(context, environment, exact=True)
    if error:
        return error
    variables, error = await _fetch_variables(context, environment_row)
    if error:
        return error
    # Keys are case-sensitive identifiers: no partial matching
    existing, error = _match(variables, variable, 'proj_test_data_id', 'variable',
                             f"variable in {_scope_label(environment_row)}", allow_partial=False)
    if error:
        return error

    if existing.get('is_default_variable') and (
            (new_variable_key is not None and new_variable_key != existing.get('variable'))
            or description is not None):
        return _failure_envelope(f"'{existing.get('variable')}' is a default variable",
                     f"The key and description of the default variables {', '.join(TEST_DATA_DEFAULT_VARIABLE_KEYS)} "
                     f"cannot be changed; only their value and active state can.")

    # Read-modify-write: the endpoint rewrites key and description on every call
    payload = _scope_params(context, environment_row)
    payload.update({
        'testDataId': str(existing['proj_test_data_id']),
        'isGlobal': '0' if environment_row else '1',
        'variableKey': new_variable_key if new_variable_key is not None else existing.get('variable'),
        'variableValue': value if value is not None else (existing.get('value') or ''),
        'description': description if description is not None else (existing.get('description') or ''),
        'isActive': ('1' if is_active else '0') if is_active is not None else str(int(existing.get('is_active') or 0)),
    })
    result = await make_api_request('POST', '/v1/projectTestData/update', context['api_key'], data=payload)
    if result.get('status') == 'OK':
        result['scope'] = _scope_label(environment_row)
        # The echoed row keeps the old active state
        if isinstance(result.get('testDataDetails'), dict):
            result['testDataDetails'] = {k: v for k, v in result['testDataDetails'].items() if k not in TEST_DATA_DB_META_KEYS}
            result['testDataDetails']['is_active'] = int(payload['isActive'])
    return result


@mcp.tool(
    name = "bugasura_delete_test_data_variable",
    title = "Delete Test Data Variable",
    description = "Permanently delete one test data variable (by ID or exact key) from an environment or the 'Globals' scope. The default baseUrl/apiBaseUrl variables cannot be deleted. Cannot be undone.",
    annotations={"readOnlyHint": False, "destructiveHint": True,  "idempotentHint": True,  "openWorldHint": True}
)
async def delete_test_data_variable(
    team_id: IdOrName = Field(description="Team id or name (required)"),
    project_id: int = Field(description="Project identifier (required)", ge=1),
    variable: str = Field(description="Variable to delete: numeric ID or exact key", min_length=1),
    environment: str = Field(description=_ENVIRONMENT_SCOPE_FIELD, min_length=1),
) -> ToolResponse:
    """
    Permanently delete a single test data variable.

    Only the variable's creator, a team admin or a project admin may delete it. Exactly one
    variable is deleted: the tool always resolves and sends its ID.

    Args:
        variable: Variable ID or exact key (required)
        environment: Environment ID, name, or 'Globals' the variable belongs to (required)
        team_id: Team identifier (required)
        project_id: Project identifier (required)

    Returns:
        dict: {
            'status': 'OK',
            'message': 'Test data deleted successfully',
            'variable': str,
            'scope': str
        } OR a failure envelope.

    Examples:
        delete_test_data_variable(variable="legacyToken", environment="Staging", team_id=7, project_id=70)
    """
    context = await _test_data_context(team_id, project_id, 'bugasura_delete_test_data_variable',
                                       f', variable="{variable}", environment="{environment}"')
    if context.get('status') != 'OK':
        return context

    environment_row, error = await _resolve_environment(context, environment, exact=True)
    if error:
        return error
    variables, error = await _fetch_variables(context, environment_row)
    if error:
        return error
    existing, error = _match(variables, variable, 'proj_test_data_id', 'variable',
                             f"variable in {_scope_label(environment_row)}", allow_partial=False)
    if error:
        return error
    if existing.get('is_default_variable'):
        return _failure_envelope(f"'{existing.get('variable')}' is a default variable",
                     f"The default variables {', '.join(TEST_DATA_DEFAULT_VARIABLE_KEYS)} cannot be deleted. "
                     f"Deactivate it with bugasura_update_test_data_variable(is_active=false) instead.")

    # Always send the resolved testDataId: without it the endpoint deletes every variable in scope
    payload = _scope_params(context, environment_row)
    payload['testDataId'] = str(existing['proj_test_data_id'])
    if not environment_row:
        payload['isGlobal'] = '1'
    logger.info(f"delete_test_data_variable: Deleting test data variable '{existing.get('variable')}' (id={payload['testDataId']}) "
                f"from {_scope_label(environment_row)} for project_id={context['project_id']}")
    result = await make_api_request('POST', '/v1/projectTestData/delete', context['api_key'], data=payload)
    if result.get('status') == 'OK':
        result.update({'variable': existing.get('variable'), 'scope': _scope_label(environment_row)})
    return result


# ---------------------------------------------------------------------------
# Files & categories
# ---------------------------------------------------------------------------

@mcp.tool(
    name = "bugasura_list_test_data_files",
    title = "List Test Data Files",
    description = "List the test data files of an environment or of the 'Globals' scope, optionally filtered by category or file name. Each file carries a download URL. Also returns the project's file categories.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def list_test_data_files(
    team_id: IdOrName = Field(description="Team id or name (required)"),
    project_id: int = Field(description="Project identifier (required)", ge=1),
    environment: str = Field(default=TEST_DATA_GLOBALS_SCOPE, description=_ENVIRONMENT_FIELD, min_length=1),
    include_globals: bool = Field(default=False, description="With an environment, also return the global files (default: False)"),
    category: Optional[str] = Field(default=None, description="Return only files in this category (exact name, e.g. 'App Build', optional)"),
    file_name: Optional[str] = Field(default=None, description="Return only files with this exact name (e.g. 'users.csv', optional)"),
    start_at: int = Field(default=0, ge=0, description="Pagination offset (default: 0)"),
    max_results: int = Field(default=50, ge=1, le=100, description="Number of results to return (default: 50, max 100)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
) -> ToolResponse:
    """
    List the test data files of a scope.

    Args:
        environment: Environment ID, name, or 'Globals' (default: 'Globals')
        include_globals: With an environment, also return the global files
        category: Exact category filter (optional)
        file_name: Exact file name filter (optional)
        team_id: Team identifier (required)
        project_id: Project identifier (required)
        start_at: Pagination offset (default: 0)
        max_results: Page size (default: 50, max 100)

    Returns:
        dict: {
            'status': 'OK', 'total', 'count', 'offset', 'has_more', 'next_offset',
            'scope': str,
            'items': [{
                'proj_test_data_file_id': int, 'file_name': str, 'category': str,
                'description': str, 'file_type': str, 'file_size': str (KB),
                'json_file_path': str (download URL), 'is_global': 0|1,
                'environment_name': str | None, 'creator_name': str, 'created_date': str, ...
            }],
            'categories': [{'categoryName', 'categoryDescription', 'is_default'}]
        } OR a failure envelope.

    Examples:
        list_test_data_files(environment="Staging", category="App Build", team_id=7, project_id=70)
    """
    context = await _test_data_context(team_id, project_id, 'bugasura_list_test_data_files',
                                       f', environment="{environment}"')
    if context.get('status') != 'OK':
        return respond(context, response_format)

    environment_row, error = await _resolve_environment(context, environment)
    if error:
        return respond(error, response_format)
    files, custom_categories, error = await _fetch_files(context, environment_row, include_globals, category, file_name)
    if error:
        return respond(error, response_format)
    # Upstream returns the whole list; page it here
    return respond(paginate_upstream({'status': 'OK', 'scope': _scope_label(environment_row), 'files': files,
                                      'categories': _all_categories(custom_categories)},
                                     items_key='files', offset=start_at, max_results=max_results, local=True),
                   response_format)


@mcp.tool(
    name = "bugasura_get_test_data_file",
    title = "Get Test Data File",
    description = "Get one test data file (by ID or file name) from an environment or the 'Globals' scope: its details, a direct download link (no login needed) and, for Office files, a browser preview link. Pass include_content=true to also read a text file (csv, json, txt, md, xml, yaml, log, sql, html) inline.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def get_test_data_file(
    team_id: IdOrName = Field(description="Team id or name (required)"),
    project_id: int = Field(description="Project identifier (required)", ge=1),
    file: str = Field(description="File: numeric ID or file name (e.g. 'users.csv')", min_length=1),
    environment: str = Field(default=TEST_DATA_GLOBALS_SCOPE, description=_ENVIRONMENT_FIELD, min_length=1),
    category: Optional[str] = Field(default=None, description="Category of the file, to tell apart files with the same name (optional)"),
    include_content: bool = Field(default=False, description="Also return the file's text content (text file types only, first 1MB) (default: False)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
) -> ToolResponse:
    """
    Get a test data file's details and links, optionally with its text content.

    Test data files are public CDN objects, so the download link opens the file
    directly. Office files also get a preview link through Microsoft's viewer, as in
    the web app.

    Args:
        file: File ID or file name (required)
        environment: Environment ID, name, or 'Globals' the file belongs to (default: 'Globals')
        category: Category, to disambiguate files with the same name (optional)
        include_content: Return the text content of a text file (first 1MB)
        team_id: Team identifier (required)
        project_id: Project identifier (required)

    Returns:
        dict: {
            'status': 'OK',
            'file': {'proj_test_data_file_id', 'file_name', 'category', 'description',
                     'file_type', 'file_size' (KB), 'creator_name', 'created_date', ...},
            'scope': str,
            'download_url': str,             # direct, no login needed
            'preview_url': str,              # Office files only
            'content': str,                  # include_content=true, text files only
            'content_truncated': bool
        } OR a failure envelope.

    Examples:
        get_test_data_file(file="users.csv", environment="Staging", include_content=True,
                           team_id=7, project_id=70)
    """
    context = await _test_data_context(team_id, project_id, 'bugasura_get_test_data_file',
                                       f', file="{file}", environment="{environment}"')
    if context.get('status') != 'OK':
        return respond(context, response_format)

    environment_row, existing, error = await _resolve_file(context, environment, file, category)
    if error:
        return respond(error, response_format)

    response = {'status': 'OK', 'file': existing, 'scope': _scope_label(environment_row), **_file_links(existing)}
    if include_content:
        file_type = str(existing.get('file_type') or '').lower()
        if file_type not in TEST_DATA_TEXT_EXTS:
            response['content_note'] = (f"'.{file_type}' files are not text, so their content is not returned. "
                                        f"Use download_url to open the file.")
        elif not response['download_url']:
            response['content_note'] = 'The file has no download link, so its content could not be read.'
        else:
            try:
                content, truncated = await asyncio.to_thread(
                    fetch_url_bytes, response['download_url'], TEST_DATA_MAX_INLINE_CONTENT_BYTES)
            except Exception as e:
                logger.error(f"get_test_data_file: Could not read '{response['download_url']}': {e}")
                return respond(_failure_envelope('Could not read the file', f"The file could not be fetched: {e}. "
                                     f"Its download link is {response['download_url']}", 'IOError',
                                     download_url=response['download_url']), response_format)
            response['content'] = content.decode('utf-8', errors='replace')
            response['content_truncated'] = truncated
    return respond(response, response_format)


@mcp.tool(
    name = "bugasura_download_test_data_file",
    title = "Download Test Data File",
    description = "Get a test data file (by ID or file name) as a file the user can open. Returns download_url, a direct link that opens in a browser with no login; give that link to the user when they just want the file. Additionally pass save_to_path (an absolute path or directory on the machine running this server) to write the file to disk as well - useful in the terminal, where that machine is the user's own.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def download_test_data_file(
    team_id: IdOrName = Field(description="Team id or name (required)"),
    project_id: int = Field(description="Project identifier (required)", ge=1),
    file: str = Field(description="File to download: numeric ID or file name (e.g. 'users.csv')", min_length=1),
    environment: str = Field(default=TEST_DATA_GLOBALS_SCOPE, description=_ENVIRONMENT_FIELD, min_length=1),
    category: Optional[str] = Field(default=None, description="Category of the file, to tell apart files with the same name (optional)"),
    save_to_path: Optional[str] = Field(default=None, description="Absolute path on the MCP server's local filesystem to write the file to - a directory (the file's own name is used) or a full file path. Omit to just get the download link. Local STDIO servers only; rejected on the hosted server."),
    overwrite: bool = Field(default=False, description="Set True to replace the file at save_to_path when one is already there (default: False)"),
) -> ToolResponse:
    """
    Get a download link for a test data file, and optionally save it locally.

    Args:
        file: File ID or file name (required)
        environment: Environment ID, name, or 'Globals' the file belongs to (default: 'Globals')
        category: Category, to disambiguate files with the same name (optional)
        save_to_path: Local directory or file path to write the file to (optional, STDIO only)
        overwrite: Allow replacing an existing file at save_to_path
        team_id: Team identifier (required)
        project_id: Project identifier (required)

    Returns:
        dict: {
            'status': 'OK',
            'file_name': str, 'category': str, 'file_size': str (KB), 'scope': str,
            'download_url': str,         # direct, no login needed
            'preview_url': str,          # Office files only
            'saved_to': str | None,      # local path, when save_to_path was used
            'saved_bytes': int | None,
            'message': str,
            'next_step': str
        } OR a failure envelope.

    Examples:
        # Just the link
        download_test_data_file(file="users.csv", environment="Staging", team_id=7, project_id=70)

        # Save it locally as well
        download_test_data_file(file="app-release.apk", environment="Production", save_to_path="/home/me/builds/",
                                team_id=7, project_id=70)
    """
    context = await _test_data_context(team_id, project_id, 'bugasura_download_test_data_file',
                                       f', file="{file}", environment="{environment}"')
    if context.get('status') != 'OK':
        return context

    environment_row, existing, error = await _resolve_file(context, environment, file, category)
    if error:
        return error
    links = _file_links(existing)
    download_url = links['download_url']
    if not download_url:
        return _failure_envelope('Download link unavailable', f"'{existing.get('file_name')}' has no stored file URL.",
                     'DownloadUrlUnavailable')

    response = {
        'status': 'OK',
        'file_name': existing.get('file_name'),
        'category': existing.get('category'),
        'file_size': existing.get('file_size'),
        'scope': _scope_label(environment_row),
        **links,
        'saved_to': None,
        'saved_bytes': None,
    }

    if save_to_path and save_to_path.strip():
        if rejected := local_path_rejected('save_to_path'):
            return {**rejected, 'download_url': download_url,
                    'message': ("save_to_path refers to the server's own filesystem, which a hosted "
                                "server does not expose. Give the user download_url instead.")}
        # A folder means "put it here under its own name"; anything else is the file path
        try:
            destination, new_folder = resolve_save_destination(
                save_to_path, os.path.basename(existing.get('file_name') or 'test-data-file'))
        except ValueError:
            return _failure_envelope('save_to_path must be absolute',
                         f"'{save_to_path}' is not an absolute path. Ask the user for the full path of the folder "
                         f"or file, or hand them the download link instead: {download_url}",
                         download_url=download_url)
        parent_dir = os.path.dirname(destination) or '.'
        if not new_folder and not os.path.isdir(parent_dir):
            return _failure_envelope(f'Directory not found: {parent_dir}',
                         f"Cannot save to '{destination}' - the folder '{parent_dir}' does not exist. Ask the "
                         f"user for a folder that does, or hand them the download link instead: {download_url}",
                         download_url=download_url)
        if os.path.exists(destination) and not overwrite:
            return _failure_envelope('File already exists',
                         f"There is already a file at '{destination}'. Tell the user, and call this tool again "
                         f"with overwrite=True to replace it or with a different save_to_path. The download "
                         f"link works either way: {download_url}", 'FileExists',
                         download_url=download_url, save_to_path=destination)

        created_top = None
        if new_folder:
            try:
                created_top = create_folder(new_folder)
            except OSError as e:
                logger.error(f"download_test_data_file: Could not create '{new_folder}': {e}")
                return _failure_envelope(f'Could not create the folder: {new_folder}',
                             f"Cannot create the folder '{new_folder}'. Ask the user for a folder that exists, or "
                             f"hand them the download link instead: {download_url}", 'IOError',
                             download_url=download_url)

        logger.info(f"download_test_data_file: Saving file id={existing['proj_test_data_file_id']} to '{destination}'")
        try:
            response['saved_bytes'] = await asyncio.to_thread(download_url_to_path, download_url, destination)
            response['saved_to'] = destination
        except Exception as e:
            logger.error(f"download_test_data_file: Download failed from '{download_url}': {e}")
            if new_folder:
                remove_created_folder(new_folder, created_top)
            return _failure_envelope('Could not download the file',
                         f"The download link could not be fetched: {e}. Hand the user the link so they can "
                         f"download it in their browser: {download_url}", 'IOError', download_url=download_url)

    if response['saved_to']:
        response['message'] = (f"Saved '{response['file_name']}' to {response['saved_to']} "
                               f"({response['saved_bytes']} bytes). It can also be downloaded from {download_url}")
        response['next_step'] = ("Tell the user where the file was saved. Share download_url too "
                                 "if they would rather open it in their browser.")
    else:
        response['message'] = (f"'{response['file_name']}' can be downloaded from {download_url} - "
                               f"the link opens the file directly, no login needed.")
        response['next_step'] = ("Give the user download_url. If they wanted the file on this machine "
                                 "instead, ask where to put it and call this tool again with save_to_path.")
    return response


@mcp.tool(
    name = "bugasura_list_test_data_app_builds",
    title = "List Test Data App Builds",
    description = "List every app build (files in the 'App Build' category: apk, aab, ipa, ...) across all of a project's environments and the 'Globals' scope - the builds a test run can be pointed at.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def list_test_data_app_builds(
    team_id: IdOrName = Field(description="Team id or name (required)"),
    project_id: int = Field(description="Project identifier (required)", ge=1),
    start_at: int = Field(default=0, ge=0, description="Pagination offset (default: 0)"),
    max_results: int = Field(default=50, ge=1, le=100, description="Number of results to return (default: 50, max 100)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
) -> ToolResponse:
    """
    List the app builds of a project across all scopes.

    Args:
        team_id: Team identifier (required)
        project_id: Project identifier (required)
        start_at: Pagination offset (default: 0)
        max_results: Page size (default: 50, max 100)

    Returns:
        dict: {
            'status': 'OK', 'total', 'count', 'offset', 'has_more', 'next_offset',
            'items': [{'proj_test_data_file_id': int, 'file_name': str,
                       'proj_test_data_env_id': int | None, 'is_global': 0|1,
                       'environment_name': str}]
        } OR a failure envelope.

    Examples:
        list_test_data_app_builds(team_id=7, project_id=70)
    """
    context = await _test_data_context(team_id, project_id, 'bugasura_list_test_data_app_builds')
    if context.get('status') != 'OK':
        return respond(context, response_format)

    resp = await make_api_request('GET', '/v1/projectTestDataFiles/get', context['api_key'], params={
        'appId': str(context['project_id']),
        'teamId': str(context['team_id']),
        'isGetAppBuildsList': 1,
        # The flag only slims the rows; the category does the filtering (as the environment endpoint does)
        'category': TEST_DATA_APP_BUILD_CATEGORY,
    })
    if resp.get('status') != 'OK':
        return respond(resp, response_format)
    builds = _clean_rows(resp.get('testDataFileDetails'))

    # The slim build rows carry only the environment id; name them for the caller
    environments, error = await _fetch_environments(context)
    if error:
        return respond(error, response_format)
    names = {str(e['proj_test_data_env_id']): e['environment_name'] for e in environments}
    for build in builds:
        build['environment_name'] = (TEST_DATA_GLOBALS_SCOPE if build.get('is_global')
                                     else names.get(str(build.get('proj_test_data_env_id')), ''))
    # Upstream returns the whole list; page it here
    return respond(paginate_upstream({'status': 'OK', 'app_builds': builds}, items_key='app_builds',
                                     offset=start_at, max_results=max_results, local=True), response_format)


@mcp.tool(
    name = "bugasura_upload_test_data_files",
    title = "Upload Test Data Files",
    description = (
        "Upload one or more files (csv, json, images, documents, app builds ...) to an environment or to the "
        "'Globals' scope of a project's test data, filed under a category (e.g. 'Sample Data Files', 'App Build'). "
        "THREE WAYS TO PROVIDE THE FILE - pick ONE per call: "
        "(1) upload_id - from bugasura_create_upload_link(purpose='test_data'), after the user uploaded the file to "
        "that link (the normal way on the hosted server, for a file on the user's own computer, up to 100MB). "
        "(2) source_url - the Google Drive / Dropbox / public download link the user shared; the server fetches "
        "the file itself. "
        "(3) file_paths - absolute paths on the machine running this server (local STDIO servers only)."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def upload_test_data_files(
    team_id: IdOrName = Field(description="Team id or name (required)"),
    project_id: int = Field(description="Project identifier (required)", ge=1),
    category: str = Field(description="Category for the files: a built-in one ('App Build', 'Attachments & Documents', 'Product Images', 'Sample Data Files') or a custom one from bugasura_list_test_data_categories", min_length=1),
    environment: str = Field(description=_ENVIRONMENT_SCOPE_FIELD, min_length=1),
    upload_id: Optional[str] = Field(default=None, description="upload_id returned by bugasura_create_upload_link(purpose='test_data'), once the user has uploaded the file(s) to its link. Every file uploaded there is added."),
    file_paths: List[str] = Field(default=[], description="Absolute paths on the MCP server's local filesystem (local STDIO servers only; rejected on the hosted server), exactly as the user gave them.", max_length=TEST_DATA_MAX_FILES_PER_UPLOAD),
    source_url: Optional[str] = Field(default=None, description="Google Drive share link, Dropbox share link, or any public direct download URL. The MCP server fetches the file - no encoding needed. A Google Drive link must be set to 'Anyone with the link'."),
    source_url_filename: Optional[str] = Field(default=None, description="Original filename with extension (e.g. 'users.csv'). Optional - inferred from the URL or the download's headers; pass it only if auto-detection fails or the user names the file."),
    description: str = Field(default="", description="What the files are for (0-500 characters, applied to every file, optional)", max_length=TEST_DATA_DESCRIPTION_MAX_LENGTH),
) -> ToolResponse:
    """
    Upload test data files to an environment or the Globals scope.

    The files are sent to /v1/projectTestDataFiles/add as multipart `testData[]` parts, with
    a matching `categoryDetails` list; the API stores them on the CDN. The user's own files
    are only read, never moved or deleted.

    File types follow the web app: 'App Build' takes apk, aab, ipa, apks, apkm, xapk; other
    categories take documents, spreadsheets, csv/json/xml/yaml, images, audio/video and app
    builds. Files can be up to 1024MB. A file with the same name and category cannot be
    uploaded twice to one scope.

    Args:
        category: Category name, built-in or custom (required)
        upload_id: Files staged through an upload link (one of upload_id, source_url, file_paths is required)
        file_paths: Absolute local paths to upload (STDIO only)
        source_url: Public/share link the server downloads the file from
        source_url_filename: Original filename for source_url when it cannot be detected
        description: Description for the uploaded files (optional)
        environment: Environment ID, name, or 'Globals' (required)
        team_id: Team identifier (required)
        project_id: Project identifier (required)

    Returns:
        dict: {
            'status': 'OK',
            'message': str,
            'testDataFilesDetails': [{'test_data_file_id', 'file_name', 'category', 'file_size',
                                      'file_path', ...}],
            'uploaded_files': [str],
            'category': str,
            'scope': str,
            'next_step': str
        } OR a failure envelope.

    Examples:
        # A local CSV into Staging
        upload_test_data_files(category="Sample Data Files", file_paths=["/home/me/users.csv"],
                               environment="Staging", team_id=7, project_id=70)

        # From an upload link the user has used
        upload_test_data_files(category="Sample Data Files", upload_id="Qm9...", environment="Staging",
                               team_id=7, project_id=70)

        # An app build from a share link into Globals
        upload_test_data_files(category="App Build", source_url="https://drive.google.com/file/d/abc/view",
                               environment="Globals", team_id=7, project_id=70)
    """
    context = await _test_data_context(team_id, project_id, 'bugasura_upload_test_data_files',
                                       f', category="{category}", environment="{environment}"')
    if context.get('status') != 'OK':
        return context

    if file_paths and (rejected := local_path_rejected('file_paths')):
        return rejected
    content_sources = sum(bool(source) for source in (upload_id, file_paths, source_url))
    if not content_sources:
        if in_http_request():
            how = ("Call bugasura_create_upload_link(purpose='test_data') and give the user the upload link, then "
                   "call this tool again with its upload_id. A Google Drive or Dropbox link (\"Anyone with the "
                   "link\") passed as source_url also works.")
        else:
            how = ("Ask for the exact absolute file path and pass file_paths=[...], or for a Google Drive or "
                   "Dropbox link (\"Anyone with the link\") to pass as source_url.")
        return _failure_envelope('No file provided',
                     f'Ask the user how they want to provide the file. {how} Never read or encode the file yourself.')
    if content_sources > 1:
        return _failure_envelope('Multiple content sources provided',
                                 'Provide only one of upload_id, source_url or file_paths per call.')
    if upload_id:
        staged = staged_paths(upload_id, current_user_id(), 'test_data')
        if staged.get('status') != 'OK':
            return staged
        file_paths = staged['paths']
    description = description.strip()
    error = _length_error('Description', description, TEST_DATA_DESCRIPTION_MAX_LENGTH, required=False)
    if error:
        return error

    environment_row, error = await _resolve_environment(context, environment, exact=True)
    if error:
        return error
    # Only the web app's categories; the current files tell a timed-out upload's new rows apart
    existing_files, custom_categories, error = await _fetch_files(context, environment_row)
    if error:
        return error
    categories = _all_categories(custom_categories)
    match = next((c for c in categories if str(c.get('categoryName', '')).lower() == category.strip().lower()), None)
    if not match:
        return _failure_envelope(f"Unknown category: '{category}'",
                     f"'{category}' is not a test data category of this project. Pick one of: "
                     f"{', '.join(c['categoryName'] for c in categories)} - or create it first with "
                     f"bugasura_create_test_data_category.", 'NotFound',
                     available=[c['categoryName'] for c in categories])
    category = match['categoryName']

    allowed = TEST_DATA_APP_BUILD_EXTS if category == TEST_DATA_APP_BUILD_CATEGORY else TEST_DATA_FILE_EXTS
    max_bytes = TEST_DATA_MAX_FILE_SIZE_MB * 1024 * 1024
    sources = []  # (path, display name)
    tmp_path = None  # the source_url download, removed in the finally
    try:
        if source_url:
            download_url = normalise_share_url(source_url)
            name = (os.path.basename(source_url_filename) if source_url_filename
                    else infer_filename_from_url_path(download_url) or infer_filename_from_url_path(source_url))
            ext = os.path.splitext(name or '')[1].lstrip('.').lower()
            if name and ext not in allowed:
                return _unsupported_file_error(name, ext, category)
            try:
                # A blocking download of up to 1024MB: keep it off the event loop
                tmp_path, header_name = await asyncio.to_thread(
                    download_url_tmp, download_url, f'.{ext}' if ext else '.tmp', max_bytes=max_bytes)
            except Exception as e:
                logger.error(f"upload_test_data_files: Download failed for '{source_url}': {e}")
                return _failure_envelope('Failed to download file from source_url',
                             f"Could not download '{source_url}': {e}. Make sure the link is set to "
                             f"'Anyone with the link' (not restricted to signed-in users).", 'IOError')
            if not name:
                if not header_name:
                    return _failure_envelope('Could not determine filename from URL or response headers',
                                 "Could not auto-detect the filename. Pass source_url_filename with the "
                                 "original filename and extension (e.g. 'users.csv').")
                name = os.path.basename(header_name)
                ext = os.path.splitext(name)[1].lstrip('.').lower()
                if ext not in allowed:
                    return _unsupported_file_error(name, ext, category)
            sources.append((tmp_path, name))
        else:
            for path in file_paths:
                if not os.path.isfile(path):
                    return _failure_envelope(f'File not found: {path}',
                                 f"Could not find a readable file at '{path}'. Ask the user for the exact "
                                 f"absolute path, or for a Google Drive/Dropbox link to use as source_url.")
                name = os.path.basename(path)
                ext = os.path.splitext(name)[1].lstrip('.').lower()
                if ext not in allowed:
                    return _unsupported_file_error(name, ext, category)
                sources.append((path, name))

        for path, name in sources:
            size = os.path.getsize(path)
            if size > max_bytes:
                return _failure_envelope('File too large',
                             f"'{name}' is {size / (1024 * 1024):.1f}MB. Test data files can be up to "
                             f"{TEST_DATA_MAX_FILE_SIZE_MB}MB.")
            if size == 0:
                return _failure_envelope('Empty file', f"'{name}' is empty, so there is nothing to upload.")
        filenames = [name for _, name in sources]
        if len(sources) > TEST_DATA_MAX_FILES_PER_UPLOAD:
            return _failure_envelope('Too many files',
                         f"{len(sources)} files were given; one upload takes up to {TEST_DATA_MAX_FILES_PER_UPLOAD}. "
                         f"Split them over several calls.")
        if sum(os.path.getsize(path) for path, _ in sources) > TEST_DATA_MAX_UPLOAD_TOTAL_MB * 1024 * 1024:
            return _failure_envelope('Upload too large',
                         f"Together the files exceed {TEST_DATA_MAX_UPLOAD_TOTAL_MB}MB, more than one upload can "
                         f"carry. Split them over several calls.")
        # Bugasura keeps one file per name and category in a scope, but does not check within one upload
        duplicates = sorted({n for n in filenames if [f.lower() for f in filenames].count(n.lower()) > 1})
        if duplicates:
            return _failure_envelope('Duplicate file names',
                         f"{', '.join(duplicates)} appears more than once in this upload. A scope keeps one file "
                         f"per name and category, so rename one of them or upload them separately.")

        payload = _scope_params(context, environment_row)
        payload.update({
            'isGlobal': '0' if environment_row else '1',
            'categoryDetails': json.dumps([{'category': category, 'description': description}] * len(sources)),
        })
        total_mb = sum(os.path.getsize(path) for path, _ in sources) / (1024 * 1024)
        timeout = min(TEST_DATA_UPLOAD_TIMEOUT_BASE_SECONDS + TEST_DATA_UPLOAD_TIMEOUT_SECONDS_PER_MB * total_mb,
                      TEST_DATA_UPLOAD_TIMEOUT_MAX_SECONDS)
        logger.info(f"upload_test_data_files: Uploading {len(sources)} file(s) ({total_mb:.1f}MB) to "
                    f"{_scope_label(environment_row)} ('{category}') for project_id={context['project_id']}, "
                    f"timeout {timeout:.0f}s")
        with contextlib.ExitStack() as stack:
            files = [('testData[]', (name, stack.enter_context(open(path, 'rb')),
                                     mimetypes.guess_type(name)[0] or 'application/octet-stream'))
                     for path, name in sources]
            result = await make_api_request('POST', '/v1/projectTestDataFiles/add', context['api_key'],
                                            data=payload, files=files,
                                            timeout=httpx.Timeout(timeout, connect=10.0))

        # A timeout usually means the API is still working: check for the files so a retry does not duplicate them
        if result.get('error_type') == 'Timeout':
            known_ids = {f.get('proj_test_data_file_id') for f in existing_files}
            found: list = []
            for attempt in range(TEST_DATA_UPLOAD_CONFIRM_ATTEMPTS):
                if attempt:
                    await asyncio.sleep(TEST_DATA_UPLOAD_CONFIRM_INTERVAL_SECONDS)
                rows, _, fetch_error = await _fetch_files(context, environment_row)
                if fetch_error:
                    continue
                new_rows = [r for r in rows if r.get('proj_test_data_file_id') not in known_ids
                            and bool(r.get('is_global')) == (environment_row is None)]
                found = []
                for name in filenames:
                    row = next((r for r in new_rows if r.get('file_name') == name and r not in found), None)
                    if row is None:
                        break
                    found.append(row)
                if len(found) == len(filenames):
                    break
            if len(found) == len(filenames):
                logger.info(f"upload_test_data_files: Add call timed out after {timeout:.0f}s but all "
                            f"{len(found)} file(s) appeared on check {attempt + 1}")
                result = {
                    'status': 'OK',
                    'message': 'Test data file uploaded successfully.',
                    'testDataFilesDetails': [
                        {'test_data_file_id': r.get('proj_test_data_file_id'), 'file_name': r.get('file_name'),
                         'file_size': r.get('file_size'), 'file_path': r.get('json_file_path'),
                         'category': r.get('category'), 'created_date': r.get('created_date')}
                        for r in found],
                    'warning': (f"The Bugasura API took longer than {timeout:.0f}s to answer, but the upload "
                                f"finished: the file(s) are in place."),
                }
            else:
                missing = [n for n in filenames if n not in {r.get('file_name') for r in found}]
                logger.warning(f"upload_test_data_files: Add call timed out after {timeout:.0f}s; not yet in "
                               f"{_scope_label(environment_row)}: {missing}")
                result = {
                    **result,
                    'error': 'Upload not confirmed',
                    'message': (f"Bugasura did not answer within {timeout:.0f}s and {', '.join(missing)} has not "
                                f"appeared in {_scope_label(environment_row)} yet. It may still be processing. Do "
                                f"not upload again straight away: list the files with bugasura_list_test_data_files "
                                f"first, so the upload is not duplicated."),
                }
    except OSError as e:
        logger.error(f"upload_test_data_files: Could not read the files to upload: {e}")
        return _failure_envelope('Could not read the files to upload',
                                 'The files could not be read. Check them and try again.', 'IOError')
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    if result.get('status') != 'OK':
        # Bugasura reports its own errors as status "ERROR"; every tool reports "failed"
        return {**result, 'status': 'failed'}
    if upload_id:
        discard(upload_id)
    result.update({'uploaded_files': filenames, 'category': category, 'scope': _scope_label(environment_row)})
    result['next_step'] = (f"Tell the user the file(s) are in the '{category}' category of "
                           f"{_scope_label(environment_row)}. List them with bugasura_list_test_data_files.")
    return result


@mcp.tool(
    name = "bugasura_delete_test_data_file",
    title = "Delete Test Data File",
    description = "Permanently delete one test data file (by ID or file name) from an environment or the 'Globals' scope. Cannot be undone.",
    annotations={"readOnlyHint": False, "destructiveHint": True,  "idempotentHint": True,  "openWorldHint": True}
)
async def delete_test_data_file(
    team_id: IdOrName = Field(description="Team id or name (required)"),
    project_id: int = Field(description="Project identifier (required)", ge=1),
    file: str = Field(description="File to delete: numeric ID or file name (e.g. 'users.csv')", min_length=1),
    environment: str = Field(description=_ENVIRONMENT_SCOPE_FIELD, min_length=1),
    category: Optional[str] = Field(default=None, description="Category of the file, to tell apart files with the same name (optional)"),
) -> ToolResponse:
    """
    Permanently delete a single test data file.

    Only the file's uploader, a team admin or a project admin may delete it. Exactly one
    file is deleted: the tool always resolves and sends its ID.

    Args:
        file: File ID or file name (required)
        environment: Environment ID, name, or 'Globals' the file belongs to (required)
        category: Category, to disambiguate files with the same name (optional)
        team_id: Team identifier (required)
        project_id: Project identifier (required)

    Returns:
        dict: {
            'status': 'OK',
            'message': 'Test data file(s) deleted successfully.',
            'deletedCount': int,
            'file_name': str,
            'category': str,
            'scope': str
        } OR a failure envelope.

    Examples:
        delete_test_data_file(file="users.csv", environment="Staging", team_id=7, project_id=70)
    """
    context = await _test_data_context(team_id, project_id, 'bugasura_delete_test_data_file',
                                       f', file="{file}", environment="{environment}"')
    if context.get('status') != 'OK':
        return context

    environment_row, existing, error = await _resolve_file(context, environment, file, category, exact=True)
    if error:
        return error

    # Always send the resolved testDataFileId: an environmentId alone deletes every file in it
    logger.info(f"delete_test_data_file: Deleting test data file '{existing.get('file_name')}' (id={existing['proj_test_data_file_id']}) "
                f"from {_scope_label(environment_row)} for project_id={context['project_id']}")
    result = await make_api_request('POST', '/v1/projectTestDataFiles/delete', context['api_key'], data={
        'appId': str(context['project_id']),
        'teamId': str(context['team_id']),
        'testDataFileId': str(existing['proj_test_data_file_id']),
    })
    if result.get('status') == 'OK':
        result.update({'file_name': existing.get('file_name'), 'category': existing.get('category'),
                       'scope': _scope_label(environment_row)})
    return result


@mcp.tool(
    name = "bugasura_list_test_data_categories",
    title = "List Test Data File Categories",
    description = "List the categories test data files can be filed under: the built-in ones (App Build, Attachments & Documents, Product Images, Sample Data Files) and the project's custom ones.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def list_test_data_categories(
    team_id: IdOrName = Field(description="Team id or name (required)"),
    project_id: int = Field(description="Project identifier (required)", ge=1),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
) -> ToolResponse:
    """
    List the test data file categories of a project.

    Args:
        team_id: Team identifier (required)
        project_id: Project identifier (required)

    Returns:
        dict: {
            'status': 'OK', 'total', 'count', 'offset', 'has_more', 'next_offset',
            'items': [{'categoryName': str, 'categoryDescription': str, 'is_default': bool}]
        } OR a failure envelope.

    Examples:
        list_test_data_categories(team_id=7, project_id=70)
    """
    context = await _test_data_context(team_id, project_id, 'bugasura_list_test_data_categories')
    if context.get('status') != 'OK':
        return respond(context, response_format)

    # The custom categories ride along with the file listing
    _, custom_categories, error = await _fetch_files(context, None)
    if error:
        return respond(error, response_format)
    return respond(paginate_upstream({'status': 'OK', 'categories': _all_categories(custom_categories)},
                                     items_key='categories', local=True), response_format)


@mcp.tool(
    name = "bugasura_create_test_data_category",
    title = "Create Test Data File Category",
    description = "Add a custom category for test data files in a project (e.g. 'Payment Fixtures'). Category names are unique per project, ignoring case.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def create_test_data_category(
    team_id: IdOrName = Field(description="Team id or name (required)"),
    project_id: int = Field(description="Project identifier (required)", ge=1),
    category_name: str = Field(description="Category name (1-250 characters, unique in the project ignoring case)", min_length=1, max_length=TEST_DATA_NAME_MAX_LENGTH),
    category_description: str = Field(description="What files in this category are for (1-250 characters, required)", min_length=1, max_length=TEST_DATA_CATEGORY_DESCRIPTION_MAX_LENGTH),
) -> ToolResponse:
    """
    Create a custom test data file category.

    Args:
        category_name: Category name (1-250 characters, unique ignoring case)
        category_description: Description (1-250 characters, required by the backend)
        team_id: Team identifier (required)
        project_id: Project identifier (required)

    Returns:
        dict: {
            'status': 'OK',
            'message': 'Test data file category added successfully.',
            'customCategory': {'categoryName': str, 'categoryDescription': str}
        } OR a failure envelope.

    Examples:
        create_test_data_category(category_name="Payment Fixtures",
                                  category_description="Card numbers and payment payloads",
                                  team_id=7, project_id=70)
    """
    context = await _test_data_context(team_id, project_id, 'bugasura_create_test_data_category',
                                       f', category_name="{category_name}"')
    if context.get('status') != 'OK':
        return context

    category_name = category_name.strip()
    category_description = category_description.strip()
    error = (_length_error('Category name', category_name, TEST_DATA_NAME_MAX_LENGTH)
             or _length_error('Category description', category_description, TEST_DATA_CATEGORY_DESCRIPTION_MAX_LENGTH))
    if error:
        return error
    # The backend only checks the custom list; the built-in names would show up twice
    if category_name.lower() in (c['categoryName'].lower() for c in TEST_DATA_DEFAULT_FILE_CATEGORIES):
        return _failure_envelope(f"Category already exists: '{category_name}'",
                     f"'{category_name}' is a built-in category and can be used as it is.")

    return await make_api_request('POST', '/v1/projectTestDataFiles/addCategory', context['api_key'], data={
        'appId': str(context['project_id']),
        'teamId': str(context['team_id']),
        'categoryName': category_name,
        'categoryDescription': category_description,
    })


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _failure_envelope(error: str, message: str, error_type: str = 'ValidationError', **extra) -> dict:
    """Build a failure envelope. `extra` carries the choices a caller needs to recover."""
    return {'status': 'failed', 'error': error, 'error_type': error_type,
            'message': message, **extra}


def _clean_rows(rows: Any) -> list:
    """Strip the backend's NROWS/STATUS bookkeeping from list rows and drop rows that held only that."""
    if not isinstance(rows, list):
        return []
    cleaned = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        row = {k: v for k, v in row.items() if k not in TEST_DATA_DB_META_KEYS}
        if row:
            cleaned.append(row)
    return cleaned


def _is_globals(environment: Any) -> bool:
    """True when the environment argument names the global scope (only "Globals" is reserved upstream)."""
    return environment is None or str(environment).strip().lower() == TEST_DATA_GLOBALS_SCOPE.lower()


def _length_error(field: str, value: str, max_length: int, required: bool = True) -> Optional[dict]:
    """Mirror the backend's string-length validation so the caller gets the reason up front."""
    if required and not value.strip():
        return _failure_envelope(f"{field} is required", f"{field} cannot be empty.")
    if len(value) > max_length:
        return _failure_envelope(f"{field} too long: {len(value)} characters",
                     f"{field} cannot be longer than {max_length} characters.")
    return None


def _variable_key_error(variable_key: str) -> Optional[dict]:
    """Validate a variable key: letters, digits, combining marks, underscores and dashes (backend regex)."""
    error = _length_error('Variable key', variable_key, TEST_DATA_NAME_MAX_LENGTH)
    if error:
        return error
    if not all(ch.isalnum() or ch in '_-' or unicodedata.category(ch).startswith('M')
               for ch in variable_key):
        return _failure_envelope(f"Invalid variable key: '{variable_key}'",
                     'Variable key must contain only letters, numbers, underscores, or dashes '
                     '(no spaces or other symbols), e.g. "loginEmail" or "api_token".')
    return None


def _scope_label(environment_row: Optional[dict]) -> str:
    """Display name of a resolved scope."""
    return environment_row['environment_name'] if environment_row else TEST_DATA_GLOBALS_SCOPE


def _scope_params(context: dict, environment_row: Optional[dict]) -> dict:
    """Project + team + scope fields shared by the variable and file endpoints."""
    params = {'appId': str(context['project_id']), 'teamId': str(context['team_id'])}
    if environment_row:
        params['environmentId'] = str(environment_row['proj_test_data_env_id'])
    return params


def _match(items: list, identifier: Any, id_key: str, name_key: str, label: str,
           allow_partial: bool = True):
    """
    Resolve identifier (numeric ID or name) against a pre-fetched list.

    Returns (row, error_dict). A numeric identifier must be an ID in the list (or, failing
    that, an exact name). Names match exact-case first, then case-insensitively, then
    (when allow_partial) as a substring. Not-found / ambiguous produce a standard error
    dict with the available options.
    """
    s = str(identifier).strip()
    if s.isdigit():
        by_id = [it for it in items if str(it.get(id_key)) == s]
        if by_id:
            return by_id[0], None

    matches = [it for it in items if str(it.get(name_key) or '').strip() == s]
    if not matches:
        matches = [it for it in items if str(it.get(name_key) or '').strip().lower() == s.lower()]
    if not matches and allow_partial:
        matches = [it for it in items if s.lower() in str(it.get(name_key) or '').strip().lower()]

    if not matches:
        available = ', '.join(str(it.get(name_key)) for it in items[:20]) or '(none)'
        return None, _failure_envelope(f"{label[0].upper()}{label[1:]} not found: '{s}'",
                           f"No {label} matches '{s}'. Available: {available}", 'NotFound')
    if len(matches) > 1:
        listing = '\n'.join(f"  - ID: {m.get(id_key)}, Name: {m.get(name_key)}" for m in matches)
        return None, _failure_envelope(f"Multiple {label}s match '{s}'",
                           f"Multiple {label}s match '{s}'. Use the numeric ID:\n{listing}", 'Ambiguous')
    return matches[0], None


async def _test_data_context(team_id: int, project_id: int, tool_name: str,
                             operation_params: str = "") -> dict:
    """
    Run the credential check and team/project validation every test data tool starts with.

    The test data endpoints take their team from the request (falling back to the user's
    first team), so the project's own team is looked up and sent as teamId.

    Returns:
        dict: {'status': 'OK', 'api_key': str, 'team_id': int, 'project_id': int}, or the
        failure envelope to hand straight back to the caller.
    """
    api_key = get_api_key()
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id, tool_name, operation_params)
    # A resolved context carries the ids and no status; everything else is a prompt or a failure.
    if 'team_id' not in context or 'project_id' not in context:
        return context

    project = await make_api_request('GET', '/v1/projects/get', api_key, params={
        'team_id': context['team_id'],
        'project_id': context['project_id']
    })
    project_team_id = (project.get('project_details') or {}).get('team_id') if project.get('status') == 'OK' else None
    if project_team_id and str(project_team_id) != str(context['team_id']):
        logger.warning(f"{tool_name}: Team ID mismatch - context team_id={context['team_id']}, "
                       f"project team_id={project_team_id}. Using project's team_id.")
    return {'status': 'OK', 'api_key': api_key, 'team_id': project_team_id or context['team_id'],
            'project_id': context['project_id']}


async def _fetch_environments(context: dict, include_globals: bool = False):
    """Fetch the project's environments -> (rows, error). The global scope row is named 'Globals'."""
    params = {'appId': str(context['project_id']), 'teamId': str(context['team_id'])}
    if include_globals:
        params['fetchGlobalTestData'] = 1
    resp = await make_api_request('GET', '/v1/projectTestDataEnvironments/get', context['api_key'], params=params)
    if resp.get('status') != 'OK':
        return None, resp
    rows = _clean_rows(resp.get('environmentDetails'))
    for row in rows:
        if row.get('is_global'):
            row['environment_name'] = TEST_DATA_GLOBALS_SCOPE
    return rows, None


async def _resolve_environment(context: dict, environment: Any, exact: bool = False):
    """
    Resolve an environment identifier -> (environment_row, error).

    environment_row is None for the global scope. Writes and deletes pass exact=True, so a
    partial name never lands them on a different environment.
    """
    if _is_globals(environment):
        return None, None
    if not str(environment).strip():
        return None, _failure_envelope('Environment is required',
                                       f"Name the environment, or '{TEST_DATA_GLOBALS_SCOPE}' for the global scope.")
    environments, error = await _fetch_environments(context)
    if error:
        return None, error
    return _match(environments, environment, 'proj_test_data_env_id', 'environment_name', 'environment',
                  allow_partial=not exact)


async def _fetch_variables(context: dict, environment_row: Optional[dict], include_globals: bool = False,
                           variable_key: Optional[str] = None):
    """Fetch the variables of one scope (optionally with the globals) -> (rows, error)."""
    params = _scope_params(context, environment_row)
    if environment_row is None or include_globals:
        params['isGetGlobalTestData'] = 1
    if variable_key:
        params['variableKey'] = variable_key
    resp = await make_api_request('GET', '/v1/projectTestData/get', context['api_key'], params=params)
    if resp.get('status') != 'OK':
        return None, resp
    return _clean_rows(resp.get('testDataDetails')), None


async def _fetch_files(context: dict, environment_row: Optional[dict], include_globals: bool = False,
                       category: Optional[str] = None, file_name: Optional[str] = None):
    """Fetch the files of one scope (optionally with the globals) -> (rows, custom_categories, error)."""
    params = _scope_params(context, environment_row)
    if environment_row is None or include_globals:
        params['isGetGlobalTestData'] = 1
    if category:
        params['category'] = category
    if file_name:
        params['fileName'] = file_name
    resp = await make_api_request('GET', '/v1/projectTestDataFiles/get', context['api_key'], params=params)
    if resp.get('status') != 'OK':
        return None, None, resp
    # The custom categories come as a JSON string
    categories = resp.get('customTestDataCategory')
    if categories and not isinstance(categories, list):
        try:
            categories = json.loads(categories)
        except (TypeError, ValueError):
            logger.warning(f"_fetch_files: Could not parse customTestDataCategory: {str(categories)[:200]}")
            categories = []
    return _clean_rows(resp.get('testDataFileDetails')), categories if isinstance(categories, list) else [], None


async def _resolve_file(context: dict, environment: Any, file: Any, category: Optional[str], exact: bool = False):
    """Resolve a file identifier within one scope -> (environment_row, file_row, error).

    exact=True (deletes) matches the ID or the whole file name only, never part of one.
    """
    environment_row, error = await _resolve_environment(context, environment, exact)
    if error:
        return None, None, error
    files, _, error = await _fetch_files(context, environment_row, category=category)
    if error:
        return None, None, error
    # Keep to the requested scope so a same-named file elsewhere is never picked
    files = [f for f in files if bool(f.get('is_global')) == (environment_row is None)]
    existing, error = _match(files, file, 'proj_test_data_file_id', 'file_name',
                             f"file in {_scope_label(environment_row)}", allow_partial=not exact)
    return environment_row, existing, error


def _file_links(row: dict) -> dict:
    """Download link (public CDN object) and, for Office files, a browser preview link."""
    download_url = row.get('json_file_path') or ''
    links = {'download_url': download_url}
    if download_url and str(row.get('file_type') or '').lower() in TEST_DATA_OFFICE_VIEWER_EXTS:
        links['preview_url'] = TEST_DATA_OFFICE_VIEWER_URL + download_url
    return links


def _unsupported_file_error(filename: str, ext: str, category: str) -> dict:
    """Failure envelope for a file type the category does not accept."""
    allowed = TEST_DATA_APP_BUILD_EXTS if category == TEST_DATA_APP_BUILD_CATEGORY else TEST_DATA_FILE_EXTS
    return _failure_envelope(f"Unsupported file type: '.{ext}'" if ext else f"File has no extension: '{filename}'",
                 f"'{filename}' cannot be uploaded to the '{category}' category. "
                 f"Allowed types: {', '.join(sorted(allowed))}.")


def _all_categories(custom_categories: list) -> list:
    """Built-in categories followed by the project's custom ones, each flagged with is_default."""
    return ([{**c, 'is_default': True} for c in TEST_DATA_DEFAULT_FILE_CATEGORIES]
            + [{**c, 'is_default': False} for c in custom_categories if isinstance(c, dict)])
