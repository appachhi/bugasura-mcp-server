"""Bugasura MCP tools: test_cases."""
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
    name = "bugasura_list_test_cases",
    description = (
        "List test cases for a project with pagination. When sprint_id is provided, returns full test "
        "case details for that sprint (grouped by sub-feature): scenario, steps, severity, priority, "
        "conditions, test data, and execution status. "
        "Add test_run_execution_run_id to scope to a specific run — at run level, pass_count and "
        "fail_count per test case are also included (scoped to that run only). "
        "Without sprint_id, returns all project-level test cases as brief summaries. "
        "IMPORTANT: always display scenario text exactly as returned — never shorten, rephrase, or summarize it. "
        "Show test_case_number (e.g. TES123, formed from project prefix + id) as the test case identifier, not the raw numeric test_case_id. "
        "Interactive team/project selection available."
    ),
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def list_test_cases(
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    sprint_id: Optional[int] = Field(default=None, description="Sprint ID (report_id). When provided, returns full test case details for that sprint, grouped by sub-feature."),
    test_run_execution_run_id: Optional[int] = Field(default=None, description="Test run execution ID (testRunsExecutionRunId). When provided alongside sprint_id, filters test cases to that specific run. Obtain from bugasura_list_test_runs."),
    sub_feature_name: Optional[str] = Field(default=None, description="Filter sprint test cases by sub-feature name (case-insensitive substring). Only used with sprint_id."),
    start_at: int = Field(default=0, description="Pagination offset (default: 0, ge=0)"),
    max_results: int = Field(default=20, description="Number of results to return (default: 20, ge=1, le=100)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment."),
    ctx: Optional[Context] = None,
) -> ToolResponse:
    """List test cases. With sprint_id: fetches via /testpert/sprintTestCase/get (full details,
    grouped by sub-feature, includes pass_count/fail_count).
    Add test_run_execution_run_id to scope to a specific run within the sprint.
    Without sprint_id: fetches all project test cases via /v1/testcases/list (summaries).
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return _respond(validation, response_format)

    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_list_test_cases')
    if 'status' in context and context['status'] == 'selection_required':
        return _respond(context, response_format)

    tid, pid = context['team_id'], context['project_id']

    # --- Sprint-scoped path: full details via testpert endpoint ---
    if sprint_id:
        if ctx is not None:
            await ctx.report_progress(0.3, total=1.0, message=f"Fetching sprint {sprint_id} test cases")
        params = {'teamId': tid, 'appId': pid, 'sprintId': sprint_id}
        if test_run_execution_run_id:
            params['testRunsExecutionRunId'] = test_run_execution_run_id
        resp = await make_api_request('GET', '/testpert/sprintTestCase/get', api_key, params=params)
        if not (isinstance(resp, dict) and resp.get('status') == 'OK'):
            return _respond({
                'status': 'failed',
                'error': 'Could not fetch sprint test cases',
                'message': (resp.get('message') if isinstance(resp, dict) else None)
                           or 'Failed to fetch test cases. Ensure the sprint has reached TEST_CASES.',
            }, response_format)

        all_cases = resp.get('testCaseDetails') or []

        # Optional sub-feature filter.
        if sub_feature_name:
            needle = sub_feature_name.lower()
            all_cases = [
                tc for tc in all_cases
                if needle in str(tc.get('sub_feature_name') or '').lower()
                or needle in str(tc.get('feature_name') or '').lower()
            ]

        total = len(all_cases)
        page = all_cases[start_at: start_at + max_results]

        # Group by sub_feature_name (fall back to feature_name).
        groups: dict = {}
        for tc in page:
            group_key = str(tc.get('sub_feature_name') or tc.get('feature_name') or 'Uncategorised')
            if group_key not in groups:
                groups[group_key] = []
            steps_raw = tc.get('test_steps') or []
            if isinstance(steps_raw, str):
                try:
                    steps_raw = json.loads(steps_raw)
                except Exception:
                    steps_raw = [{'action': steps_raw}]
            entry = {
                'test_case_number': tc.get('test_case_number'),
                'test_case_id': tc.get('test_case_id'),
                'scenario': tc.get('scenario'),
                'severity': tc.get('severity'),
                'priority': tc.get('priority'),
                'testing_type': tc.get('testing_type'),
                'platform': tc.get('platform_type'),
                'test_conditions': tc.get('test_conditions') or '',
                'test_idea': tc.get('test_idea') or '',
                'test_data': tc.get('test_data') or '',
                'steps': [s.get('action') for s in steps_raw if isinstance(s, dict) and s.get('action')],
                'acceptance_criteria': tc.get('acceptance_criteria') or '',
                'execution_status': tc.get('execution_status') or '',
            }
            # pass/fail counts are only scoped correctly at run level; at sprint level the
            # backend join has no execution_run_id filter and aggregates across all runs.
            if test_run_execution_run_id:
                entry['pass_count'] = tc.get('total_pass_count') or 0
                entry['fail_count'] = tc.get('total_fail_count') or 0
            groups[group_key].append(entry)

        result = {
            'status': 'OK',
            'sprint_id': sprint_id,
            'total': total,
            'offset': start_at,
            'returned': len(page),
            'by_sub_feature': groups,
        }
        if test_run_execution_run_id:
            result['test_run_execution_run_id'] = test_run_execution_run_id
        if total > start_at + max_results:
            result['next_offset'] = start_at + max_results
            result['message'] = (f"Showing {start_at + 1}–{start_at + len(page)} of {total}. "
                                 f"Call again with start_at={start_at + max_results} for the next page.")
        else:
            result['message'] = f"Showing all {len(page)} of {total} test cases for sprint {sprint_id}."
        return _respond(result, response_format)

    # --- Project-wide path: all test cases (summaries, server-side pagination) ---
    if ctx is not None:
        await ctx.report_progress(0.5, total=1.0, message=f"Fetching test cases for project {pid}")
    response = await make_api_request('GET', '/v1/testcases/list', api_key, params={
        'team_id': tid,
        'app_id': pid,
        'start_at': start_at,
        'max_results': max_results,
    })
    response = filter_large_fields(response)
    return _respond(_paginate_upstream(response, offset=start_at), response_format)


@mcp.tool(
    name = "bugasura_create_test_case",
    description = "Create a new test case with required scenario. Supports feature tags, testing type, severity, priority, conditions, test data, assignees, and folder organization. Interactive team/project selection available.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def create_test_case(
    scenario: str = Field(description="Test case scenario/title (required, min_length=1)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    feature_name: str = Field(default="", description="Feature name/tag (optional)"),
    sub_feature_name: str = Field(default="", description="Sub-feature name/tag (optional)"),
    testing_type: str = Field(default="Functional", description="Testing type: 'Functional', 'Regression', 'Smoke', 'Integration', etc. (default: Functional)"),
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(default="MEDIUM", description="Severity: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW' (default: MEDIUM)"),
    priority: Literal["P0", "P1", "P2", "P3", "P4"] = Field(default="P2", description="Priority: 'P0', 'P1', 'P2', 'P3', 'P4' (default: P2)"),
    test_conditions: str = Field(default="", description="Pre-conditions and test setup (optional)"),
    test_idea: str = Field(default="", description="Test idea or objective (optional)"),
    test_data: str = Field(default="", description="Test data required (optional)"),
    acceptance_criteria: str = Field(default="", description="Acceptance criteria or expected results (optional)"),
    assignees: Optional[str] = Field(default=None, description="Comma-separated assignee names, emails, or IDs (optional)"),
    is_api_test_case: bool = Field(default=False, description="Flag for API test cases (default: False)"),
    folder_id: Optional[int] = Field(default=None, description="Folder ID for organization (optional, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_create_test_case', f', scenario="{scenario}"')

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
        resolution_result = await _find_user_ids_by_names_or_emails(api_key, team_id, assignees)
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
    return await make_api_request('POST', '/v1/testcases/add', api_key, data=payload)


@mcp.tool(
    name = "bugasura_get_test_case",
    description = "Get detailed test case information by numeric ID. Returns full test case details including steps and execution history. Interactive team/project selection available.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def get_test_case(
    testcase_id: int = Field(description="Test case numeric ID", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (optional, ge=1)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return _respond(validation, response_format)

    # Use centralized context selection helper
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_get_test_case', f', testcase_id={testcase_id}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return _respond(context, response_format)

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

    response = await make_api_request('GET', '/v1/testcases/get', api_key, params=params)

    # Return full response for individual test case (including tools_integration_settings if needed)
    return _respond(response, response_format)


@mcp.tool(
    name = "bugasura_update_test_case",
    description = "Update test case details (partial updates supported). Can update any field including scenario, feature tags, testing type, severity, priority, conditions, assignees, status, and sprint associations. To assign a sprint-level test case to an agent for automated execution, set assign_to_agent=True along with sprint_id — functional test cases are routed to the Browser Agent, API test cases to the Testpert Agent (the backend decides based on is_api_test_case). Interactive selection available.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def update_test_case(
    testcase_id: int = Field(description="Test case numeric ID to update", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
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
    folder_id: Optional[int] = Field(default=None, description="New folder ID for organization (optional, ge=1)"),
    sprint_ids: Optional[str] = Field(default=None, description="New sprint associations, comma-separated sprint IDs (optional)"),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (report_id) for sprint-level operations such as agent assignment (optional, ge=1)"),
    test_run_execution_run_id: Optional[int] = Field(default=None, description="Test run execution ID (testRunsExecutionRunId). When provided with assign_to_agent=True, scopes the agent assignment to that specific test run execution."),
    assign_to_agent: bool = Field(default=False, description="When True (and sprint_id is provided), assigns this test case to an agent for automated execution within that sprint. Functional test cases go to the Browser Agent; API test cases go to the API Agent. The project must have the relevant agent enabled."),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
        sprint_id: Sprint identifier for agent assignment context (optional)
        assign_to_agent: True to assign this sprint test case to an agent (optional)

    Returns:
        dict: API response with update status. When assign_to_agent=True, also includes
              agent_assignment with the result of the agent assignment call.

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

        # Assign a sprint test case to an agent (functional → Browser Agent, API → Testpert Agent)
        update_test_case(api_key, team_id, project_id, testcase_id, sprint_id=42, assign_to_agent=True)
    """
    # Validate API key before proceeding
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    # Handle case where API might return a list instead of dict
    if isinstance(validation, list):
        return {'status': 'failed', 'error': 'Unexpected API response format', 'details': str(validation)}
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_update_test_case', f', testcase_id={testcase_id}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Step 1: Fetch existing test case details
    logger.info(f"Fetching existing test case details for testcase_id={testcase_id}")
    existing_tc_response = await make_api_request('GET', '/v1/testcases/get', api_key, params={
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

    # Start with all existing fields so a partial update never clears untouched data.
    tc_details = {
        'feature_name': tc_data.get('feature_name', ''),
        'sub_feature_name': tc_data.get('sub_feature_name', ''),
        'test_case_scenario': tc_data.get('test_case_scenario') or tc_data.get('scenario', ''),
        'testing_type': tc_data.get('testing_type', ''),
        'severity': tc_data.get('severity', 'MEDIUM'),
        'priority': tc_data.get('priority', 'P2'),
        'test_conditions': tc_data.get('test_conditions') or '',
        'test_idea': tc_data.get('test_idea') or '',
        'test_data': tc_data.get('test_data') or '',
        'acceptance_criteria': tc_data.get('acceptance_criteria') or '',
        'test_steps': _normalise_steps(tc_data.get('test_steps') or tc_data.get('steps')),
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
        resolution_result = await _find_user_ids_by_names_or_emails(api_key, team_id, assignees)
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
    result = await make_api_request('POST', '/v1/testcases/update', api_key, data=payload)

    # Step 6 (optional): Assign to agent within a sprint.
    # Mirrors the UI's "Assign to Agent" action: calls /testpert/sprintTestCase/update
    # with isTestAgentEnabled=1.
    # Routing: functional test cases → Browser Agent; API test cases → Testpert Agent.
    # The UI hides Browser Agent for API test cases and hides Testpert Agent for functional ones.
    if assign_to_agent:
        if not sprint_id:
            if isinstance(result, dict):
                result['agent_assignment'] = {
                    'status': 'failed',
                    'error': 'sprint_id is required for agent assignment',
                    'message': 'Provide sprint_id together with assign_to_agent=True.',
                }
            return result

        logger.info(f"Assigning testcase_id={testcase_id} to agent in sprint_id={sprint_id}")

        # Fetch test case list to determine is_api_test_case and discover agent user IDs.
        # The backend requires testCaseAssignees (agent user_id) + isTestCaseAssigneesUpdate=1
        # alongside isTestAgentEnabled=1, otherwise testpert_executor stays 0.
        agent_user_id = ''
        tc_params = {'teamId': str(team_id), 'appId': str(project_id), 'sprintId': str(sprint_id)}
        if test_run_execution_run_id:
            tc_params['testRunsExecutionRunId'] = str(test_run_execution_run_id)
        tc_resp = await make_api_request('GET', '/testpert/sprintTestCase/get', api_key, params=tc_params)
        if not (isinstance(tc_resp, dict) and tc_resp.get('status') == 'OK'):
            if isinstance(result, dict):
                result['agent_assignment'] = {
                    'status': 'failed',
                    'error': 'Could not fetch sprint test case data for agent assignment',
                    'message': 'Testpert may not be enabled for this project, or the sprint_id is invalid.',
                }
            return result

        # Determine if this specific test case is an API test case
        tc_cases = tc_resp.get('testCaseDetails') or []
        tc_detail = next(
            (t for t in tc_cases if str(t.get('test_case_id', '')) == str(testcase_id)),
            None
        )
        is_api_tc = bool(tc_detail.get('is_api_test_case')) if tc_detail else False

        # Collect Browser Agent and Testpert Agent user IDs separately
        browser_agent_id = ''
        testpert_agent_id = ''
        for member in (tc_resp.get('teamMembersDetails') or []):
            member_type = str(member.get('type') or member.get('user_type') or '').upper()
            if member_type == 'AGENT':
                if member.get('is_browser_agent_enabled') == 1:
                    browser_agent_id = str(member.get('user_id', ''))
                else:
                    testpert_agent_id = str(member.get('user_id', ''))

        # Route to the correct agent (mirrors UI: API tc → Testpert Agent, functional → Browser Agent)
        if is_api_tc:
            agent_user_id = testpert_agent_id or browser_agent_id
        else:
            agent_user_id = browser_agent_id or testpert_agent_id

        if not agent_user_id:
            if isinstance(result, dict):
                result['agent_assignment'] = {
                    'status': 'failed',
                    'error': 'No agent found for this sprint',
                    'message': 'No Testpert agent is enabled for this project. Enable agents in the project settings before assigning.',
                }
            return result

        agent_payload = {
            'appId': str(project_id),
            'teamId': str(team_id),
            'sprintId': str(sprint_id),
            'testCaseId': str(testcase_id),
            'executionStatus': 'NEW',
            'isTestAgentEnabled': '1',
            'isTestCaseAssigneesUpdate': '1',
        }
        if agent_user_id:
            agent_payload['testCaseAssignees'] = agent_user_id
        if test_run_execution_run_id:
            agent_payload['testRunsExecutionRunId'] = str(test_run_execution_run_id)
        agent_resp = await make_api_request('POST', '/testpert/sprintTestCase/update', api_key, data=agent_payload)
        if isinstance(result, dict):
            result['agent_assignment'] = agent_resp

    return result


@mcp.tool(
    name = "bugasura_delete_test_case",
    description = (
        "Delete or unlink a test case at three scopes — choose the right one:\n"
        "• Project-level (default): permanently deletes the test case from the project. WARNING: irreversible.\n"
        "• Sprint-level (provide sprint_id): unlinks the test case from the sprint only; it stays in the project.\n"
        "• Run-level (provide sprint_id + test_run_execution_run_id): removes the test case from that specific test run execution only.\n"
        "Accepts numeric ID, test case key (e.g. 'TES5', 'MCP11'), or exact/partial scenario text. "
        "Interactive team/project selection available."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": True}
)
async def delete_test_case(
    testcase_identifier: str = Field(description="Test case identifier: numeric ID (e.g., '123'), test case key (e.g., 'TES5', 'MCP11'), or scenario text for matching"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    sprint_id: Optional[int] = Field(default=None, description="Sprint ID (report_id). When provided, unlinks the test case from the sprint instead of deleting it from the project. Get from bugasura_list_sprints."),
    test_run_execution_run_id: Optional[int] = Field(default=None, description="Test run execution ID. When provided together with sprint_id, removes the test case from that specific run only (not from the sprint). Get from bugasura_list_test_runs."),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Delete or unlink a test case at three scopes:
    - Project-level (no sprint_id): permanent hard delete from the project.
    - Sprint-level (sprint_id only): unlinks from sprint (removes from tcTags +
      testRunTestCasesTable default template row); test case stays in the project.
    - Run-level (sprint_id + test_run_execution_run_id): removes from that
      specific execution run's testRunTestCasesTable row only.
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_delete_test_case', f', testcase_identifier={testcase_identifier}')
    if 'status' in context and context['status'] == 'selection_required':
        return context

    team_id = context['team_id']
    project_id = context['project_id']

    # --- Resolve testcase_identifier to a numeric testcase_id ---
    testcase_id = int(testcase_identifier) if testcase_identifier.isdigit() else None
    if testcase_id:
        logger.info(f"delete_test_case: Using numeric testcase_id={testcase_id}")

    # --- Branch by scope ---

    if sprint_id is not None:
        scope = 'run' if test_run_execution_run_id else 'sprint'

        # Resolve non-numeric identifier from sprint listing (covers all test cases, not just first 100).
        if testcase_id is None:
            logger.info(f"delete_test_case: Searching sprint {sprint_id} for '{testcase_identifier}'")
            sprint_params = {'teamId': str(team_id), 'appId': str(project_id), 'sprintId': str(sprint_id)}
            if test_run_execution_run_id:
                sprint_params['testRunsExecutionRunId'] = str(test_run_execution_run_id)
            sprint_resp = await make_api_request('GET', '/testpert/sprintTestCase/get', api_key, params=sprint_params)
            sprint_tcs = sprint_resp.get('testCaseDetails', []) if isinstance(sprint_resp, dict) else []

            ident_upper = testcase_identifier.upper()
            match = next((tc for tc in sprint_tcs if tc.get('test_case_number', '').upper() == ident_upper), None)
            if not match:
                match = next((tc for tc in sprint_tcs if tc.get('scenario', '').lower() == testcase_identifier.lower()), None)
            if not match:
                matches = [tc for tc in sprint_tcs if testcase_identifier.lower() in tc.get('scenario', '').lower()]
                if len(matches) > 1:
                    tc_list = '\n'.join([f"  - ID: {tc.get('test_case_id')}, Key: {tc.get('test_case_number', 'N/A')}, Scenario: {tc.get('scenario')}" for tc in matches[:10]])
                    return {'status': 'failed', 'error': 'Multiple test cases found', 'message': f"Multiple test cases match '{testcase_identifier}'. Please use a unique key or ID:\n{tc_list}"}
                match = matches[0] if matches else None

            if not match:
                return {'status': 'failed', 'error': 'Test case not found', 'message': f"No test case '{testcase_identifier}' found in sprint {sprint_id}."}
            testcase_id = match.get('test_case_id')
            logger.info(f"delete_test_case: Resolved '{testcase_identifier}' to testcase_id={testcase_id} from sprint listing")

        logger.info(f"delete_test_case: {scope}-level unlink for testcase_id={testcase_id}, sprint_id={sprint_id}, run_id={test_run_execution_run_id}")
        payload = {
            'team_id': str(team_id),
            'app_id': str(project_id),
            'testcaseids': str(testcase_id),
            'sprintId': str(sprint_id),
        }
        if test_run_execution_run_id:
            payload['testRunsExecutionRunId'] = str(test_run_execution_run_id)
        result = await make_api_request('POST', '/v1/testcases/delete', api_key, data=payload)
        if isinstance(result, dict):
            result['delete_scope'] = scope
            result['testcase_id'] = testcase_id
            result['sprint_id'] = sprint_id
            if test_run_execution_run_id:
                result['test_run_execution_run_id'] = test_run_execution_run_id
        return result

    # Project-level: permanent delete.
    if testcase_id is None:
        logger.info(f"delete_test_case: Searching project {project_id} for '{testcase_identifier}'")
        testcases_response = await make_api_request('GET', '/v1/testcases/list', api_key, params={
            'team_id': str(team_id), 'app_id': str(project_id), 'start_at': 0, 'max_results': 100,
        })
        if testcases_response.get('status') != 'OK':
            return {'status': 'failed', 'error': 'Failed to fetch test cases', 'message': testcases_response.get('message', 'Could not retrieve test cases list')}

        testcases = testcases_response.get('testCases', [])
        matching_testcases = [tc for tc in testcases if tc.get('test_case_key', '').upper() == testcase_identifier.upper()]
        if not matching_testcases:
            matching_testcases = [tc for tc in testcases if tc.get('scenario', '').lower() == testcase_identifier.lower()]
        if not matching_testcases:
            matching_testcases = [tc for tc in testcases if testcase_identifier.lower() in tc.get('scenario', '').lower()]

        if not matching_testcases:
            return {'status': 'failed', 'error': 'Test case not found', 'message': f"No test case found with key or scenario '{testcase_identifier}' in project {project_id}"}
        if len(matching_testcases) > 1:
            testcase_list = '\n'.join([f"  - ID: {tc['project_test_case_id']}, Key: {tc.get('test_case_key', 'N/A')}, Scenario: {tc['scenario']}" for tc in matching_testcases[:10]])
            return {'status': 'failed', 'error': 'Multiple test cases found', 'message': f"Multiple test cases match '{testcase_identifier}'. Please use the test case ID or unique key:\n{testcase_list}"}

        testcase_id = matching_testcases[0]['project_test_case_id']
        logger.info(f"delete_test_case: Resolved '{testcase_identifier}' to testcase_id={testcase_id}")

    logger.info(f"delete_test_case: project-level delete for testcase_id={testcase_id}, team_id={team_id}, project_id={project_id}")
    payload = {
        "app_id": project_id,
        "testcaseids": str(testcase_id),
        "team_id": team_id,
        "isDeleteTestCases": "true",
    }
    result = await make_api_request('POST', '/v1/testcases/delete', api_key, data=payload)
    if isinstance(result, dict):
        result['delete_scope'] = 'project'
        result['testcase_id'] = testcase_id
    return result


@mcp.tool(
    name = "bugasura_list_test_case_comments",
    description = "List comments for a specific test case with test case details. Returns test case information and all associated comments. Interactive team/project/test case selection available.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def list_test_case_comments(
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    test_case_id: Optional[int] = Field(default=None, description="Test case identifier (optional - will prompt if not provided)"),
    report_id: Optional[int] = Field(default=None, description="Report identifier (optional, ge=1)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return _respond(validation, response_format)

    # Use centralized context selection helper for team and project
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_list_test_case_comments')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return _respond(context, response_format)

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Now we have team_id and project_id, check if test_case_id is provided
    if test_case_id is None:
        # Fetch available test cases for selection using CORRECTED API call
        test_cases_response = await make_api_request('GET', '/v1/testcases/list', api_key, params={
            'team_id': team_id,
            'app_id': project_id,  # API expects 'app_id'
            'start_at': 0,
            'max_results': 100
        })

        # FIXED: Use 'testCasesList' and proper field names
        if test_cases_response.get('status') == 'OK' and test_cases_response.get('testCasesList'):
            return _respond({
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
            }, response_format)
        else:
            return _respond({
                'status': 'ERROR',
                'message': f'No test cases found for the selected project (team_id={team_id}, project_id={project_id}) or unable to fetch test cases',
                'debug_info': {
                    'response_status': test_cases_response.get('status'),
                    'response_message': test_cases_response.get('message', ''),
                    'response_keys': list(test_cases_response.keys()) if test_cases_response else []
                }
            }, response_format)

    # All required parameters provided - proceed with fetching test case comments
    params = {
        'team_id': team_id,
        'app_id': project_id,
        'testCaseId': test_case_id
    }

    # Add optional report_id if provided
    if report_id is not None:
        params['report_id'] = report_id

    response = await make_api_request('GET', '/v1/testcasecomments/list', api_key, params=params)

    # Attach test case details fetched before listing comments
    try:
        tc_before = await get_test_case(api_key, testcase_id=test_case_id, team_id=team_id, project_id=project_id)
        response['test_case_before'] = tc_before
    except (KeyError, AttributeError, TypeError, ValueError, requests.RequestException) as e:
        logger.debug(f"list_test_case_comments: Could not fetch test case details before listing comments: {e}")

    # Filter out large unnecessary fields to reduce payload size, then wrap in envelope
    response = filter_large_fields(response)
    return _respond(_paginate_upstream(response, offset=0), response_format)


@mcp.tool(
    name = "bugasura_add_test_case_comment",
    description = "Add a comment to a specific test case. Supports inline images, file attachments, and threaded replies. Interactive team/project/test case selection available.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def add_test_case_comment(
    comment: str = Field(description="Comment content (supports HTML formatting, required, min_length=1)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    test_case_id: Optional[int] = Field(default=None, description="Test case identifier (optional - will prompt if not provided)"),
    report_id: Optional[int] = Field(default=None, description="Report identifier (optional, ge=1)"),
    parent_comment_id: Optional[int] = Field(default=None, description="Parent comment ID for threaded replies (optional)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Validate comment is not empty
    if not comment or comment.strip() == '':
        return {
            'status': 'ERROR',
            'message': 'Comment content is required and cannot be empty'
        }

    # Use centralized context selection helper for team and project
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_add_test_case_comment', f', comment="{comment[:50]}..."')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # Now we have team_id and project_id, check if test_case_id is provided
    if test_case_id is None:
        # Fetch available test cases for selection using CORRECTED API call
        test_cases_response = await make_api_request('GET', '/v1/testcases/list', api_key, params={
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

    response = await make_api_request('POST', '/v1/testcasecomments/add', api_key, data=payload)

    if response.get('status') == 'OK':
        logger.info(f"add_test_case_comment: Successfully added comment to test case {test_case_id}")
    else:
        logger.error(f"add_test_case_comment: Failed to add comment. Response: {response.get('message', 'Unknown error')}")
    # Attach test case details fetched before adding comment
    try:
        tc_before = await get_test_case(api_key, testcase_id=test_case_id, team_id=team_id, project_id=project_id)
        response['test_case_before'] = tc_before
    except (KeyError, AttributeError, TypeError, ValueError, requests.RequestException) as e:
        logger.debug(f"add_test_case_comment: Could not fetch test case details before adding comment: {e}")

    # Refresh test case list for the project so clients can get up-to-date data
    try:
        refreshed = await list_test_cases(api_key, team_id=team_id, project_id=project_id)
        response['test_cases_refresh'] = refreshed
        logger.debug("add_test_case_comment: Refreshed test case list attached to response")
    except (KeyError, AttributeError, TypeError, ValueError, requests.RequestException) as e:
        logger.error(f"add_test_case_comment: Failed to refresh test case list: {e}")
        response['test_cases_refresh_error'] = str(e)

    return response


@mcp.tool(
    name = "bugasura_get_test_case_comment",
    description = "Get detailed information for a specific test case comment by comment ID. Returns full comment details including attachments, inline images, and metadata. Interactive team/project/test case selection available.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def get_test_case_comment(
    comment_id: int = Field(description="Comment identifier (required, ge=1)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    test_case_id: Optional[int] = Field(default=None, description="Test case identifier (optional - will prompt if not provided)"),
    report_id: Optional[int] = Field(default=None, description="Report identifier (optional, ge=1)"),
    parent_comment_id: Optional[int] = Field(default=None, description="Parent comment ID for fetching threaded replies (optional)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return _respond(validation, response_format)

    # Validate comment_id is provided (required parameter)
    if comment_id is None or comment_id <= 0:
        return _respond({
            'status': 'ERROR',
            'message': 'comment_id is required and must be a positive integer'
        }, response_format)

    # Use centralized context selection helper for team and project
    context = await select_team_project_context(
        api_key, team_id, project_id, 'bugasura_get_test_case_comment',
        f', comment_id={comment_id}'
    )

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return _respond(context, response_format)

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
            return _respond(resolved, response_format)
        test_case_id = resolved['testcase_id']

    if test_case_id is None:
        # Fetch available test cases for selection using CORRECTED API call
        test_cases_response = await make_api_request('GET', '/v1/testcases/list', api_key, params={
            'team_id': team_id,
            'app_id': project_id,
            'start_at': 0,
            'max_results': 100
        })

        # FIXED: Use 'testCasesList' and proper field names
        if test_cases_response.get('status') == 'OK' and test_cases_response.get('testCasesList'):
            return _respond({
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
            }, response_format)
        else:
            return _respond({
                'status': 'ERROR',
                'message': f'No test cases found for the selected project (team_id={team_id}, project_id={project_id}) or unable to fetch test cases',
                'debug_info': {
                    'response_status': test_cases_response.get('status'),
                    'response_message': test_cases_response.get('message', ''),
                    'response_keys': list(test_cases_response.keys()) if test_cases_response else []
                }
            }, response_format)

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

    response = await make_api_request('GET', '/v1/testcasecomments/get', api_key, params=params)

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

    return _respond(response, response_format)


@mcp.tool(
    name = "bugasura_update_test_case_comment",
    description = "Update a test case comment. Can update comment content and attachments. Only the comment owner can update their comment. Interactive team/project/test case/comment selection available.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def update_test_case_comment(
    comment: str = Field(description="Updated comment content (supports HTML formatting, required, min_length=1)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    test_case_id: Optional[int] = Field(default=None, description="Test case identifier (optional - will prompt if not provided)"),
    comment_id: Optional[int] = Field(default=None, description="Comment identifier to update (optional - will prompt if not provided, ge=1)"),
    report_id: Optional[int] = Field(default=None, description="Report identifier (optional, ge=1)"),
    comment_attachments: Optional[str] = Field(default=None, description="Comma-separated list of attachment filenames to keep (optional)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Validate comment is not empty
    if not comment or comment.strip() == '':
        return {
            'status': 'ERROR',
            'message': 'Comment content is required and cannot be empty'
        }

    # Use centralized context selection helper for team and project
    context = await select_team_project_context(
        api_key, team_id, project_id, 'bugasura_update_test_case_comment',
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
        test_cases_response = await make_api_request('GET', '/v1/testcases/list', api_key, params={
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

        comments_response = await make_api_request('GET', '/v1/testcasecomments/list', api_key, params=comments_params)

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
        tc_before = await get_test_case(api_key, testcase_id=test_case_id, team_id=team_id, project_id=project_id)
    except (KeyError, AttributeError, TypeError, ValueError, requests.RequestException) as e:
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

    response = await make_api_request('POST', '/v1/testcasecomments/update', api_key, data=payload)

    if response.get('status') == 'OK':
        logger.info(f"update_test_case_comment: Successfully updated comment {comment_id} for test case {test_case_id}")
    else:
        logger.error(f"update_test_case_comment: Failed to update comment. Response: {response.get('message', 'Unknown error')}")
    # Attach the pre-update test case details to the response
    response['test_case_before'] = tc_before

    # Refresh test case list for the project after comment update
    try:
        refreshed = await list_test_cases(api_key, team_id=team_id, project_id=project_id)
        response['test_cases_refresh'] = refreshed
        logger.debug("update_test_case_comment: Refreshed test case list attached to response")
    except (KeyError, AttributeError, TypeError, ValueError, requests.RequestException) as e:
        logger.error(f"update_test_case_comment: Failed to refresh test case list: {e}")
        response['test_cases_refresh_error'] = str(e)

    return response


@mcp.tool(
    name = "bugasura_delete_test_case_comment",
    description = "Delete a test case comment permanently by comment ID. Supports interactive team/project/test case/comment selection. Only the comment owner can delete their comment. WARNING: This action cannot be undone.",
    annotations={"readOnlyHint": False, "destructiveHint": True,  "idempotentHint": True,  "openWorldHint": True}
)
async def delete_test_case_comment(
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    test_case_id: Optional[int] = Field(default=None, description="Test case identifier (optional - will prompt if not provided)"),
    comment_id: Optional[int] = Field(default=None, description="Comment identifier to delete (optional - will prompt if not provided, ge=1)"),
    report_id: Optional[int] = Field(default=None, description="Report identifier (optional, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
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
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper for team and project
    context = await select_team_project_context(
        api_key, team_id, project_id, 'bugasura_delete_test_case_comment'
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
        test_cases_response = await make_api_request('GET', '/v1/testcases/list', api_key, params={
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

        comments_response = await make_api_request('GET', '/v1/testcasecomments/list', api_key, params=comments_params)

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

    response = await make_api_request('POST', '/v1/testcasecomments/delete', api_key, data=payload)

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
        tc_before = await get_test_case(api_key, testcase_id=test_case_id, team_id=team_id, project_id=project_id)
        response['test_case_before'] = tc_before
    except (KeyError, AttributeError, TypeError, ValueError, requests.RequestException) as e:
        logger.debug(f"delete_test_case_comment: Could not fetch test case details before deletion: {e}")

    # Refresh test case list for the project after comment deletion
    try:
        refreshed = await list_test_cases(api_key, team_id=team_id, project_id=project_id)
        response['test_cases_refresh'] = refreshed
        logger.debug("delete_test_case_comment: Refreshed test case list attached to response")
    except (KeyError, AttributeError, TypeError, ValueError, requests.RequestException) as e:
        logger.error(f"delete_test_case_comment: Failed to refresh test case list: {e}")
        response['test_cases_refresh_error'] = str(e)

    return response


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise_steps(steps):
    """Return steps as a JSON string so the backend can json_decode it correctly.
    The GET endpoint may return test_steps as a list or a JSON string; the update
    endpoint must receive a JSON string, else PHP implodes nested arrays into garbage."""
    if not steps:
        return ''
    if isinstance(steps, list):
        return json.dumps(steps)
    return steps
