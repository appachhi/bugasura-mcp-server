"""Bugasura MCP tools: test_cases."""
import html, json
from typing import Any, List, Literal, Optional

from fastmcp import Context
from pydantic import Field

from output_types import ToolResponse
from app import mcp
from auth import fetch_user_context, get_api_key, validate_api_key
from client import paginate_upstream, respond, logger, make_api_request
from config import (
    BROWSER_AGENT_PLATFORM_TYPES, MOBILE_AGENT_PLATFORM_TYPES, TestCaseExecutionStatus, TestCasePlatformType,
    TestCaseResultStatus, TestCaseStatus,
)
from helpers import (
    ATTACH_FILE_PATHS_DESCRIPTION, ATTACH_UPLOAD_ID_DESCRIPTION, find_user_ids_by_names_or_emails,
    attachment_names_csv, filter_large_fields, open_attachments, project_comment_attachment_names,
    select_team_project_context, send_with_attachments,
)


@mcp.tool(
    name = "bugasura_list_test_cases",
    title = "List Test Cases",
    description = (
        "List test cases for a project with pagination. When sprint_id is provided, returns full test "
        "case details for that sprint (grouped by sub-feature): scenario, steps, severity, priority, "
        "conditions, test data, execution status, and test_case_status (PASS, FAIL, or PENDING if not run yet). "
        "Filter by test_case_status to answer e.g. 'which test cases failed in this sprint'. "
        "Add test_run_execution_run_id to scope to a specific run: test_case_status is then that run's, and "
        "pass_count and fail_count per test case are also included (scoped to that run only). Without it, a sprint "
        "with several runs reports the status of any one of them, so pass the run for run results. "
        "Without sprint_id, returns all project-level test cases as brief summaries. "
        "IMPORTANT: always display scenario text exactly as returned — never shorten, rephrase, or summarize it. "
        "Show test_case_number (e.g. TES123, formed from project prefix + id) as the test case identifier, not the raw numeric test_case_id. "
        "Interactive team/project selection available."
    ),
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def list_test_cases(
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)", ge=1),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
    sprint_id: Optional[int] = Field(default=None, description="Sprint ID (report_id). When provided, returns full test case details for that sprint, grouped by sub-feature."),
    test_run_execution_run_id: Optional[int] = Field(default=None, description="Test run execution ID (testRunsExecutionRunId). When provided alongside sprint_id, filters test cases to that specific run. Obtain from bugasura_list_test_runs."),
    sub_feature_name: Optional[str] = Field(default=None, description="Filter sprint test cases by sub-feature name (case-insensitive substring). Only used with sprint_id."),
    test_case_status: Optional[TestCaseStatus] = Field(default=None, description="Only return test cases with this status: PASS, FAIL, or PENDING (not run yet). Requires sprint_id; add test_run_execution_run_id to filter on that run's status (recommended when the sprint has several runs)."),
    start_at: int = Field(default=0, description="Pagination offset (default: 0, ge=0)", ge=0),
    max_results: int = Field(default=20, description="Number of results to return (default: 20, ge=1, le=100)", ge=1, le=100),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    ctx: Optional[Context] = None,
) -> ToolResponse:
    """List test cases. With sprint_id: fetches via /testpert/sprintTestCase/get (full details,
    grouped by sub-feature, includes test_case_status and, per run, pass_count/fail_count).
    Add test_run_execution_run_id to scope to a specific run within the sprint; test_case_status filters
    on the sprint (or run) status, so it needs sprint_id.
    Without sprint_id: fetches all project test cases via /v1/testcases/list (summaries).
    """
    api_key = get_api_key()
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return respond(validation, response_format)

    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_list_test_cases')
    if 'status' in context and context['status'] == 'selection_required':
        return respond(context, response_format)

    tid, pid = context['team_id'], context['project_id']

    if test_case_status and not sprint_id:
        return respond({
            'status': 'failed',
            'error': 'test_case_status filter needs sprint_id',
            'error_type': 'ValidationError',
            'message': "Pass/fail status is tracked per sprint and run. Pass sprint_id (from bugasura_list_sprints), "
                       "and test_run_execution_run_id for a specific run.",
        }, response_format)

    # --- Sprint-scoped path: full details via testpert endpoint ---
    if sprint_id:
        if ctx is not None:
            await ctx.report_progress(0.3, total=1.0, message=f"Fetching sprint {sprint_id} test cases")
        params = {'teamId': tid, 'appId': pid, 'sprintId': sprint_id}
        if test_run_execution_run_id:
            params['testRunsExecutionRunId'] = test_run_execution_run_id
        resp = await make_api_request('GET', '/testpert/sprintTestCase/get', api_key, params=params)
        if not (isinstance(resp, dict) and resp.get('status') == 'OK'):
            return respond({
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

        if test_case_status:
            all_cases = [tc for tc in all_cases if (tc.get('test_case_status') or 'PENDING') == test_case_status]

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
                # test_data is a display string ("key : value | ..."); original_test_data is the stored value, HTML-escaped.
                'test_data': html.unescape(tc.get('original_test_data') or '') or tc.get('test_data') or '',
                'steps': [s.get('action') for s in steps_raw if isinstance(s, dict) and s.get('action')],
                'acceptance_criteria': tc.get('acceptance_criteria') or '',
                'execution_status': tc.get('execution_status') or '',
                'test_case_status': tc.get('test_case_status') or 'PENDING',
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
        if test_case_status:
            result['test_case_status'] = test_case_status
        if total > start_at + max_results:
            result['next_offset'] = start_at + max_results
            result['message'] = (f"Showing {start_at + 1}–{start_at + len(page)} of {total}. "
                                 f"Call again with start_at={start_at + max_results} for the next page.")
        else:
            result['message'] = f"Showing all {len(page)} of {total} test cases for sprint {sprint_id}."
        return respond(result, response_format)

    # --- Project-wide path: all test cases (summaries, server-side pagination) ---
    if ctx is not None:
        await ctx.report_progress(0.5, total=1.0, message=f"Fetching test cases for project {pid}")
    # Without isFirstLoad/totalLoadedCount the endpoint returns every row (no LIMIT), so page here.
    response = await make_api_request('GET', '/v1/testcases/list', api_key, params={
        'team_id': tid,
        'app_id': pid,
    })
    response = filter_large_fields(response)
    if response.get('status') == 'OK' and isinstance(response.get('testCaseDetails'), list):
        # An empty result still carries the DB layer's [{NROWS: 0, STATUS: 'OK'}] row.
        response['testCaseDetails'] = [tc for tc in response['testCaseDetails']
                                       if isinstance(tc, dict) and tc.get('test_case_id')]
    return respond(paginate_upstream(response, items_key='testCaseDetails', offset=start_at,
                                     max_results=max_results, local=True), response_format)


@mcp.tool(
    name = "bugasura_create_test_case",
    title = "Create Test Case",
    description = "Create a new test case with required scenario. Supports feature tags, testing type, severity, priority, conditions, test data, assignees, and folder organization. Interactive team/project selection available.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def create_test_case(
    scenario: str = Field(description="Test case scenario/title (required, min_length=1)", min_length=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)", ge=1),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
    feature_name: str = Field(default="", description="Feature name/tag (optional; the API requires one, so 'feature_name_1' is stored when omitted)"),
    sub_feature_name: str = Field(default="", description="Sub-feature name/tag (optional; 'sub_feature_name_1' is stored when omitted)"),
    testing_type: str = Field(default="Functional", description="Testing type: 'Functional', 'Regression', 'Smoke', 'Integration', etc. (default: Functional)"),
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(default="MEDIUM", description="Severity: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW' (default: MEDIUM)"),
    priority: Literal["P0", "P1", "P2", "P3", "P4"] = Field(default="P2", description="Priority: 'P0', 'P1', 'P2', 'P3', 'P4' (default: P2)"),
    test_conditions: str = Field(default="", description="Pre-conditions and test setup (optional)"),
    test_idea: str = Field(default="", description="Test idea or objective (optional)"),
    test_data: str | list[dict[str, Any]] = Field(default="", description="Test data (optional). Plain text, or for TestPert / agent test cases the JSON list they store: {type: 'text' or 'file', key, value, test_data_id} items (a list or its JSON string). Replaces the whole value."),
    platform_type: Optional[TestCasePlatformType] = Field(default=None, description="Platform the test case runs on (optional). Agents are platform bound: the Browser Agent runs only DESKTOP_WEB test cases, the Mobile Agent only ANDROID / ANDROID_MOBILE_WEB / IOS / IOS_MOBILE_WEB."),
    acceptance_criteria: str = Field(default="", description="Acceptance criteria or expected results (optional)"),
    assignees: Optional[str] = Field(default=None, description="Comma-separated assignee names, emails, or IDs (optional)"),
    is_api_test_case: bool = Field(default=False, description="Flag for API test cases (default: False)"),
    folder_id: Optional[int] = Field(default=None, description="Folder ID for organization (optional, ge=1)", ge=1),
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
    api_key = get_api_key()
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
        resolution_result = await find_user_ids_by_names_or_emails(api_key, team_id, assignees)
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
        'test_data': _test_data_text(test_data),     # Input data needed
        'platform_type': platform_type,              # Platform the agents check
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
    title = "Get Test Case",
    description = "Get detailed test case information by numeric ID. Returns full test case details including steps and execution history. With sprint_id it also returns the test case's status (test_case_status) in that sprint; add test_run_execution_run_id for its status in one run. For pass/fail counts use bugasura_list_test_cases with test_run_execution_run_id. Interactive team/project selection available.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def get_test_case(
    testcase_id: int = Field(description="Test case numeric ID", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)", ge=1),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (optional, ge=1)", ge=1),
    test_run_execution_run_id: Optional[int] = Field(default=None, description="Test run execution ID, to get the test case's status in that run. Needs sprint_id. Get from bugasura_list_test_runs.", ge=1),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
) -> ToolResponse:
    """
    Get test case details.

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection.

    Args:
        testcase_id: Test case identifier (required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        sprint_id: Optional sprint ID for execution context
        test_run_execution_run_id: Optional run within the sprint, for the run-level test_case_status

    Returns:
        dict: Complete test case details with execution history if sprint_id provided
    """
    # Validate API key before proceeding
    api_key = get_api_key()
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return respond(validation, response_format)

    # Use centralized context selection helper
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_get_test_case', f', testcase_id={testcase_id}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return respond(context, response_format)

    if test_run_execution_run_id and not sprint_id:
        return respond({
            'status': 'failed',
            'error': 'test_run_execution_run_id needs sprint_id',
            'error_type': 'ValidationError',
            'message': "Pass the sprint_id the run belongs to (from bugasura_list_sprints) together with test_run_execution_run_id.",
        }, response_format)

    response = await _fetch_test_case(api_key, context['team_id'], context['project_id'], testcase_id, sprint_id,
                                      test_run_execution_run_id)
    return respond(response, response_format)


@mcp.tool(
    name = "bugasura_update_test_case",
    title = "Update Test Case",
    description = "Update test case details (partial updates supported). Can update any field including scenario, feature tags, testing type, severity, priority, conditions, test steps, assignees, status, and sprint associations. execution_status and test_case_status apply to the project test case, or with sprint_id to the test case in that sprint, or with sprint_id and test_run_execution_run_id to the test case in that test run (e.g. to mark it COMPLETED in a run). To assign a sprint-level test case to an agent for automated execution, set assign_to_agent=True along with sprint_id. API test cases go to the API Agent; functional test cases go by platform_type: DESKTOP_WEB to the Browser Agent, the mobile types to the Mobile Agent. A functional test case with no platform_type cannot be assigned, so pass platform_type in the same call (e.g. platform_type='DESKTOP_WEB' for the Browser Agent). If the agent cannot be assigned the call fails, and test_case_updated says whether the other changes were saved. Interactive selection available.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def update_test_case(
    testcase_id: int = Field(description="Test case numeric ID to update", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)", ge=1),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
    feature_name: Optional[str] = Field(default=None, description="New feature name/tag (optional)"),
    sub_feature_name: Optional[str] = Field(default=None, description="New sub-feature name/tag (optional)"),
    scenario: Optional[str] = Field(default=None, description="New test case scenario/title (optional)"),
    testing_type: Optional[str] = Field(default=None, description="New testing type (optional)"),
    severity: Optional[Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]] = Field(default=None, description="New severity: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW' (optional)"),
    priority: Optional[str] = Field(default=None, description="New priority: 'P0', 'P1', 'P2', 'P3', 'P4' (optional)"),
    test_conditions: Optional[str] = Field(default=None, description="New test conditions (optional)"),
    test_idea: Optional[str] = Field(default=None, description="New test idea (optional)"),
    test_data: Optional[str | list[dict[str, Any]]] = Field(default=None, description="Test data (optional). Plain text, or for TestPert / agent test cases the JSON list they store: {type: 'text' or 'file', key, value, test_data_id} items (a list or its JSON string). Replaces the whole value."),
    platform_type: Optional[TestCasePlatformType] = Field(default=None, description="Platform the test case runs on (optional). Agents are platform bound: the Browser Agent runs only DESKTOP_WEB test cases, the Mobile Agent only ANDROID / ANDROID_MOBILE_WEB / IOS / IOS_MOBILE_WEB."),
    acceptance_criteria: Optional[str] = Field(default=None, description="New acceptance criteria (optional)"),
    test_steps: Optional[str] = Field(default=None, description="Replaces all test steps of a functional test case: one step per line or a JSON list of steps; an empty string clears them (optional)"),
    execution_status: Optional[TestCaseExecutionStatus] = Field(default=None, description="Progress of the test case (optional): NEW, IN_PROGRESS, BLOCKED, CANCELLED or COMPLETED. Not the pass/fail result, use test_case_status for that. Set in the sprint with sprint_id, or in a test run with sprint_id and test_run_execution_run_id; otherwise on the project test case. COMPLETED needs a PASS or FAIL result reported first, in that run when one is given."),
    test_case_status: Optional[TestCaseResultStatus] = Field(default=None, description="Result of the test case (optional): PASS or FAIL. Only sets the status, no result is recorded; to report a run of the test case use bugasura_report_test_case_result. Scoped by sprint_id / test_run_execution_run_id like execution_status."),
    assignees: Optional[str] = Field(default=None, description="New assignees, comma-separated names/emails/IDs (optional)"),
    folder_id: Optional[int] = Field(default=None, description="New folder ID for organization (optional, ge=1)", ge=1),
    sprint_ids: Optional[str] = Field(default=None, description="Comma-separated sprint IDs to tag the test case with (optional). This only sets the sprint tag; it does not add the test case to the sprint's test case list. Use bugasura_link_test_cases_to_sprint for that."),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (report_id) for sprint-level operations: agent assignment, or setting execution_status / test_case_status in the sprint (optional, ge=1)", ge=1),
    test_run_execution_run_id: Optional[int] = Field(default=None, description="Test run execution ID (testRunsExecutionRunId), with sprint_id. Scopes execution_status / test_case_status and agent assignment to that test run. Get from bugasura_list_test_runs.", ge=1),
    assign_to_agent: bool = Field(default=False, description="When True (and sprint_id is provided), assigns this test case to an agent for automated execution within that sprint. API test cases go to the API Agent; functional ones to the Browser Agent (platform_type DESKTOP_WEB) or the Mobile Agent (mobile platform types). The project must have that agent enabled."),
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
        test_data: Test data needed, text or a JSON list of {type, key, value} items (optional)
        platform_type: DESKTOP_WEB, ANDROID, ANDROID_MOBILE_WEB, IOS, IOS_MOBILE_WEB or MULTI_PLATFORM (optional)
        acceptance_criteria: Expected results (optional)
        test_steps: Replaces all steps of a functional test case, one per line or a JSON list (optional)
        execution_status: Progress - NEW/IN_PROGRESS/BLOCKED/CANCELLED/COMPLETED (optional)
        test_case_status: Result - PASS/FAIL (optional)
        assignees: Comma-separated names, emails, or user IDs (optional)
        folder_id: Folder ID for organization (optional)
        sprint_ids: Comma-separated sprint IDs (optional)
        sprint_id: Sprint identifier for agent assignment or sprint-level status (optional)
        test_run_execution_run_id: Test run for run-level status or agent assignment, with sprint_id (optional)
        assign_to_agent: True to assign this sprint test case to an agent (optional)

    Returns:
        dict: API response with update status. When assign_to_agent=True, also includes
              agent_assignment; an assignment that fails returns status 'failed' with
              test_case_updated saying whether the field changes were saved.

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

        # Assign a sprint test case to the Browser Agent (it runs only Desktop Web test cases)
        update_test_case(api_key, team_id, project_id, testcase_id, sprint_id=42, platform_type="DESKTOP_WEB", assign_to_agent=True)

        # Mark the test case COMPLETED in test run 9 of sprint 42
        update_test_case(api_key, team_id, project_id, testcase_id, sprint_id=42, test_run_execution_run_id=9, execution_status="COMPLETED")
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
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_update_test_case', f', testcase_id={testcase_id}')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

    # /v1/testcases/update never reaches a run's row, so sprint and run statuses go to /testpert/sprintTestCase/update.
    status_given = execution_status is not None or test_case_status is not None
    if status_given and test_run_execution_run_id and sprint_id is None:
        return {'status': 'failed', 'error': 'sprint_id is required with test_run_execution_run_id',
                'error_type': 'ValidationError',
                'message': 'Nothing was saved. Pass the sprint_id the test run belongs to (bugasura_list_test_runs).'}
    if execution_status is not None and sprint_id is not None and assign_to_agent:
        return {'status': 'failed', 'error': 'execution_status cannot be combined with assign_to_agent',
                'error_type': 'ValidationError',
                'message': 'Nothing was saved. Assigning to an agent resets the execution status to NEW; set execution_status in a separate call.'}
    status_in_sprint = status_given and sprint_id is not None
    field_args = (feature_name, sub_feature_name, scenario, testing_type, severity, priority, test_conditions, test_idea,
                  test_data, platform_type, acceptance_criteria, test_steps, assignees, folder_id, sprint_ids)
    if status_in_sprint and not assign_to_agent and all(arg is None for arg in field_args):
        return await _update_sprint_test_case_status(api_key, team_id, project_id, testcase_id, sprint_id,
                                                     test_run_execution_run_id, execution_status, test_case_status)

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
        'test_data': _test_data_text(tc_data.get('test_data')),
        'acceptance_criteria': tc_data.get('acceptance_criteria') or '',
        'test_steps': _normalise_steps(tc_data.get('test_steps') or tc_data.get('steps')),
        'assignee': tc_data.get('assignee') or '',
    }
    # API test cases keep their steps in api_test_steps; the backend clears them when it is not sent.
    is_api_test_case = str(tc_data.get('is_api_test_case') or '0') == '1'
    if is_api_test_case:
        tc_details['api_test_steps'] = tc_data.get('api_test_steps') or ''

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
        tc_details['test_data'] = _test_data_text(test_data)
    if platform_type is not None:
        tc_details['platform_type'] = platform_type
    if acceptance_criteria is not None:
        tc_details['acceptance_criteria'] = acceptance_criteria
    if test_steps is not None:
        if is_api_test_case:
            return {
                'status': 'failed',
                'error': 'test_steps applies to functional test cases only; this is an API test case',
                'error_type': 'ValidationError',
                'message': 'Edit the API test steps of this test case in Bugasura instead.',
            }
        tc_details['test_steps'] = _normalise_steps(test_steps)
    if assignees is not None:
        # Convert names/emails to user IDs using smart identifier resolution
        logger.info(f"update_test_case: Resolving assignee identifiers '{assignees}' for team_id={team_id}")
        resolution_result = await find_user_ids_by_names_or_emails(api_key, team_id, assignees)
        if resolution_result['status'] != 'OK':
            logger.error(f"update_test_case: Failed to resolve assignee identifiers: {resolution_result.get('error')}")
            return resolution_result

        assignee_ids = resolution_result['user_ids']
        logger.info(f"update_test_case: Resolved assignees to user_ids: {assignee_ids}")
        tc_details['assignee'] = assignee_ids
    if sprint_ids is not None:
        tc_details['sprint_ids'] = sprint_ids

    # The executor json-decodes test data and errors the case when it is not JSON, empty included.
    if assign_to_agent and not is_api_test_case:
        if not tc_details['test_data'].strip():
            tc_details['test_data'] = '[]'
        elif not _is_json_test_data(tc_details['test_data']):
            return {
                'status': 'failed',
                'error': 'Agents need test_data as a JSON list of {key, value} items, not plain text',
                'error_type': 'ValidationError',
                'message': "Nothing was saved. Pass test_data as a list, e.g. [{\"type\": \"text\", \"key\": \"email\", \"value\": \"qa@example.com\"}].",
                'test_case_updated': False,
            }

    # An agent that cannot take this test case fails the call before anything is saved.
    agent = None
    if assign_to_agent:
        agent, agent_failure = await _pick_agent(api_key, team_id, project_id, testcase_id, sprint_id, test_run_execution_run_id, platform_type)
        if agent_failure:
            return agent_failure

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

    # Add status fields if provided; sprint and run statuses are set after the field update.
    if execution_status is not None and not status_in_sprint:
        payload["executionStatus"] = execution_status
        logger.debug(f"Set executionStatus to {execution_status}")
    if test_case_status is not None and not status_in_sprint:
        payload["testCaseStatus"] = test_case_status
        logger.debug(f"Set testCaseStatus to {test_case_status}")
    if folder_id is not None:
        payload["folderId"] = folder_id  # Will be converted to string
        logger.debug(f"Set folderId to {folder_id}")

    # Step 5: Make the update request
    logger.info(f"Sending update request for testcase_id={testcase_id}")
    result = await make_api_request('POST', '/v1/testcases/update', api_key, data=payload)

    # Step 6 (optional): Assign to agent within a sprint, as the UI's "Assign to Agent" does:
    # /testpert/sprintTestCase/update with isTestAgentEnabled=1 and the agent as assignee.
    if agent and isinstance(result, dict) and result.get('status') == 'OK':
        assignment = await _assign_to_agent(api_key, team_id, project_id, testcase_id, sprint_id, test_run_execution_run_id, agent)
        if assignment['status'] != 'OK':
            return assignment
        result['agent_assignment'] = assignment

    if status_in_sprint and isinstance(result, dict) and result.get('status') == 'OK':
        status_update = await _update_sprint_test_case_status(api_key, team_id, project_id, testcase_id, sprint_id,
                                                              test_run_execution_run_id, execution_status, test_case_status)
        if status_update['status'] != 'OK':
            status_update['test_case_updated'] = True
            status_update['message'] = 'The other test case changes were saved. ' + status_update['message']
            return status_update
        result['status_update'] = status_update

    return result


@mcp.tool(
    name = "bugasura_delete_test_case",
    title = "Delete Test Case",
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
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)", ge=1),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
    sprint_id: Optional[int] = Field(default=None, description="Sprint ID (report_id). When provided, unlinks the test case from the sprint instead of deleting it from the project. Get from bugasura_list_sprints."),
    test_run_execution_run_id: Optional[int] = Field(default=None, description="Test run execution ID. When provided together with sprint_id, removes the test case from that specific run only (not from the sprint). Get from bugasura_list_test_runs."),
) -> ToolResponse:
    """
    Delete or unlink a test case at three scopes:
    - Project-level (no sprint_id): permanent hard delete from the project.
    - Sprint-level (sprint_id only): unlinks from sprint (removes from tcTags +
      testRunTestCasesTable default template row); test case stays in the project.
    - Run-level (sprint_id + test_run_execution_run_id): removes from that
      specific execution run's testRunTestCasesTable row only.
    """
    api_key = get_api_key()
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


async def _link_unlink_sprint_test_cases(tool_name: str, is_delete: bool, sprint_id: int, testcase_ids: str,
                                         team_id: Optional[int], project_id: Optional[int]) -> dict:
    """Shared body of the sprint link/unlink tools: one /testcases/addRemoveSprintTestCases call per ID."""
    api_key = get_api_key()
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id, tool_name,
                                                f', sprint_id={sprint_id}, testcase_ids="{testcase_ids}"')
    if 'status' in context and context['status'] == 'selection_required':
        return context
    team_id = context['team_id']
    project_id = context['project_id']

    ids = [i.strip() for i in str(testcase_ids).split(',') if i.strip()]
    invalid_ids = [i for i in ids if not i.isdigit()]
    if not ids or invalid_ids:
        return {
            'status': 'failed',
            'error': 'Invalid testcase_ids',
            'error_type': 'ValidationError',
            'message': f"testcase_ids must be comma-separated numeric test case IDs; invalid: {invalid_ids or [testcase_ids]}"
        }
    ids = list(dict.fromkeys(ids))

    # The API does not check that the sprint belongs to the project, so check it here.
    sprint_resp = await make_api_request('GET', '/v1/sprints/list', api_key, params={
        'team_id': team_id, 'project_id': project_id, 'sprint_id': sprint_id,
    })
    if sprint_resp.get('status') != 'OK':
        return {'status': 'failed', 'error': 'Failed to verify sprint',
                'message': sprint_resp.get('message', 'Could not fetch the sprint')}
    if not any(str(s.get('sprint_id')) == str(sprint_id) for s in sprint_resp.get('sprintsList', [])):
        return {'status': 'failed', 'error': 'Sprint not found', 'error_type': 'NotFound',
                'message': f"Sprint {sprint_id} was not found in project {project_id}. Use bugasura_list_sprints to find it."}

    action = 'unlink' if is_delete else 'link'
    logger.info(f"{tool_name}: {action} test cases {ids} {'from' if is_delete else 'to'} sprint {sprint_id}")

    # One call per ID: the API has no transaction, so a failing ID in a list would leave earlier ones half linked.
    done, failed = [], []
    for tc_id in ids:
        payload = {'appId': project_id, 'teamId': team_id, 'sprintId': sprint_id}
        if is_delete:
            payload.update({'isDelete': 1, 'deleteTestCaseId': tc_id})
        else:
            payload['testCaseId'] = tc_id
        response = await make_api_request('POST', '/v1/testcases/addRemoveSprintTestCases', api_key, data=payload)
        if response.get('status') == 'OK':
            done.append(int(tc_id))
        else:
            logger.error(f"{tool_name}: Failed to {action} test case {tc_id} for sprint {sprint_id}: {response.get('message')}")
            failed.append({'testcase_id': int(tc_id), 'message': response.get('message') or response.get('error')})

    key = 'unlinked_testcase_ids' if is_delete else 'linked_testcase_ids'
    if not failed:
        return {
            'status': 'OK',
            'message': f"{'Unlinked' if is_delete else 'Linked'} {len(done)} test case(s) {'from' if is_delete else 'to'} sprint {sprint_id}",
            'sprint_id': sprint_id,
            key: done
        }
    return {
        'status': 'failed' if not done else 'partial_success',
        'error': f"Failed to {action} {len(failed)} of {len(ids)} test case(s)",
        'message': failed[0]['message'],
        'sprint_id': sprint_id,
        key: done,
        'failed': failed
    }


@mcp.tool(
    name = "bugasura_link_test_cases_to_sprint",
    title = "Link Test Cases to Sprint",
    description = (
        "Add existing project test cases to a sprint, so they appear in the sprint's test case list "
        "(new execution status, no assignee). Already-linked test cases are left as they are. "
        "Accepts comma-separated numeric test case IDs (test_case_id from bugasura_list_test_cases). "
        "Reports which IDs were linked and which failed. Interactive team/project selection available."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def link_test_cases_to_sprint(
    sprint_id: int = Field(description="Sprint ID (report_id) to add the test cases to. Get from bugasura_list_sprints."),
    testcase_ids: str = Field(description="Comma-separated numeric test case IDs to link (e.g., '123,456')"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)", ge=1),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
) -> ToolResponse:
    """Link existing project test cases to a sprint via /v1/testcases/addRemoveSprintTestCases."""
    return await _link_unlink_sprint_test_cases('bugasura_link_test_cases_to_sprint', False, sprint_id, testcase_ids, team_id, project_id)


@mcp.tool(
    name = "bugasura_unlink_test_cases_from_sprint",
    title = "Unlink Test Cases from Sprint",
    description = (
        "Remove test cases from a sprint. The test cases stay in the project; only their sprint link "
        "and sprint-level execution row are removed. "
        "Accepts comma-separated numeric test case IDs (test_case_id from bugasura_list_test_cases with sprint_id). "
        "Reports which IDs were unlinked and which failed. Interactive team/project selection available."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": True}
)
async def unlink_test_cases_from_sprint(
    sprint_id: int = Field(description="Sprint ID (report_id) to remove the test cases from. Get from bugasura_list_sprints."),
    testcase_ids: str = Field(description="Comma-separated numeric test case IDs to unlink (e.g., '123,456')"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)", ge=1),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
) -> ToolResponse:
    """Unlink test cases from a sprint via /v1/testcases/addRemoveSprintTestCases with isDelete=1."""
    return await _link_unlink_sprint_test_cases('bugasura_unlink_test_cases_from_sprint', True, sprint_id, testcase_ids, team_id, project_id)


@mcp.tool(
    name = "bugasura_report_test_case_result",
    title = "Report Test Case Result",
    description = (
        "Report that a sprint test case PASSED or FAILED, the same as the Pass / Fail buttons in Bugasura. "
        "Use this, not bugasura_create_issue, to record a pass: an issue is always a failure. "
        "The result is counted in the sprint's pass/fail stats, adds a 'reported Pass/Fail' comment on the test case, "
        "and sets the test case's status (it stays FAIL once it has failed, even if a later result passes). "
        "Pass test_run_execution_run_id when the test was executed in a test run: without it the API also counts "
        "FAILs from other sprints and runs, so a PASS on a test case that ever failed stays FAIL. "
        "FAIL also creates an issue linked to the test case, so it needs a summary. "
        "Reporting moves the execution status from NEW to IN_PROGRESS only. Set mark_completed=True only when the user "
        "explicitly asks to mark the test case completed. "
        "The test case must already be in the sprint (bugasura_link_test_cases_to_sprint). "
        "Interactive team/project selection available."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def report_test_case_result(
    testcase_id: int = Field(description="Test case ID (test_case_id from bugasura_list_test_cases with sprint_id)", ge=1),
    sprint_id: int = Field(description="Sprint ID (report_id) the test case was run in. Get from bugasura_list_sprints.", ge=1),
    result: TestCaseResultStatus = Field(description="PASS or FAIL"),
    summary: str = Field(default="", description="Issue title. Required for FAIL, ignored for PASS.", max_length=500),
    description: str = Field(default="", description="Issue details for FAIL, e.g. steps, expected vs. actual (optional, supports HTML). Ignored for PASS."),
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(default="MEDIUM", description="Issue severity for FAIL (default MEDIUM). Ignored for PASS."),
    issue_status: str = Field(default="", description="Issue workflow status for FAIL, must match the project workflow (optional, defaults to the first status). Ignored for PASS."),
    test_run_execution_run_id: Optional[int] = Field(default=None, description="Test run execution ID, to record the result in that run (optional). Get from bugasura_list_test_runs.", ge=1),
    device_name: str = Field(default="", description="Device tested on (optional)"),
    os_name: str = Field(default="", description="Operating system (optional)", max_length=50),
    os_version: str = Field(default="", description="OS version (optional)", max_length=50),
    browser_name: str = Field(default="", description="Browser name (optional)", max_length=50),
    browser_version: str = Field(default="", description="Browser version (optional)", max_length=50),
    network_name: str = Field(default="", description="Network condition (optional)", max_length=25),
    resolution: str = Field(default="", description="Screen resolution like '1920x1080', web projects only (optional)", max_length=25),
    mark_completed: bool = Field(default=False, description="Also set the execution status to COMPLETED, in the test run when test_run_execution_run_id is given, otherwise in the sprint. Leave False unless the user explicitly asks to mark the test case completed; by default reporting moves NEW to IN_PROGRESS only."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)", ge=1),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
) -> ToolResponse:
    """
    Report a PASS or FAIL for a sprint test case via /testresults/issueDetails/add.

    That is the web app's report endpoint: unlike /v1/issues/add (always FAIL, no test case link) it takes the
    result status and project_test_case_ids, and the backend then links the result to the test case (and run),
    updates the sprint test case status and execution status, and comments on the test case.
    """
    api_key = get_api_key()
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_report_test_case_result',
                                                f', testcase_id={testcase_id}, sprint_id={sprint_id}, result="{result}"')
    if 'status' in context and context['status'] == 'selection_required':
        return context
    team_id = context['team_id']
    project_id = context['project_id']

    is_pass = result == 'PASS'
    summary = summary.strip()
    if not is_pass and not summary:
        return {
            'status': 'failed',
            'error': 'summary is required for a FAIL result',
            'error_type': 'ValidationError',
            'message': "A FAIL creates an issue, so pass summary (and ideally description) saying what went wrong.",
        }

    # One read checks the test case is in the sprint and gives the sprint's testrun_id and platform type.
    tc_params = {'teamId': team_id, 'appId': project_id, 'sprintId': sprint_id, 'testCaseId': testcase_id}
    if test_run_execution_run_id:
        tc_params['testRunsExecutionRunId'] = test_run_execution_run_id
    tc_resp = await make_api_request('GET', '/testpert/sprintTestCase/get', api_key, params=tc_params)
    if not (isinstance(tc_resp, dict) and tc_resp.get('status') == 'OK'):
        logger.error(f"report_test_case_result: sprint test case read failed for sprint {sprint_id}: "
                     f"{tc_resp.get('message') if isinstance(tc_resp, dict) else tc_resp}")
        return {'status': 'failed', 'error': 'Could not read the sprint test case', 'error_type': 'APIError',
                'message': (tc_resp.get('message') if isinstance(tc_resp, dict) else None)
                           or f"Check that sprint {sprint_id} belongs to project {project_id}."}

    tc_detail = next((t for t in tc_resp.get('testCaseDetails') or []
                      if str(t.get('test_case_id', '')) == str(testcase_id)), None)
    if tc_detail is None:
        return {'status': 'failed', 'error': 'Test case is not in this sprint', 'error_type': 'NotFound',
                'message': f"Test case {testcase_id} is not in sprint {sprint_id}. "
                           "Add it with bugasura_link_test_cases_to_sprint, then report the result."}

    sprint_row = next((r for r in tc_resp.get('projectReportList') or []
                       if str(r.get('report_id', '')) == str(sprint_id)), None)
    if not sprint_row or not sprint_row.get('testrun_id'):
        return {'status': 'failed', 'error': 'Sprint not found', 'error_type': 'NotFound',
                'message': f"Sprint {sprint_id} was not found in project {project_id}. Use bugasura_list_sprints to find it."}

    # The backend requires every environment field; 'None' is its own placeholder (as in /v1/issues/add).
    platform_type = sprint_row.get('platformType') or await _project_platform_type(api_key, team_id, project_id)
    condition = 'None'
    if platform_type in ('Web', 'Multiple'):
        condition = 'None x None'
        width, _, height = resolution.lower().replace('*', 'x').partition('x')
        if width.strip().isdigit() and height.strip().isdigit():
            condition = f"{width.strip()} x {height.strip()}"
    os_name = os_name or 'None'
    issue_details = {
        'testrun_id': str(sprint_row['testrun_id']),
        'report_id': str(sprint_id),
        'app_id': str(project_id),
        'project_test_case_id': str(testcase_id),
        'project_test_case_ids': str(testcase_id),
        'testruns_execution_run_id': str(test_run_execution_run_id or ''),
        'status': result,
        'device_name': os_name if platform_type == 'Web' else (device_name or 'None'),
        'os_name': os_name,
        'os_version': os_version or 'None',
        'network_name': network_name or 'None',
        'browser_name': (browser_name or 'None') if platform_type in ('Web', 'Mobileweb', 'Multiple') else 'None',
        'browser_version': (browser_version or 'None') if platform_type in ('Web', 'Mobileweb', 'Multiple') else 'None',
        'condition_name': condition,
        'failure_reason': '' if is_pass else summary,
        'bug_description': '' if is_pass else description,
        'bug_severity': '' if is_pass else severity,
        'bug_status': '' if is_pass else issue_status,
        'failure_type': '' if is_pass else 'BUG',
    }

    logger.info(f"report_test_case_result: {result} for test case {testcase_id} in sprint {sprint_id}"
                f"{f' run {test_run_execution_run_id}' if test_run_execution_run_id else ''}")
    response = await make_api_request('POST', '/testresults/issueDetails/add', api_key, data={
        'teamId': team_id,
        'issueDetails': json.dumps(issue_details),
        'isTeamMember': 1,
        'source': 'API',
    })
    if not (isinstance(response, dict) and response.get('status') == 'OK'):
        logger.error(f"report_test_case_result: report failed for test case {testcase_id}: "
                     f"{response.get('message') if isinstance(response, dict) else response}")
        return {'status': 'failed', 'error': f"Could not report {result} for test case {testcase_id}",
                'error_type': 'APIError',
                'message': (response.get('message') if isinstance(response, dict) else None) or 'The API rejected the result.'}

    ids = response.get('testResultIds') or {}
    out = {
        'status': 'OK',
        'message': f"Reported {result} for test case {testcase_id} in sprint {sprint_id}",
        'testcase_id': testcase_id,
        'sprint_id': sprint_id,
        'result': result,
        'result_id': ids.get('testresults_id'),
    }
    if test_run_execution_run_id:
        out['test_run_execution_run_id'] = test_run_execution_run_id
    if not is_pass:
        out['issue_key'] = ids.get('testresults_id')
        out['issue_id'] = ids.get('issue_id')
    elif int(tc_detail.get('total_fail_count') or 0) > 0:
        # The API keeps the status FAIL when the fail count it read is non-zero; without a run that count spans all sprints.
        where = 'in this run' if test_run_execution_run_id else 'in an earlier sprint or run (no run was given, so the API counts them all)'
        out['note'] = f"This test case already has a FAIL {where}, so its status stays FAIL; the pass is still counted."

    if mark_completed:
        completion = await _update_sprint_test_case_status(api_key, team_id, project_id, testcase_id, sprint_id,
                                                           test_run_execution_run_id, execution_status='COMPLETED')
        if completion['status'] != 'OK':
            # The result is already recorded; a retry of this call would report it twice.
            return {**completion, 'result_recorded': True, 'result_id': out['result_id'],
                    'message': f"The {result} was recorded, so do not report it again. Mark the test case COMPLETED with "
                               "bugasura_update_test_case (execution_status='COMPLETED', same sprint_id and "
                               f"test_run_execution_run_id). {completion['message']}"}
        out['execution_status'] = completion['execution_status']
    return out


@mcp.tool(
    name = "bugasura_list_test_case_comments",
    title = "List Test Case Comments",
    description = "List comments for a specific test case with test case details. Returns test case information and all associated comments. Interactive team/project/test case selection available.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def list_test_case_comments(
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)", ge=1),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
    test_case_id: Optional[int] = Field(default=None, description="Test case identifier (optional - will prompt if not provided)"),
    report_id: Optional[int] = Field(default=None, description="Report identifier (optional, ge=1)", ge=1),
    start_at: int = Field(default=0, ge=0, description="Pagination offset (default: 0)"),
    max_results: int = Field(default=50, ge=1, le=100, description="Number of results to return (default: 50, max 100)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
) -> ToolResponse:
    """
    List comments for a specific test case along with test case details.
    Interactive flow: If team_id/project_id/test_case_id are not provided, this function
    will return available options for the user to select from.
    Args:
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        test_case_id: Test case identifier (optional - will prompt if not provided)
        report_id: Report identifier (optional)
    Returns:
        dict: Test case comments list with metadata
        OR a selection prompt if team_id/project_id/test_case_id not provided
    """
    # Validate API key before proceeding
    api_key = get_api_key()
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return respond(validation, response_format)

    # Use centralized context selection helper for team and project
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_list_test_case_comments')

    # If context selection is needed, return the selection prompt
    if 'status' in context and context['status'] == 'selection_required':
        return respond(context, response_format)

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
            return respond({
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
            return respond({
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
    response['test_case_before'] = await _fetch_test_case(api_key, team_id, project_id, test_case_id)

    # Filter out large unnecessary fields to reduce payload size, then wrap in envelope
    response = filter_large_fields(response)
    return respond(paginate_upstream(response, offset=start_at, max_results=max_results, local=True), response_format)


@mcp.tool(
    name = "bugasura_add_test_case_comment",
    title = "Add Test Case Comment",
    description = "Add a comment to a specific test case. Supports inline images, threaded replies and file attachments (pass upload_id from bugasura_create_upload_link(purpose='attachment')) — the only way to attach a file to a test case. Interactive team/project/test case selection available.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def add_test_case_comment(
    comment: str = Field(description="Comment content (supports HTML formatting, required, min_length=1)", min_length=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)", ge=1),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
    test_case_id: Optional[int] = Field(default=None, description="Test case identifier (optional - will prompt if not provided)"),
    report_id: Optional[int] = Field(default=None, description="Report identifier (optional, ge=1)", ge=1),
    parent_comment_id: Optional[int] = Field(default=None, description="Parent comment ID for threaded replies (optional)"),
    upload_id: Optional[str] = Field(default=None, description=ATTACH_UPLOAD_ID_DESCRIPTION),
    file_paths: List[str] = Field(default=[], description=ATTACH_FILE_PATHS_DESCRIPTION),
) -> ToolResponse:
    """
    Add a comment to a specific test case in Bugasura.
    Interactive flow: If team_id/project_id/test_case_id are not provided, this function
    will return available options for the user to select from.
    Args:
        comment: Comment content (required) - supports HTML formatting
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        test_case_id: Test case identifier (optional - will prompt if not provided)
        report_id: Report identifier for test run context (optional)
        parent_comment_id: Parent comment ID for threaded replies (optional)
        upload_id / file_paths: Files attached to the comment (sent in the same request)
    Returns:
        dict: API response with added comment details
        OR a selection prompt if team_id/project_id/test_case_id not provided
    """
    # Validate API key before proceeding
    api_key = get_api_key()
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

    opened = open_attachments(file_paths, upload_id)
    if opened.get('status') != 'OK':
        return opened

    logger.info(f"add_test_case_comment: Adding comment to test_case_id={test_case_id} in team={team_id}, project={project_id}")

    response = await send_with_attachments('POST', '/v1/testcasecomments/add', api_key, opened, upload_id, data=payload)

    if response.get('status') == 'OK':
        logger.info(f"add_test_case_comment: Successfully added comment to test case {test_case_id}")
    else:
        logger.error(f"add_test_case_comment: Failed to add comment. Response: {response.get('message', 'Unknown error')}")
    response['test_case_before'] = await _fetch_test_case(api_key, team_id, project_id, test_case_id)
    return response


@mcp.tool(
    name = "bugasura_get_test_case_comment",
    title = "Get Test Case Comment",
    description = "Get detailed information for a specific test case comment by comment ID. Returns full comment details including attachments, inline images, and metadata. Interactive team/project/test case selection available.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def get_test_case_comment(
    comment_id: int = Field(description="Comment identifier (required, ge=1)", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)", ge=1),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
    test_case_id: Optional[int] = Field(default=None, description="Test case identifier (optional - will prompt if not provided)"),
    report_id: Optional[int] = Field(default=None, description="Report identifier (optional, ge=1)", ge=1),
    parent_comment_id: Optional[int] = Field(default=None, description="Parent comment ID for fetching threaded replies (optional)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
) -> ToolResponse:
    """
    Get detailed information for a specific test case comment.
    Interactive flow: If team_id/project_id/test_case_id are not provided, this function
    will return available options for the user to select from.
    Args:
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
    api_key = get_api_key()
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return respond(validation, response_format)

    # Validate comment_id is provided (required parameter)
    if comment_id is None or comment_id <= 0:
        return respond({
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
        return respond(context, response_format)

    # Extract validated team_id and project_id
    team_id = context['team_id']
    project_id = context['project_id']

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
            return respond({
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
            return respond({
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

    return respond(response, response_format)


@mcp.tool(
    name = "bugasura_update_test_case_comment",
    title = "Update Test Case Comment",
    description = "Update a test case comment. Can update comment content, keep a subset of its attachments (comment_attachments) and add new files (upload_id from bugasura_create_upload_link(purpose='attachment')). Existing attachments are kept unless comment_attachments says otherwise. Only the comment owner can update their comment. Interactive team/project/test case/comment selection available.",
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False,  "openWorldHint": True}
)
async def update_test_case_comment(
    comment: str = Field(description="Updated comment content (supports HTML formatting, required, min_length=1)", min_length=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)", ge=1),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
    test_case_id: Optional[int] = Field(default=None, description="Test case identifier (optional - will prompt if not provided)"),
    comment_id: Optional[int] = Field(default=None, description="Comment identifier to update (optional - will prompt if not provided, ge=1)", ge=1),
    report_id: Optional[int] = Field(default=None, description="Report identifier (optional, ge=1)", ge=1),
    comment_attachments: Optional[str] = Field(default=None, description="Comma-separated list of the existing attachment filenames to keep (optional). Omit to keep them all; '' removes them all."),
    upload_id: Optional[str] = Field(default=None, description=ATTACH_UPLOAD_ID_DESCRIPTION + " The files are added to the comment's attachments."),
    file_paths: List[str] = Field(default=[], description=ATTACH_FILE_PATHS_DESCRIPTION),
) -> ToolResponse:
    """
    Update a test case comment in Bugasura.
    Interactive flow: If team_id/project_id/test_case_id/comment_id are not provided,
    this function will return available options for the user to select from.
    Args:
        comment: Updated comment content (required) - supports HTML formatting
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        test_case_id: Test case identifier (optional - will prompt if not provided)
        comment_id: Comment identifier to update (optional - will prompt if not provided)
        report_id: Report identifier for test run context (optional)
        comment_attachments: Comma-separated attachment filenames to retain (optional; omitted keeps all)
        upload_id / file_paths: New files to add to the comment
    Returns:
        dict: API response with updated comment details
        OR a selection prompt if required parameters not provided
    """
    # Validate API key before proceeding
    api_key = get_api_key()
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
    tc_before = await _fetch_test_case(api_key, team_id, project_id, test_case_id)
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

    # The API treats a missing attachment list as "keep none" and deletes the files, so the
    # current list is read back and resent when the caller did not give one
    comment_attachments = attachment_names_csv(comment_attachments)
    if comment_attachments is None:
        comment_attachments = await project_comment_attachment_names(api_key, 'testcase', team_id, project_id,
                                                                     test_case_id, comment_id, report_id)
        if comment_attachments is None:
            return {
                'status': 'failed',
                'error': 'Could not read the comment',
                'error_type': 'APIError',
                'message': ("The comment's current attachments could not be read, so it was not updated "
                            "(updating without them would delete them). Retry, or pass comment_attachments "
                            "with the filenames to keep."),
            }
    payload['commentsAttachments'] = comment_attachments
    payload['commentAttachments'] = comment_attachments

    opened = open_attachments(file_paths, upload_id)
    if opened.get('status') != 'OK':
        return opened

    logger.info(f"update_test_case_comment: Updating comment_id={comment_id} for test_case_id={test_case_id} in team={team_id}, project={project_id}")

    response = await send_with_attachments('POST', '/v1/testcasecomments/update', api_key, opened, upload_id, data=payload)

    if response.get('status') == 'OK':
        logger.info(f"update_test_case_comment: Successfully updated comment {comment_id} for test case {test_case_id}")
    else:
        logger.error(f"update_test_case_comment: Failed to update comment. Response: {response.get('message', 'Unknown error')}")
    # Attach the pre-update test case details to the response
    response['test_case_before'] = tc_before
    return response


@mcp.tool(
    name = "bugasura_delete_test_case_comment",
    title = "Delete Test Case Comment",
    description = "Delete a test case comment permanently by comment ID. Supports interactive team/project/test case/comment selection. Only the comment owner can delete their comment. WARNING: This action cannot be undone.",
    annotations={"readOnlyHint": False, "destructiveHint": True,  "idempotentHint": True,  "openWorldHint": True}
)
async def delete_test_case_comment(
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)", ge=1),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)", ge=1),
    test_case_id: Optional[int] = Field(default=None, description="Test case identifier (optional - will prompt if not provided)"),
    comment_id: Optional[int] = Field(default=None, description="Comment identifier to delete (optional - will prompt if not provided, ge=1)", ge=1),
    report_id: Optional[int] = Field(default=None, description="Report identifier (optional, ge=1)", ge=1),
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
    api_key = get_api_key()
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
    response['test_case_before'] = await _fetch_test_case(api_key, team_id, project_id, test_case_id)
    return response


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _project_platform_type(api_key: str, team_id: int, project_id: int) -> str:
    """The project's platform type (Web / Mobileweb / Multiple / Apps) from the cached user context."""
    context = await fetch_user_context(api_key)
    for team in context.get('teams') or []:
        if str(team.get('team_id')) == str(team_id):
            for project in team.get('projects') or []:
                if str(project.get('project_id')) == str(project_id):
                    return project.get('platform_type') or ''
    return ''


async def _fetch_test_case(api_key: str, team_id: int, project_id: int, testcase_id: int,
                           sprint_id: Optional[int] = None, test_run_execution_run_id: Optional[int] = None) -> dict:
    """GET /v1/testcases/get; the endpoint names the project app_id and the sprint report_id."""
    params = {'team_id': team_id, 'app_id': project_id, 'testcase_id': testcase_id}
    if sprint_id is not None:
        params['report_id'] = sprint_id
    if test_run_execution_run_id:
        params['testRunsExecutionRunId'] = test_run_execution_run_id
    response = await make_api_request('GET', '/v1/testcases/get', api_key, params=params)
    # The endpoint's pass/fail counts span every sprint and run and are multiplied by its tag joins, so drop them.
    for row in (response.get('testCaseDetails') or []) if isinstance(response, dict) else []:
        if isinstance(row, dict):
            row.pop('total_pass_count', None)
            row.pop('total_fail_count', None)
    return response


def _is_json_test_data(test_data: str) -> bool:
    """True when the executor can read the test data: a JSON list or object."""
    try:
        return isinstance(json.loads(test_data), (list, dict))
    except ValueError:
        return False


def _agent_failed(error: str, message: str, test_case_updated: bool = False) -> dict:
    """A failed agent assignment fails the whole call; test_case_updated says whether the field changes were saved."""
    saved = ('The other test case changes were saved, so retrying the same call is safe. ' if test_case_updated
             else 'Nothing was saved. ')
    return {'status': 'failed', 'error': error, 'error_type': 'AgentAssignmentError',
            'message': saved + message, 'test_case_updated': test_case_updated}


async def _pick_agent(api_key, team_id, project_id, testcase_id, sprint_id, test_run_execution_run_id, platform_type):
    """Return (agent, failure) for a sprint test case before anything is saved. The API silently drops an
    agent whose platform does not match (status OK + warningMsg), so the platform is checked here first."""
    if not sprint_id:
        return None, _agent_failed('sprint_id is required for agent assignment',
                                   'Provide sprint_id together with assign_to_agent=True.')

    tc_params = {'teamId': str(team_id), 'appId': str(project_id), 'sprintId': str(sprint_id)}
    if test_run_execution_run_id:
        tc_params['testRunsExecutionRunId'] = str(test_run_execution_run_id)
    tc_resp = await make_api_request('GET', '/testpert/sprintTestCase/get', api_key, params=tc_params)
    if not (isinstance(tc_resp, dict) and tc_resp.get('status') == 'OK'):
        return None, _agent_failed('Could not fetch sprint test case data for agent assignment',
                                   'Testpert may not be enabled for this project, or the sprint_id is invalid.')

    tc_detail = next((t for t in tc_resp.get('testCaseDetails') or []
                      if str(t.get('test_case_id', '')) == str(testcase_id)), None)
    if tc_detail is None:
        return None, _agent_failed('Test case is not in this sprint',
                                   'Link the test case to the sprint before assigning it to an agent.')

    # The sprint listing flags each enabled agent user as is_<agent>_enabled.
    agent_ids = {}
    for member in tc_resp.get('teamMembersDetails') or []:
        if str(member.get('type') or member.get('user_type') or '').upper() != 'AGENT':
            continue
        for agent in ('api_agent', 'browser_agent', 'mobile_agent'):
            if str(member.get(f'is_{agent}_enabled')) == '1':
                agent_ids.setdefault(agent, str(member.get('user_id', '')))

    tc_platform = str(platform_type or tc_detail.get('platform_type') or '').upper()
    if str(tc_detail.get('is_api_test_case') or '0') == '1':
        agent, label = 'api_agent', 'API Agent'
    elif tc_platform in BROWSER_AGENT_PLATFORM_TYPES:
        agent, label = 'browser_agent', 'Browser Agent'
    elif tc_platform in MOBILE_AGENT_PLATFORM_TYPES:
        agent, label = 'mobile_agent', 'Mobile Agent'
    else:
        return None, _agent_failed(
            f"No agent runs test cases with platform type '{tc_platform or 'not set'}'",
            "Call again with platform_type='DESKTOP_WEB' for the Browser Agent, or a mobile platform type "
            "(ANDROID, ANDROID_MOBILE_WEB, IOS, IOS_MOBILE_WEB) for the Mobile Agent.")

    if not agent_ids.get(agent):
        return None, _agent_failed(f'The {label} is not enabled for this project',
                                   f'Enable the {label} in the project settings before assigning.')
    return {'user_id': agent_ids[agent], 'label': label}, None


async def _assign_to_agent(api_key, team_id, project_id, testcase_id, sprint_id, test_run_execution_run_id, agent) -> dict:
    """Assign the sprint test case to the agent _pick_agent chose; runs after the field update was saved."""
    label = agent['label']
    logger.info(f"Assigning testcase_id={testcase_id} to the {label} in sprint_id={sprint_id}")
    agent_payload = {
        'appId': str(project_id),
        'teamId': str(team_id),
        'sprintId': str(sprint_id),
        'testCaseId': str(testcase_id),
        'executionStatus': 'NEW',
        'isTestAgentEnabled': '1',
        'isTestCaseAssigneesUpdate': '1',
        'testCaseAssignees': agent['user_id'],
    }
    if test_run_execution_run_id:
        agent_payload['testRunsExecutionRunId'] = str(test_run_execution_run_id)
    agent_resp = await make_api_request('POST', '/testpert/sprintTestCase/update', api_key, data=agent_payload)
    if not isinstance(agent_resp, dict) or agent_resp.get('status') != 'OK':
        return _agent_failed(f'Could not assign the test case to the {label}',
                             (agent_resp.get('message') if isinstance(agent_resp, dict) else '') or 'The assignment was rejected.',
                             test_case_updated=True)
    # warningMsg means the API dropped the agent from the assignees.
    if str(agent_resp.get('warningMsg') or '0') == '1':
        return _agent_failed(f'The {label} was not assigned', agent_resp.get('message') or '', test_case_updated=True)
    # Runs copy the sprint's assignee and executor flag only when they are created.
    scope = ('this test run' if test_run_execution_run_id else
             'test runs created from now on; pass test_run_execution_run_id to assign it in an existing run')
    return {'status': 'OK', 'agent': label, 'message': f'Assigned to the {label} for {scope}.'}


async def _update_sprint_test_case_status(api_key, team_id, project_id, testcase_id, sprint_id, test_run_execution_run_id,
                                          execution_status=None, test_case_status=None) -> dict:
    """Set the status of a test case in a sprint, or in one of its runs, as the web app's status dropdown does."""
    scope = f"test run {test_run_execution_run_id}" if test_run_execution_run_id else f"sprint {sprint_id}"
    payload = {'teamId': team_id, 'appId': project_id, 'sprintId': sprint_id, 'testCaseId': testcase_id}
    if execution_status is not None:
        payload['executionStatus'] = execution_status
    if test_case_status is not None:
        payload['testCaseStatus'] = test_case_status
    if test_run_execution_run_id:
        payload['testRunsExecutionRunId'] = test_run_execution_run_id
    logger.info(f"Setting the status of testcase_id={testcase_id} in {scope}: "
                f"execution_status={execution_status}, test_case_status={test_case_status}")
    response = await make_api_request('POST', '/testpert/sprintTestCase/update', api_key, data=payload)
    if not (isinstance(response, dict) and response.get('status') == 'OK'):
        logger.error(f"_update_sprint_test_case_status: update failed for testcase_id={testcase_id} in {scope}: "
                     f"{response.get('message') if isinstance(response, dict) else response}")
        hint = f"Check that test case {testcase_id} is in {scope}."
        if execution_status == 'COMPLETED':
            # The API counts only the results reported in that run (or sprint) for this check.
            hint += (f" COMPLETED needs a PASS or FAIL reported in {scope} first: bugasura_report_test_case_result "
                     "with the same sprint_id and test_run_execution_run_id.")
        upstream = (response.get('message') if isinstance(response, dict) else '') or ''
        return {'status': 'failed', 'error': f"Could not update the status of test case {testcase_id} in {scope}",
                'error_type': 'APIError', 'message': f"{upstream} {hint}".strip()}

    details = response.get('testCaseDetails')
    row = (details[0] if isinstance(details, list) and details else details) if details else {}
    row = row if isinstance(row, dict) else {}
    out = {'status': 'OK', 'message': f"Updated the status of test case {testcase_id} in {scope}",
           'testcase_id': testcase_id, 'sprint_id': sprint_id}
    if test_run_execution_run_id:
        out['test_run_execution_run_id'] = test_run_execution_run_id
    if execution_status is not None:
        out['execution_status'] = row.get('execution_status') or execution_status
    if test_case_status is not None:
        out['test_case_status'] = row.get('test_case_status') or test_case_status
    return out


def _normalise_steps(steps):
    """Return steps as the JSON string the update endpoint validates. The GET endpoint returns
    the actions joined by new lines, so plain text is turned back into one step per line."""
    if not steps:
        return ''
    if isinstance(steps, str):
        try:
            parsed = json.loads(steps)
        except ValueError:
            parsed = None
        # Only a JSON list is a step list; any other text, even "123", is one step per line.
        steps = parsed if isinstance(parsed, list) else [line.strip() for line in steps.splitlines() if line.strip()]
    return json.dumps([s if isinstance(s, dict) else {'step': str(i), 'action': s, 'execution_status': ''} for i, s in enumerate(steps, 1)])


def _test_data_text(test_data) -> str:
    """Test data as the string the API stores; a list or dict is sent as JSON."""
    if test_data is None or test_data == '':
        return ''
    return test_data if isinstance(test_data, str) else json.dumps(test_data)
