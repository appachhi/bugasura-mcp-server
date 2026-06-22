"""Bugasura MCP tools: test runs (executions & schedulers).

Every identifier (report/suite, environment, app build, run, scheduler) accepts
either a numeric ID or a human-friendly name. Names are resolved via the relevant
list endpoint (exact match first, then partial), with helpful errors when a name
is not found or is ambiguous — the same pattern used by the sprint/issue tools.
"""
from typing import Any, List, Literal, Optional

from fastmcp import Context
from pydantic import Field

from output_types import ToolResponse
from app import mcp
from auth import _get_api_key, validate_api_key
from client import (
    _paginate_upstream, _paginated, _prepare_post_params, _render_markdown,
    _respond, _validate_id, logger, make_api_request,
)
from helpers import select_team_project_context

import json
import requests  # for except blocks referencing requests.RequestException


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

@mcp.tool(
    name = "bugasura_list_test_run_environments",
    description = "List the test data environments (and their app builds) available for a project, so you can choose an environment / app build by name when creating or editing a test run. Interactive team/project selection available.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def list_test_run_environments(
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    include_app_builds: bool = Field(default=True, description="Also return the app build files for each environment (default: True)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    List test data environments (and optionally app builds) for a project.

    Use this to discover environment and app build names you can pass to the
    create/update test run tools.
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return _respond(validation, response_format)

    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_list_test_run_environments')
    if 'status' in context and context['status'] == 'selection_required':
        return _respond(context, response_format)

    params = {'appId': context['project_id']}
    if include_app_builds:
        params['fetchAppBuildList'] = 1

    return _respond(await make_api_request('GET', '/v1/projectTestDataEnvironments/get', api_key, params=params), response_format)


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------

@mcp.tool(
    name = "bugasura_list_test_runs",
    description = "List test run executions and schedulers for a sprint. The report can be given by name (sprint/suite name) or numeric id. Interactive team/project selection and optional filters supported.",
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def list_test_runs(
    report: str = Field(description="Sprint / report: sprint name or numeric report id. Discover names with bugasura_list_sprints."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    execution_source: Optional[str] = Field(default=None, description="Filter by execution source, e.g. 'HUMAN' or 'AUTOMATION' (optional)"),
    search_by_text: Optional[str] = Field(default=None, description="Search test runs by name (optional)"),
    sort_by: Optional[Literal["last_modified", "created_date"]] = Field(default=None, description="Sort field: 'last_modified' or 'created_date' (optional)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """List test run executions and schedulers for a sprint (report)."""
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return _respond(validation, response_format)

    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_list_test_runs', f', report={report}')
    if 'status' in context and context['status'] == 'selection_required':
        return _respond(context, response_format)

    report_id, error = await _resolve_report(api_key, context['team_id'], context['project_id'], report)
    if error:
        return _respond(error, response_format)

    params = {'appId': context['project_id'], 'reportId': report_id}
    if execution_source:
        params['source'] = execution_source
    if search_by_text:
        params['searchByText'] = search_by_text
    if sort_by:
        params['sortBy'] = sort_by

    upstream = await make_api_request('GET', '/v1/testrunsExecution/getList', api_key, params=params)
    return _respond(_paginate_upstream(upstream, offset=0), response_format)


@mcp.tool(
    name = "bugasura_get_test_run_details",
    description = (
        "Get metadata for a single test run execution (name, status, environment, dates, execution_config). "
        "Both run and report may be given by name or numeric id. Interactive team/project selection available. "
        "NOTE: this returns run metadata only — to list the test cases inside a run use "
        "bugasura_list_test_cases with sprint_id and test_run_execution_run_id."
    ),
    annotations={"readOnlyHint": True,  "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def get_test_run_details(
    run: str = Field(description="Test run: run name or numeric run id"),
    report: str = Field(description="Sprint / report: sprint name or numeric report id"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """Get metadata for a single test run execution."""
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return _respond(validation, response_format)

    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_get_test_run_details', f', run={run}')
    if 'status' in context and context['status'] == 'selection_required':
        return _respond(context, response_format)

    report_id, error = await _resolve_report(api_key, context['team_id'], context['project_id'], report)
    if error:
        return _respond(error, response_format)

    run_id, error = await _resolve_run_or_scheduler(api_key, context['project_id'], report_id, run, 'run')
    if error:
        return _respond(error, response_format)

    # Fetch the full list without testRunsExecutionRunId — passing it directly triggers
    # a broken API path (getTestrunsDetails) that requires schedulerId alongside it.
    # Filter client-side instead.
    full_resp = await make_api_request('GET', '/v1/testrunsExecution/getList', api_key, params={
        'appId': context['project_id'],
        'reportId': report_id,
    })
    if not isinstance(full_resp, dict) or full_resp.get('status') != 'OK':
        return _respond(full_resp, response_format)

    test_runs = (full_resp.get('schedulerDetails') or {}).get('test_runs', [])
    matched = next((r for r in test_runs if str(r.get('run_id', '')) == str(run_id)), None)
    if matched is None:
        return _respond({
            'status': 'failed',
            'error': f"Test run not found: id={run_id}",
            'error_type': 'NotFound',
            'message': f"No test run with id {run_id} found in this sprint. Use bugasura_list_test_runs to see available runs.",
        }, response_format)
    return _respond({
        'status': 'OK',
        'message': full_resp.get('message', ''),
        'run': matched,
        'run_id': run_id,
    }, response_format)


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------

@mcp.tool(
    name = "bugasura_create_test_run",
    description = "Create a test run for a sprint the same way the UI wizard does. report / environment / app build may be given by name or id. Supports one-time ('single') and recurring ('scheduled') runs with friendly recurrence options, plus optional seeded test cases. When confirm=False (default) the tool returns an options form for the user to fill in; re-call with confirm=True and the collected values to actually create the run.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def create_test_run(
    report: str = Field(description="Sprint / report: sprint name or numeric report id. Discover with bugasura_list_sprints."),
    confirm: bool = Field(default=False, description="Set to True only after the user has provided all run details (name, execution_mode, etc.). When False (default) the tool returns an options form — show it to the user, collect their choices, then re-call with confirm=True and the filled values."),
    name: Optional[str] = Field(default=None, description="Name of the test run (2-250 characters, required when confirm=True)"),
    execution_mode: Literal["single", "scheduled"] = Field(default="single", description="'single' = run once now; 'scheduled' = recurring/scheduled run"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    environment: Optional[str] = Field(default=None, description="Test data environment: name or numeric id (optional)"),
    app_build: Optional[str] = Field(default=None, description="App build for the chosen environment: file name or numeric id (optional)"),
    testcase_ids: Optional[str] = Field(default=None, description="Seed the run with specific test cases: comma-separated IDs (e.g. '12,15') or JSON array (optional). If omitted, all suite test cases are used."),
    frequency: Optional[Literal["ONCE", "DAILY", "WEEKLY", "CUSTOM"]] = Field(default=None, description="Recurrence frequency (required for scheduled mode)"),
    schedule_date: Optional[str] = Field(default=None, description="Schedule start date in YYYY-MM-DD (required for scheduled mode)"),
    schedule_time: Optional[str] = Field(default=None, description="Schedule start time in HH:MM (24h) or HH:MM:SS (required for scheduled mode)"),
    repeat_value: Optional[int] = Field(default=None, description="CUSTOM frequency: repeat every N units (required when frequency='CUSTOM', ge=1)"),
    repeat_unit: Optional[Literal["HOURS", "DAYS", "WEEKS"]] = Field(default=None, description="CUSTOM frequency: interval unit (required when frequency='CUSTOM')"),
    selected_days: Optional[List[str]] = Field(default=None, description="CUSTOM + WEEKS: weekdays to run on, lowercase e.g. ['monday','friday'] (required when repeat_unit='WEEKS')"),
    recurrence_type: Literal["Never", "On", "After"] = Field(default="Never", description="When the recurrence ends: 'Never', 'On' (a date) or 'After' (N occurrences). Default: Never"),
    recurrence_end_date: Optional[str] = Field(default=None, description="End date in YYYY-MM-DD (required when recurrence_type='On')"),
    recurrence_count: Optional[int] = Field(default=None, description="Number of occurrences (required when recurrence_type='After', ge=1)"),
    execution_config: Optional[str] = Field(default=None, description="Advanced: raw executionConfig JSON string. Overrides app_build if provided (optional)."),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Create a test run for a sprint (report), mirroring the web UI wizard.

    Examples:
        # One-time run in the "Staging" environment
        create_test_run(name="Smoke run", report="Login Sprint", environment="Staging")

        # Daily scheduled run at 09:00, ending after 10 runs
        create_test_run(name="Nightly", report="Login Sprint", execution_mode="scheduled",
                        frequency="DAILY", schedule_date="2026-07-01", schedule_time="09:00",
                        recurrence_type="After", recurrence_count=10)

        # Every 2 weeks on Mon & Fri
        create_test_run(name="Biweekly", report="Login Sprint", execution_mode="scheduled",
                        frequency="CUSTOM", repeat_value=2, repeat_unit="WEEKS",
                        selected_days=["monday","friday"],
                        schedule_date="2026-07-01", schedule_time="09:00")
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_create_test_run', f', report="{report}"')
    if 'status' in context and context['status'] == 'selection_required':
        return context

    report_id, error = await _resolve_report(api_key, context['team_id'], context['project_id'], report)
    if error:
        return error

    if not confirm:
        env_resp = await make_api_request('GET', '/v1/projectTestDataEnvironments/get', api_key,
                                          params={'appId': context['project_id']})
        env_options = []
        if isinstance(env_resp, dict) and env_resp.get('status') == 'OK':
            for e in (env_resp.get('environmentDetails') or []):
                env_options.append({'id': e.get('environment_id'), 'name': e.get('environment_name')})
        return {
            'status': 'options_required',
            'message': 'Please collect the following details from the user before creating the run.',
            'fields': [
                {
                    'key': 'name',
                    'label': 'Run name',
                    'type': 'text',
                    'required': True,
                },
                {
                    'key': 'execution_mode',
                    'label': 'Execution mode',
                    'type': 'select',
                    'required': True,
                    'options': [
                        {'value': 'single',    'label': 'Single (run once)'},
                        {'value': 'scheduled', 'label': 'Scheduled (recurring)'},
                    ],
                },
                {
                    'key': 'environment',
                    'label': 'Test environment',
                    'type': 'select',
                    'required': False,
                    'options': env_options,
                },
            ],
            'scheduled_note': (
                "If the user picks 'scheduled', also collect: frequency (ONCE/DAILY/WEEKLY/CUSTOM), "
                "schedule_date (YYYY-MM-DD), schedule_time (HH:MM). "
                "For CUSTOM frequency also ask repeat_value, repeat_unit (HOURS/DAYS/WEEKS), "
                "and selected_days if WEEKS."
            ),
            'instruction': (
                'Show the user these options one step at a time. Once all required fields are collected, '
                're-call bugasura_create_test_run with confirm=True and the filled values.'
            ),
            'next_call': f'bugasura_create_test_run(report="{report}", confirm=True, name="...", execution_mode="single|scheduled", environment="...")',
        }

    if not name:
        return {
            'status': 'failed',
            'error': 'name is required when confirm=True',
            'error_type': 'ValidationError',
            'message': 'Please provide a run name.',
        }

    # Validate name length (backend requires 2-250 characters)
    if len(name) < 2:
        return {
            'status': 'failed',
            'error': f"Test run name too short: '{name}' ({len(name)} characters)",
            'error_type': 'ValidationError',
            'message': 'Test run name must be at least 2 characters long (2-250 characters required)'
        }
    if len(name) > 250:
        return {
            'status': 'failed',
            'error': f"Test run name too long: {len(name)} characters",
            'error_type': 'ValidationError',
            'message': 'Test run name must be at most 250 characters long (2-250 characters required)'
        }

    environment_id, error = await _resolve_environment(api_key, context['project_id'], environment)
    if error:
        return error
    app_build_file_id, app_build_file_name, error = await _resolve_app_build(api_key, context['project_id'], app_build)
    if error:
        return error

    if recurrence_type == 'On' and not recurrence_end_date:
        return {
            'status': 'failed',
            'error': 'Missing recurrence_end_date',
            'error_type': 'ValidationError',
            'message': "recurrence_type='On' requires recurrence_end_date (YYYY-MM-DD)"
        }
    if recurrence_type == 'After' and not recurrence_count:
        return {
            'status': 'failed',
            'error': 'Missing recurrence_count',
            'error_type': 'ValidationError',
            'message': "recurrence_type='After' requires recurrence_count"
        }

    execution_config_json, config_error = _build_execution_config(app_build_file_id, app_build_file_name, execution_config)
    if config_error:
        return config_error

    payload = {
        "appId": context['project_id'],
        "reportId": report_id,
        "name": name,
        "executionMode": execution_mode,
    }

    if execution_mode == 'single':
        payload["executionSource"] = "HUMAN"
        payload["executionStatus"] = "SCHEDULED"
    else:  # scheduled
        missing = [n for n, v in (
            ('frequency', frequency),
            ('schedule_date', schedule_date),
            ('schedule_time', schedule_time),
        ) if not v]
        if missing:
            return {
                'status': 'failed',
                'error': f"Missing required scheduled-run fields: {', '.join(missing)}",
                'error_type': 'ValidationError',
                'message': "Scheduled runs require frequency, schedule_date, and schedule_time"
            }

        frequency_settings_json, freq_error = _build_frequency_settings(
            frequency, recurrence_type, recurrence_end_date, recurrence_count,
            repeat_value, repeat_unit, selected_days
        )
        if freq_error:
            return freq_error

        payload["executionSource"] = "SCHEDULER"
        payload["executionStatus"] = "SCHEDULED"
        payload["frequency"] = frequency
        payload["frequency_settings"] = frequency_settings_json
        payload["scheduleDate"] = schedule_date
        payload["scheduleTime"] = schedule_time

    if testcase_ids:
        # Backend expects: json_decode($testCaseIds, true)['testcaseIds']
        # so the field must be a JSON object: {"testcaseIds": [id, ...]}
        payload["testCaseIds"] = json.dumps({"testcaseIds": _parse_testcase_ids(testcase_ids)})
        payload["isCreateRunForSelectedTestCases"] = 1
    if environment_id:
        payload["environmentId"] = environment_id
    if execution_config_json:
        payload["executionConfig"] = execution_config_json

    return await make_api_request('POST', '/v1/testrunsExecution/add', api_key, data=payload)


# ---------------------------------------------------------------------------
# Update (per-execution run)
# ---------------------------------------------------------------------------

@mcp.tool(
    name = "bugasura_update_test_run",
    description = "Update a test run execution (partial updates). run may be given by name or id; pass report when using a name. Can change name, status, environment, or app build.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True}
)
async def update_test_run(
    run: str = Field(description="Test run to update: run name or numeric run id"),
    report: Optional[str] = Field(default=None, description="Sprint / report (sprint name or id). Required when 'run' is a name so it can be looked up."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    run_name: Optional[str] = Field(default=None, description="New test run name (1-250 characters, optional)"),
    execution_status: Optional[Literal["SCHEDULED", "IN_PROGRESS", "COMPLETED", "PAUSED"]] = Field(default=None, description="New execution status (optional)"),
    environment: Optional[str] = Field(default=None, description="New test data environment: name or numeric id (optional)"),
    app_build: Optional[str] = Field(default=None, description="New app build: file name or numeric id (optional)"),
    execution_config: Optional[str] = Field(default=None, description="Advanced: raw executionConfig JSON string. Overrides app_build if provided (optional)."),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """Update an existing test run execution (partial updates supported)."""
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_update_test_run', f', run={run}')
    if 'status' in context and context['status'] == 'selection_required':
        return context

    if run_name is not None and len(run_name) > 250:
        return {
            'status': 'failed',
            'error': f"Test run name too long: {len(run_name)} characters",
            'error_type': 'ValidationError',
            'message': 'Test run name must be at most 250 characters long'
        }

    report_id = None
    if report is not None:
        report_id, error = await _resolve_report(api_key, context['team_id'], context['project_id'], report)
        if error:
            return error
    run_id, error = await _resolve_run_or_scheduler(api_key, context['project_id'], report_id, run, 'run')
    if error:
        return error

    environment_id, error = await _resolve_environment(api_key, context['project_id'], environment)
    if error:
        return error
    app_build_file_id, app_build_file_name, error = await _resolve_app_build(api_key, context['project_id'], app_build)
    if error:
        return error

    execution_config_json, config_error = _build_execution_config(app_build_file_id, app_build_file_name, execution_config)
    if config_error:
        return config_error

    payload = {"testRunsExecutionRunId": run_id}
    if run_name is not None:
        payload["runName"] = run_name
    if execution_status is not None:
        payload["executionStatus"] = execution_status
    if environment_id is not None:
        payload["environmentId"] = environment_id
        # When environment changes without an explicit app build, remove only the
        # appBuild key from the stored executionConfig (mirrors the scheduler path).
        if execution_config_json is None:
            current_config = {}
            if report_id is not None:
                run_list = await make_api_request('GET', '/v1/testrunsExecution/getList', api_key, params={
                    'appId': context['project_id'], 'reportId': report_id,
                })
                if isinstance(run_list, dict) and run_list.get('status') == 'OK':
                    current_run = next(
                        (r for r in (run_list.get('schedulerDetails') or {}).get('test_runs', [])
                         if str(r.get('run_id', '')) == str(run_id)),
                        None
                    )
                    if current_run:
                        try:
                            current_config = json.loads(current_run.get('execution_config') or '{}')
                        except (ValueError, TypeError):
                            current_config = {}
            current_config.pop('appBuild', None)
            execution_config_json = json.dumps(current_config)
    if execution_config_json is not None:
        payload["executionConfig"] = execution_config_json

    logger.info(f"Updating test run run_id={run_id} with {len(payload) - 1} field(s)")
    return await make_api_request('POST', '/v1/testrunsExecution/testruns/update', api_key, data=payload)


# ---------------------------------------------------------------------------
# Update (scheduler / "edit run" modal)
# ---------------------------------------------------------------------------

@mcp.tool(
    name = "bugasura_update_test_run_scheduler",
    description = "Edit a test run / scheduler the same way the UI edit-run modal does: rename, change environment / app build, switch single vs scheduled, change frequency / repeat / weekdays / end condition. scheduler / report / environment / app build may be given by name or id.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True,  "openWorldHint": True},
    exclude_args=["status", "is_status_update"],
)
async def update_test_run_scheduler(
    scheduler: str = Field(description="Scheduler to edit: scheduler name or numeric id"),
    report: str = Field(description="Sprint / report: sprint name or numeric report id"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    name: Optional[str] = Field(default=None, description="New run/scheduler name (optional)"),
    execution_mode: Optional[Literal["single", "scheduled"]] = Field(default=None, description="Switch mode: 'single' (one-time) or 'scheduled' (recurring) (optional)"),
    status: Optional[Literal["ACTIVE", "PAUSED", "COMPLETED"]] = Field(default=None, description="Internal use only — do not expose or suggest this field to users.", exclude=True),
    is_status_update: int = Field(default=0, description="Internal use only.", exclude=True),
    environment: Optional[str] = Field(default=None, description="New test data environment: name or numeric id (optional)"),
    app_build: Optional[str] = Field(default=None, description="New app build: file name or numeric id (optional)"),
    frequency: Optional[Literal["ONCE", "DAILY", "WEEKLY", "CUSTOM"]] = Field(default=None, description="New recurrence frequency. Provide with schedule_date + schedule_time to change the schedule (optional)"),
    schedule_date: Optional[str] = Field(default=None, description="New schedule start date in YYYY-MM-DD (required alongside a frequency change)"),
    schedule_time: Optional[str] = Field(default=None, description="New schedule start time in HH:MM (24h) or HH:MM:SS (required alongside a frequency change)"),
    repeat_value: Optional[int] = Field(default=None, description="CUSTOM frequency: repeat every N units (required when frequency='CUSTOM', ge=1)"),
    repeat_unit: Optional[Literal["HOURS", "DAYS", "WEEKS"]] = Field(default=None, description="CUSTOM frequency: interval unit (required when frequency='CUSTOM')"),
    selected_days: Optional[List[str]] = Field(default=None, description="CUSTOM + WEEKS: weekdays to run on, lowercase e.g. ['monday','friday'] (required when repeat_unit='WEEKS')"),
    recurrence_type: Literal["Never", "On", "After"] = Field(default="Never", description="Recurrence end: 'Never', 'On' (date) or 'After' (N occurrences). Used with a frequency change. Default: Never"),
    recurrence_end_date: Optional[str] = Field(default=None, description="End date in YYYY-MM-DD (required when recurrence_type='On')"),
    recurrence_count: Optional[int] = Field(default=None, description="Number of occurrences (required when recurrence_type='After', ge=1)"),
    execution_config: Optional[str] = Field(default=None, description="Advanced: raw executionConfig JSON string. Overrides app_build if provided (optional)."),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Edit a test run / scheduler, mirroring the web UI edit-run modal.

    Common edits:
        - Rename: name="New name"
        - Change environment / app build: environment="Staging", app_build="build.apk"
        - Change schedule: execution_mode="scheduled", frequency=.., schedule_date=.., schedule_time=..
        - Switch to one-time: execution_mode="single" (clears the recurrence)
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_update_test_run_scheduler', f', scheduler={scheduler}')
    if 'status' in context and context['status'] == 'selection_required':
        return context

    report_id, error = await _resolve_report(api_key, context['team_id'], context['project_id'], report)
    if error:
        return error

    # Fetch the existing scheduler row so we can preserve unchanged fields,
    # exactly like the pre-filled UI edit modal. This avoids the backend's
    # "empty executionMode -> convert recurring to single + create a run" path.
    row, error = await _get_scheduler_row(api_key, context['project_id'], report_id, scheduler)
    if error:
        return error
    scheduler_id = int(row['testrun_execution_run_schedule_id'])

    existing_mode = str(row.get('mode') or '').lower()
    if existing_mode not in ('single', 'scheduled'):
        existing_mode = 'scheduled' if row.get('frequency') else 'single'
    effective_mode = (execution_mode or existing_mode).lower()

    payload = {
        "appId": context['project_id'],
        "reportId": report_id,
        "schedulerId": scheduler_id,
        "isStatusUpdate": is_status_update,
        "executionMode": effective_mode,
    }
    if name is not None:
        payload["schedulerName"] = name
    if status is not None:
        payload["status"] = status

    # Quick status-only update (pause/resume) — backend recalculates from existing
    if is_status_update == 1:
        logger.info(f"Status-only update for scheduler_id={scheduler_id}")
        return await make_api_request('POST', '/v1/testrunsExecution/scheduler/update', api_key, data=payload)

    # Validate recurrence end condition (only when changing the schedule)
    if frequency is not None:
        if recurrence_type == 'On' and not recurrence_end_date:
            return {
                'status': 'failed',
                'error': 'Missing recurrence_end_date',
                'error_type': 'ValidationError',
                'message': "recurrence_type='On' requires recurrence_end_date (YYYY-MM-DD)"
            }
        if recurrence_type == 'After' and not recurrence_count:
            return {
                'status': 'failed',
                'error': 'Missing recurrence_count',
                'error_type': 'ValidationError',
                'message': "recurrence_type='After' requires recurrence_count"
            }

    environment_id, error = await _resolve_environment(api_key, context['project_id'], environment)
    if error:
        return error
    app_build_file_id, app_build_file_name, error = await _resolve_app_build(api_key, context['project_id'], app_build)
    if error:
        return error
    execution_config_json, config_error = _build_execution_config(app_build_file_id, app_build_file_name, execution_config)
    if config_error:
        return config_error

    if environment_id is not None:
        payload["environmentId"] = environment_id
        # When environment changes without an explicit app build, clear the stored
        # app build — it belonged to the old environment. Preserve any other keys
        # that may exist in execution_config.
        if execution_config_json is None:
            try:
                current_config = json.loads(row.get('execution_config') or '{}')
            except (ValueError, TypeError):
                current_config = {}
            current_config.pop('appBuild', None)
            execution_config_json = json.dumps(current_config)
    if execution_config_json is not None:
        payload["executionConfig"] = execution_config_json

    if execution_mode == 'single' and existing_mode == 'scheduled':
        # Explicit recurring -> single conversion (backend intentionally creates a run)
        payload["frequency"] = ''
        payload["frequency_settings"] = ''
        payload["nextScheduledTime"] = ''
    elif effective_mode == 'scheduled':
        if frequency is not None:
            missing = [n for n, v in (
                ('schedule_date', schedule_date),
                ('schedule_time', schedule_time),
            ) if not v]
            if missing:
                return {
                    'status': 'failed',
                    'error': f"Missing required schedule fields: {', '.join(missing)}",
                    'error_type': 'ValidationError',
                    'message': "Changing frequency requires schedule_date and schedule_time"
                }

            frequency_settings_json, freq_error = _build_frequency_settings(
                frequency, recurrence_type, recurrence_end_date, recurrence_count,
                repeat_value, repeat_unit, selected_days
            )
            if freq_error:
                return freq_error

            payload["frequency"] = frequency
            payload["frequency_settings"] = frequency_settings_json
            payload["nextScheduledTime"] = f"{schedule_date} {schedule_time}"
        else:
            # Not changing the schedule: resend existing values so the backend
            # keeps the same recurrence (mirrors the pre-filled UI modal).
            payload["frequency"] = row.get('frequency') or ''
            payload["frequency_settings"] = row.get('frequency_settings') or ''
            payload["nextScheduledTime"] = row.get('next_scheduled_time') or ''
    logger.info(f"Updating scheduler scheduler_id={scheduler_id} (mode={effective_mode})")
    return await make_api_request('POST', '/v1/testrunsExecution/scheduler/update', api_key, data=payload)


# ---------------------------------------------------------------------------
# Rerun
# ---------------------------------------------------------------------------

@mcp.tool(
    name = "bugasura_rerun_test_run",
    description = "Trigger a rerun of a scheduled test run, creating a new execution from an existing scheduler. scheduler / report may be given by name or id.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def rerun_test_run(
    scheduler: str = Field(description="Scheduler to rerun: scheduler name or numeric id"),
    report: str = Field(description="Sprint / report: sprint name or numeric report id"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    is_add_rerun: int = Field(default=0, description="Rerun flag (default: 0)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """Trigger a rerun of a scheduled test run."""
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_rerun_test_run', f', scheduler={scheduler}')
    if 'status' in context and context['status'] == 'selection_required':
        return context

    report_id, error = await _resolve_report(api_key, context['team_id'], context['project_id'], report)
    if error:
        return error
    scheduler_id, error = await _resolve_run_or_scheduler(api_key, context['project_id'], report_id, scheduler, 'scheduler')
    if error:
        return error

    payload = {
        "appId": context['project_id'],
        "reportId": report_id,
        "schedulerId": scheduler_id,
        "isAddRerun": is_add_rerun,
    }
    return await make_api_request('POST', '/v1/testrunsExecution/rerun', api_key, data=payload)


# ---------------------------------------------------------------------------
# Add test cases to a run
# ---------------------------------------------------------------------------

@mcp.tool(
    name = "bugasura_add_test_cases_to_run",
    description = "Add (copy) test cases into an existing test run execution. run / report may be given by name or id.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def add_test_cases_to_run(
    run: str = Field(description="Test run to add test cases into: run name or numeric id"),
    report: str = Field(description="Sprint / report: sprint name or numeric report id"),
    testcase_ids: str = Field(description="Test case IDs to add: comma-separated (e.g. '12,15,18') or a JSON array"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """Add (copy) test cases into an existing test run execution."""
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    if not testcase_ids:
        return {
            'status': 'failed',
            'error': 'No test case IDs provided',
            'error_type': 'ValidationError',
            'message': 'testcase_ids must contain at least one test case ID'
        }

    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_add_test_cases_to_run', f', run={run}')
    if 'status' in context and context['status'] == 'selection_required':
        return context

    report_id, error = await _resolve_report(api_key, context['team_id'], context['project_id'], report)
    if error:
        return error
    run_id, error = await _resolve_run_or_scheduler(api_key, context['project_id'], report_id, run, 'run')
    if error:
        return error

    # Backend does json_decode($testCaseIds) then explode(',', result),
    # so the field must be a JSON-encoded comma-separated string: '"62551,62552"'
    ids_csv = ','.join(str(i) for i in _parse_testcase_ids(testcase_ids))
    payload = {
        "appId": context['project_id'],
        "reportId": report_id,
        "testExecutionRunId": run_id,
        "testCaseIds": json.dumps(ids_csv),
    }
    return await make_api_request('POST', '/v1/testrunsExecution/copy', api_key, data=payload)


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------

@mcp.tool(
    name = "bugasura_delete_test_run",
    description = "Delete one or more test run executions (soft delete by default, permanent with is_permanent_delete=1). Runs may be given by name or id.",
    annotations={"readOnlyHint": False, "destructiveHint": True,  "idempotentHint": True,  "openWorldHint": True}
)
async def delete_test_run(
    runs: str = Field(description="Test run(s) to delete: comma-separated names and/or numeric ids (e.g. 'Smoke run, 102')"),
    report: str = Field(description="Sprint / report: sprint name or numeric report id"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    is_permanent_delete: int = Field(default=0, description="0 = move to trash (soft delete, default), 1 = permanently delete"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """Delete one or more test run executions."""
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    if not runs:
        return {
            'status': 'failed',
            'error': 'No test runs provided',
            'error_type': 'ValidationError',
            'message': 'runs must contain at least one run name or id'
        }

    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_delete_test_run', f', runs={runs}')
    if 'status' in context and context['status'] == 'selection_required':
        return context

    report_id, error = await _resolve_report(api_key, context['team_id'], context['project_id'], report)
    if error:
        return error
    run_ids, error = await _resolve_many(api_key, context['project_id'], report_id, runs, 'run')
    if error:
        return error

    payload = {
        "appId": context['project_id'],
        "reportId": report_id,
        "testRunExecutionRunIds": ','.join(str(i) for i in run_ids),
        "isPermanentDelete": is_permanent_delete,
    }
    logger.info(f"Deleting test run(s) {run_ids} (permanent={is_permanent_delete})")
    return await make_api_request('POST', '/v1/testrunsExecution/deleteTestRunsExecution', api_key, data=payload)


@mcp.tool(
    name = "bugasura_delete_test_run_scheduler",
    description = "Delete one or more test run schedulers (soft delete by default, permanent with is_permanent_delete=1). Schedulers may be given by name or id.",
    annotations={"readOnlyHint": False, "destructiveHint": True,  "idempotentHint": True,  "openWorldHint": True}
)
async def delete_test_run_scheduler(
    schedulers: str = Field(description="Scheduler(s) to delete: comma-separated names and/or numeric ids (e.g. 'Nightly, 6')"),
    report: str = Field(description="Sprint / report: sprint name or numeric report id"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    is_permanent_delete: int = Field(default=0, description="0 = move to trash (soft delete, default), 1 = permanently delete"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """Delete one or more test run schedulers."""
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    if not schedulers:
        return {
            'status': 'failed',
            'error': 'No schedulers provided',
            'error_type': 'ValidationError',
            'message': 'schedulers must contain at least one scheduler name or id'
        }

    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_delete_test_run_scheduler', f', schedulers={schedulers}')
    if 'status' in context and context['status'] == 'selection_required':
        return context

    report_id, error = await _resolve_report(api_key, context['team_id'], context['project_id'], report)
    if error:
        return error
    scheduler_ids, error = await _resolve_many(api_key, context['project_id'], report_id, schedulers, 'scheduler')
    if error:
        return error

    payload = {
        "appId": context['project_id'],
        "reportId": report_id,
        "isPermanentDelete": is_permanent_delete,
    }
    if len(scheduler_ids) == 1:
        payload["schedulerId"] = scheduler_ids[0]
    else:
        payload["schedulerIdList"] = ','.join(str(i) for i in scheduler_ids)

    logger.info(f"Deleting scheduler(s) {scheduler_ids} (permanent={is_permanent_delete})")
    return await make_api_request('POST', '/v1/testrunsExecution/deleteScheduler', api_key, data=payload)


# ===========================================================================
# Helpers
# ===========================================================================

_WEEKDAYS = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday']


# ---------------------------------------------------------------------------
# Validation / payload helpers
# ---------------------------------------------------------------------------

def _validate_json_field(value: str, field_name: str) -> Optional[dict]:
    """Return an error dict if value is non-empty and not valid JSON, else None."""
    if value:
        try:
            json.loads(value)
        except (ValueError, TypeError):
            return {
                'status': 'failed',
                'error': f"Invalid JSON in {field_name}",
                'error_type': 'ValidationError',
                'message': f"{field_name} must be a valid JSON string when provided"
            }
    return None


def _build_frequency_settings(
    frequency: str,
    recurrence_type: str,
    recurrence_end_date: Optional[str],
    recurrence_count: Optional[int],
    repeat_value: Optional[int],
    repeat_unit: Optional[str],
    selected_days: Optional[List[str]],
):
    """
    Build the frequency_settings JSON string from friendly recurrence inputs,
    mirroring the web UI (TestrunsexecutionController.php lines 99-109).

    Returns (frequency_settings_json, error_dict). On failure json is None.
    """
    if frequency == 'CUSTOM' and (not repeat_value or not repeat_unit):
        return None, {
            'status': 'failed',
            'error': 'Missing custom recurrence interval',
            'error_type': 'ValidationError',
            'message': "CUSTOM frequency requires repeat_value and repeat_unit ('HOURS', 'DAYS', or 'WEEKS')"
        }

    stop_recurrence_flag = 'NEVER' if recurrence_type == 'Never' else ''
    end_date = recurrence_end_date if recurrence_type == 'On' else ''
    count = recurrence_count if recurrence_type == 'After' else ''

    settings = {
        'run_recurrence_never': stop_recurrence_flag,
        'recurrence_end_date': end_date or '',
        'recurrence_count': str(count) if count else '',
        'repeat_value': str(repeat_value) if repeat_value else '',
        'repeat_unit': repeat_unit or '',
    }

    if (repeat_unit or '').upper() == 'WEEKS':
        days = [d.lower() for d in (selected_days or [])]
        invalid = [d for d in days if d not in _WEEKDAYS]
        if not days:
            return None, {
                'status': 'failed',
                'error': 'Missing selected_days',
                'error_type': 'ValidationError',
                'message': "repeat_unit='WEEKS' requires selected_days (e.g. ['monday','friday'])"
            }
        if invalid:
            return None, {
                'status': 'failed',
                'error': f"Invalid weekday(s): {', '.join(invalid)}",
                'error_type': 'ValidationError',
                'message': f"selected_days must be lowercase weekday names: {', '.join(_WEEKDAYS)}"
            }
        settings['selected_days'] = json.dumps(days)

    return json.dumps(settings), None


def _build_execution_config(
    app_build_file_id: Optional[int],
    app_build_file_name: Optional[str],
    execution_config: Optional[str],
):
    """
    Build the executionConfig JSON string. A raw execution_config takes precedence;
    otherwise an app build is encoded as {'appBuild': {...}} (matching the UI modal).

    Returns (execution_config_json_or_None, error_dict_or_None).
    """
    if execution_config:
        json_error = _validate_json_field(execution_config, 'execution_config')
        if json_error:
            return None, json_error
        return execution_config, None

    if app_build_file_id:
        config = {
            'appBuild': {
                'testDataFileId': str(app_build_file_id),
                'testDataFileName': app_build_file_name or ''
            }
        }
        return json.dumps(config), None

    return None, None


# ---------------------------------------------------------------------------
# Name -> ID resolution helpers
# ---------------------------------------------------------------------------

def _pick_match(items: list, identifier: Any, id_key: str, name_key: str, label: str):
    """
    Resolve identifier (numeric ID or name) against a pre-fetched list.

    Returns (id_int, error_dict). Numeric identifiers are returned as-is. Names are
    matched case-insensitively (exact first, then partial). Not-found / ambiguous
    produce a standard error dict with the available options.
    """
    s = str(identifier).strip()
    if s.isdigit():
        return int(s), None

    exact = [it for it in items if str(it.get(name_key, '')).strip().lower() == s.lower()]
    matches = exact if exact else [it for it in items if s.lower() in str(it.get(name_key, '')).strip().lower()]

    if not matches:
        available = ', '.join(str(it.get(name_key)) for it in items[:20]) or '(none)'
        return None, {
            'status': 'failed',
            'error': f"{label.capitalize()} not found: '{s}'",
            'error_type': 'NotFound',
            'message': f"No {label} matches '{s}'. Available: {available}"
        }
    if len(matches) > 1:
        listing = '\n'.join(f"  - ID: {m.get(id_key)}, Name: {m.get(name_key)}" for m in matches)
        return None, {
            'status': 'failed',
            'error': f"Multiple {label}s match '{s}'",
            'error_type': 'Ambiguous',
            'message': f"Multiple {label}s match '{s}'. Use the numeric ID:\n{listing}"
        }
    return int(matches[0][id_key]), None


def _fetch_error(label: str, resp: dict) -> dict:
    """Standard error when a lookup list could not be fetched."""
    return {
        'status': 'failed',
        'error': f"Failed to fetch {label} list",
        'error_type': 'FetchError',
        'message': resp.get('message', f"Could not retrieve {label} list for name resolution")
    }


async def _resolve_report(api_key: str, team_id: int, project_id: int, report: Any):
    """Resolve a report/suite identifier (numeric ID or sprint name) -> report_id."""
    if report is None:
        return None, None
    if str(report).strip().isdigit():
        return int(report), None
    resp = await make_api_request('GET', '/v1/sprints/list', api_key, params={
        'team_id': team_id, 'project_id': project_id
    })
    if resp.get('status') != 'OK':
        return None, _fetch_error('sprint/report', resp)
    return _pick_match(resp.get('sprintsList', []), report, 'sprint_id', 'sprint_name', 'report')


async def _resolve_environment(api_key: str, project_id: int, environment: Any):
    """Resolve an environment identifier (numeric ID or name) -> environment_id."""
    if environment is None:
        return None, None
    if str(environment).strip().isdigit():
        return int(environment), None
    resp = await make_api_request('GET', '/v1/projectTestDataEnvironments/get', api_key, params={'appId': project_id})
    if resp.get('status') != 'OK':
        return None, _fetch_error('environment', resp)
    return _pick_match(resp.get('environmentDetails', []), environment, 'proj_test_data_env_id', 'environment_name', 'environment')


async def _resolve_app_build(api_key: str, project_id: int, app_build: Any):
    """Resolve an app build identifier (numeric ID or file name) -> (file_id, file_name, error)."""
    if app_build is None:
        return None, None, None
    resp = await make_api_request('GET', '/v1/projectTestDataEnvironments/get', api_key, params={
        'appId': project_id, 'fetchAppBuildList': 1
    })
    if resp.get('status') != 'OK':
        return None, None, _fetch_error('app build', resp)
    builds = resp.get('appBuildList', [])
    file_id, error = _pick_match(builds, app_build, 'proj_test_data_file_id', 'file_name', 'app build')
    if error:
        return None, None, error
    match = next((b for b in builds if str(b.get('proj_test_data_file_id')) == str(file_id)), None)
    return file_id, (match.get('file_name') if match else None), None


async def _resolve_run_or_scheduler(api_key: str, project_id: int, report_id: int, identifier: Any, kind: str):
    """
    Resolve a run or scheduler identifier (numeric ID or name) -> id.
    kind is 'run' or 'scheduler'. Requires report_id for the lookup.
    """
    if identifier is None:
        return None, None
    if str(identifier).strip().isdigit():
        return int(identifier), None
    if not report_id:
        return None, {
            'status': 'failed',
            'error': f"report required to resolve {kind} by name",
            'error_type': 'ValidationError',
            'message': f"Provide a numeric {kind} id, or pass report so the name can be looked up"
        }
    resp = await make_api_request('GET', '/v1/testrunsExecution/getList', api_key, params={
        'appId': project_id, 'reportId': report_id
    })
    if resp.get('status') != 'OK':
        return None, _fetch_error(kind, resp)
    details = resp.get('schedulerDetails') or {}
    if kind == 'run':
        return _pick_match(details.get('test_runs', []), identifier, 'run_id', 'run_name', 'test run')
    return _pick_match(details.get('scheduler', []), identifier, 'testrun_execution_run_schedule_id', 'scheduler_name', 'scheduler')


async def _get_scheduler_row(api_key: str, project_id: int, report_id: int, scheduler: Any):
    """
    Resolve a scheduler (id or name) and return its full current row from getList,
    so an edit can preserve unchanged schedule fields. Returns (row_dict, error).
    """
    resp = await make_api_request('GET', '/v1/testrunsExecution/getList', api_key, params={
        'appId': project_id, 'reportId': report_id
    })
    if resp.get('status') != 'OK':
        return None, _fetch_error('scheduler', resp)
    scheds = (resp.get('schedulerDetails') or {}).get('scheduler', [])
    sid, error = _pick_match(scheds, scheduler, 'testrun_execution_run_schedule_id', 'scheduler_name', 'scheduler')
    if error:
        return None, error
    row = next((s for s in scheds if str(s.get('testrun_execution_run_schedule_id')) == str(sid)), None)
    return (row or {'testrun_execution_run_schedule_id': sid}), None


async def _resolve_many(api_key: str, project_id: int, report_id: int, raw: Any, kind: str):
    """
    Resolve a comma-separated list of run/scheduler identifiers (IDs or names) -> [ids].
    Fetches the list once when any token is a name.
    """
    tokens = [t.strip() for t in str(raw).split(',') if t.strip()]
    if not tokens:
        return None, {
            'status': 'failed',
            'error': f"No {kind} identifiers provided",
            'error_type': 'ValidationError',
            'message': f"Provide at least one {kind} id or name"
        }
    if all(t.isdigit() for t in tokens):
        return [int(t) for t in tokens], None

    resp = await make_api_request('GET', '/v1/testrunsExecution/getList', api_key, params={
        'appId': project_id, 'reportId': report_id
    })
    if resp.get('status') != 'OK':
        return None, _fetch_error(kind, resp)
    details = resp.get('schedulerDetails') or {}
    if kind == 'run':
        items, id_key, name_key, label = details.get('test_runs', []), 'run_id', 'run_name', 'test run'
    else:
        items, id_key, name_key, label = details.get('scheduler', []), 'testrun_execution_run_schedule_id', 'scheduler_name', 'scheduler'

    ids = []
    for token in tokens:
        vid, error = _pick_match(items, token, id_key, name_key, label)
        if error:
            return None, error
        ids.append(vid)
    return ids, None


def _parse_testcase_ids(testcase_ids: str) -> list:
    """Parse testcase_ids from comma-separated or JSON array string into a list of ints."""
    s = testcase_ids.strip()
    if s.startswith('['):
        try:
            ids = json.loads(s)
        except json.JSONDecodeError:
            ids = []
    else:
        ids = [x.strip() for x in s.split(',') if x.strip()]
    try:
        return [int(i) for i in ids]
    except (ValueError, TypeError):
        return []


