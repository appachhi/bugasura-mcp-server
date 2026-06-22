"""Bugasura MCP tools: TestPert sprints.

TestPert is an app-level (paid) capability flagged by `apps.is_testpert_enabled`.
When a project has it enabled, a sprint can be created as a *TestPert sprint*
(AI deep test enrichment) instead of a standard *TestCase sprint*.

The public /v1/sprints/add endpoint cannot produce a TestPert sprint (it never
threads the testpert flag and the backend zeroes it for non-PLATFORM callers).
The platform's /v1/sprint/create endpoint can: given a `testDetails` blob with
`isTestpertEnabled`/`testpertValue` and `source=PLATFORM`, it persists the flag.
This module mirrors the web frontend's createFunctionalReport payload for an
existing project.
"""

from typing import Any, List, Literal, Optional

from pydantic import Field

from output_types import ToolResponse
from app import mcp
from auth import _get_api_key, validate_api_key
from client import logger, make_api_request
from helpers import select_team_project_context, WEB_BASE_URL
from tools.projects import get_project_details

import asyncio
import base64
import json
import mimetypes
import os
import re
import tempfile
import time
import urllib.parse
import urllib.request

# --- Polling ------------------------------------------------------------------
_KB_POLL_INTERVAL_SECONDS = 5
# Cap well under the ~60s MCP client timeout so a single call never gets killed mid-poll.
# Tools that need longer use re-calls (the caller loops with next_step guidance).
_KB_POLL_MAX_BUDGET_SECONDS = 45

# --- TestPert status machine --------------------------------------------------
# Forward statuses -> terminal status the engine lands on after that phase.
# GENERATE_TEST_COVERAGE is absent — it goes through test-plan endpoints.
_TESTPERT_EXPECTED_TERMINAL = {
    'KNOWLEDGE_BASE': 'KNOWLEDGE_BASE',
    'GENERATE_SPRINT_CONTEXT': 'DEEPEN_REQUIREMENTS_QUESTIONS',
    'GENERATE_DEEPEN_REQUIREMENTS_QUESTIONS': 'DEEPEN_REQUIREMENTS_QUESTIONS',
    'GENERATE_MISSING_REQUIREMENTS': 'MISSING_REQUIREMENTS',
    'RISKS_IN_REQUIREMENTS': 'RISKS_IN_REQUIREMENTS',
    'GENERATE_TEST_PLANING': 'TEST_PLANING',
    'GENERATE_ENRICH_REQUIREMENTS': 'ENRICH_REQUIREMENTS',
    'TEST_COVERAGE': 'TEST_COVERAGE',
    'GENERATE_TEST_CASES': 'TEST_CASES',
}

# Canonical forward order of pipeline stages — used to reject backward moves.
_STATUS_ORDER = {
    'SPRINT_DETAILS': 0,
    'KNOWLEDGE_BASE': 1,
    'DEEPEN_REQUIREMENTS_QUESTIONS': 2,
    'MISSING_REQUIREMENTS': 3,
    'RISKS_IN_REQUIREMENTS': 4,
    'TEST_PLANING': 5,
    'ENRICH_REQUIREMENTS': 6,
    'TEST_COVERAGE': 7,
    'TEST_CASES': 8,
}

# --- User-facing labels -------------------------------------------------------
_FRIENDLY_STATUS = {
    'SPRINT_DETAILS': 'sprint setup',
    'KNOWLEDGE_BASE': 'knowledge base',
    'DEEPEN_REQUIREMENTS_QUESTIONS': 'requirement questions',
    'MISSING_REQUIREMENTS': 'missing requirements',
    'RISKS_IN_REQUIREMENTS': 'requirement risks',
    'TEST_PLANING': 'test plan',
    'ENRICH_REQUIREMENTS': 'requirement enrichment',
    'TEST_COVERAGE': 'test coverage',
    'TEST_CASES': 'test cases',
}

# Per terminal status: (message to user, auto-show directive).
_REACHED = {
    'DEEPEN_REQUIREMENTS_QUESTIONS': (
        "I've reviewed your documents and prepared some questions to refine the requirements.",
        "Immediately fetch and show the user these questions (get_requirements category='deepen_questions'), "
        "one at a time. Do NOT ask whether to pull them."),
    'MISSING_REQUIREMENTS': (
        "I've identified the missing requirements.",
        "Immediately show them to the user for approve/edit (get_requirements category='missing'). Do NOT ask first."),
    'RISKS_IN_REQUIREMENTS': (
        "I've flagged the potential requirement risks.",
        "Immediately show them for approve/reject (get_requirements category='risk'). Do NOT ask first."),
    'TEST_PLANING': (
        "Your test plan is ready.",
        "Immediately call bugasura_testpert_get_testplan and show the user the focus areas from "
        "edit_view.focus_areas and the feature tree from edit_view.features. Then also call "
        "bugasura_testpert_get_features to get the live editable tree (for add/delete). If "
        "get_features returns 0 features, wait 3 seconds and call it once more — features may "
        "still be populating. Do NOT ask the user before doing this."),
    'ENRICH_REQUIREMENTS': (
        "I've enriched the requirements.",
        "The next phase is coverage: call bugasura_testpert_generate_coverage (to reach TEST_COVERAGE), "
        "then bugasura_testpert_get_coverage (show the user the coverage mind map and share the "
        "sprint_url so they can visit the Coverage tab), then bugasura_testpert_generate_testcases."),
    'TEST_COVERAGE': (
        "Test coverage is ready.",
        "Immediately call bugasura_testpert_get_coverage and show the user the coverage mind map "
        "(features and sub-features). Also share the sprint_url from the response "
        "so the user can visit the Coverage tab in the platform directly. Do NOT skip straight to "
        "bugasura_testpert_generate_testcases — the user must see the coverage first. Only after "
        "showing it, proceed to bugasura_testpert_generate_testcases."),
    'TEST_CASES': (
        "Your test cases are ready.",
        "Share the sprint_url so the user can review the test cases. "
        "Then ask the user what they'd like to do next — present exactly these three options: "
        "1) Regenerate test cases for a specific sub-feature "
        "2) Assign a test case to an AI agent "
        "3) Create a test run for this sprint. "
        "Based on their choice: "
        "(1) call bugasura_testpert_get_features(sprint_id=...) to list sub-features with IDs, "
        "then bugasura_testpert_regenerate_testcases(feature_id=<id>, sprint_id=...) for each they want to redo; "
        "(2) call bugasura_list_test_cases(sprint_id=...) to show test cases, ask which one, "
        "then bugasura_update_test_case(testcase_id=<id>, sprint_id=..., assign_to_agent=True) — "
        "functional test cases route to the Browser Agent, API test cases to the Testpert Agent automatically; "
        "(3) call bugasura_create_test_run(report=<sprint_id>) — the tool will collect all run "
        "options from the user (name, single vs scheduled, environment, etc.) before creating."
    ),
}

# --- Knowledge base file types ------------------------------------------------
_KB_DOC_EXTS = {'txt', 'pdf', 'doc', 'docx', 'md', 'json'}
_KB_IMG_EXTS = {'png', 'jpg', 'jpeg', 'webp', 'gif'}
# Extensions that are inherently plain-text: text_content can be uploaded with
# these extensions intact. All other doc extensions are binary formats where
# only extracted text is available from a conversation, so they fall back to .txt.
_KB_TEXT_NATIVE_EXTS = {'txt', 'md', 'json'}

# kb_type -> (multipart field prefix, allowed extensions).
_KB_TYPE_FIELDS = {
    'document':           ('kbFilesUploaded',      _KB_DOC_EXTS),
    'api_docs':           ('kbApiDocs',            _KB_DOC_EXTS),
    'meeting_notes':      ('kbMeetingNotes',       _KB_DOC_EXTS),
    'user_flow':          ('kbUserFlow',           _KB_DOC_EXTS),
    'test_data':          ('kbTestData',           _KB_DOC_EXTS),
    'architecture_image': ('kbArchitectureImages', _KB_IMG_EXTS),
    'db_schema_image':    ('kbDBSchemaImages',     _KB_IMG_EXTS),
    'wireframe_image':    ('kbWireframeImages',    _KB_IMG_EXTS),
    'design_image':       ('kbDesignImages',       _KB_IMG_EXTS),
    'flow_image':         ('kbFlowImages',         _KB_IMG_EXTS),
}

# --- Test plan ----------------------------------------------------------------
_FOCUS_AREAS = ('functionality', 'usability', 'reliability', 'performance', 'security')
_FOCUS_LEVELS = ('EXHAUSTIVE', 'SUFFICIENT', 'MINIMAL', 'NONE')
# Hardcoded placeholder testplan/get returns when no plan row exists — not real data.
_DEFAULT_FOCUS_KEYS = {'functionality', 'usability', 'reliability', 'performance', 'security'}

# --- Requirement context sub-categories --------------------------------------
_DEEPEN_SUBCAT_ORDER = ['product', 'business', 'tech', 'test', 'user']


@mcp.tool(
    name = "bugasura_create_testpert_sprint",
    description = "Create a TestPert (AI deep-enrichment) sprint for a project. The project (app) must be TestPert-enabled. Requires sprint_name (5-250 chars). Configurable options: feature_name, testing_type (Human/Agent/Automation), testing_depth (Quick/Deep), and skip_enrich_requirements. When called without confirm_options=True, returns the editable options for the user to confirm before the sprint is created. Interactive team/project selection available.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def create_testpert_sprint(
    sprint_name: str = Field(description="Name of the sprint (5-250 characters required, min_length=1)"),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    start_date: Optional[str] = Field(default=None, description="Sprint start date in YYYY-MM-DD format (optional)"),
    end_date: Optional[str] = Field(default=None, description="Sprint end date in YYYY-MM-DD format (optional)"),
    duration: Optional[int] = Field(default=None, description="Sprint duration in days (optional)"),
    sprint_status: Literal["SCHEDULED", "IN PROGRESS", "CANCELLED", "COMPLETED"] = Field(default="IN PROGRESS", description="Sprint status: 'SCHEDULED', 'IN PROGRESS', 'CANCELLED', 'COMPLETED' (default: IN PROGRESS)"),
    feature_name: Optional[str] = Field(default=None, description="Feature the TestPert sprint covers (optional - defaults to the sprint name)"),
    testing_type: Literal["Human", "Agent", "Automation"] = Field(default="Agent", description="Testing Type / execution mode: 'Human', 'Agent', or 'Automation' (default: Agent)"),
    testing_depth: Literal["Quick", "Deep"] = Field(default="Deep", description="Testing Depth: 'Quick' (lighter pass) or 'Deep' (full enrichment) (default: Deep)"),
    skip_enrich_requirements: bool = Field(default=False, description="Skip the AI requirements-enrichment check (default: False)"),
    confirm_options: bool = Field(default=False, description="Set True once the user has confirmed the sprint options. When False, the tool returns the editable options for confirmation instead of creating the sprint."),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Create a TestPert-enabled sprint for a project.

    The project (app) must have TestPert enabled (apps.is_testpert_enabled = 1).
    If it isn't, this returns a ValidationError - use bugasura_create_sprint for a
    standard sprint instead.

    Interactive flow: If team_id/project_id are not provided, this function
    will guide you through selection. Once the project is resolved and confirmed
    TestPert-enabled, if `confirm_options` is False the tool returns the editable
    options (sprint name, feature name, testing type, testing depth, skip enrich)
    for the user to confirm; re-call with the chosen values and
    `confirm_options=True` to actually create the sprint.

    Args:
        api_key: User's Bugasura API key (required)
        sprint_name: Name of the sprint (5-250 characters required)
        team_id: Team identifier (optional - will prompt if not provided)
        project_id: Project identifier (optional - will prompt if not provided)
        start_date: Sprint start date in YYYY-MM-DD format (optional)
        end_date: Sprint end date in YYYY-MM-DD format (optional)
        duration: Sprint duration in days (optional)
        sprint_status: Sprint status (default: IN PROGRESS)
        feature_name: Feature the TestPert sprint covers (defaults to sprint_name)
        testing_type: Testing Type / execution mode - Human, Agent, or Automation (default: Agent)
        testing_depth: Testing Depth - Quick or Deep (default: Deep)
        skip_enrich_requirements: Skip the AI requirements-enrichment check (default: False)
        confirm_options: Set True once the user confirmed the options; otherwise
            the tool returns the options for confirmation first

    Returns:
        dict: {
            'status': 'OK',
            'message': str,
            'app_id': int,
            'report_id': int,        # the created sprint id
            'report_name': str,
            'platform': str,
            'platform_type': str
        }
    """
    # Validate API key before proceeding
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Use centralized context selection helper
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_create_testpert_sprint', f', sprint_name="{sprint_name}"')
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # Validate sprint_name length (backend requires 5-250 characters)
    name_error = _validate_sprint_name(sprint_name)
    if name_error:
        return name_error

    # The project must be TestPert-enabled to create a TestPert sprint.
    # Reuse get_project_details() (/v1/projects/get), which now returns
    # is_testpert_enabled, instead of a separate app lookup.
    proj_resp = await get_project_details.fn(team_id=context['team_id'], project_id=context['project_id'],
                                             response_format="json", api_key=api_key)
    app_record = proj_resp.get('project_details') if isinstance(proj_resp, dict) and proj_resp.get('status') == 'OK' else None
    if not _is_testpert_enabled(app_record):
        return {
            'status': 'failed',
            'error': 'Project is not TestPert-enabled',
            'error_type': 'ValidationError',
            'message': (f"Project {context['project_id']} does not have TestPert enabled. "
                        f"Use bugasura_create_sprint to create a standard sprint.")
        }

    # Surface the editable options to the user before creating the sprint, unless
    # they have already been confirmed.
    if not confirm_options:
        project_label = (app_record.get('project_name') or app_record.get('name')
                         or app_record.get('app_name') or context['project_id'])
        return testpert_options_prompt(context['team_id'], context['project_id'],
                                       sprint_name, feature_name, project_label)

    result = await _create_testpert_sprint(
        api_key, context['team_id'], context['project_id'], app_record,
        sprint_name, start_date, end_date, duration, sprint_status, feature_name,
        _normalize_testing_type(testing_type), _normalize_testing_depth(testing_depth),
        1 if skip_enrich_requirements else 0
    )

    # Next step in the TestPert flow. Branch the guidance by whether enrichment is skipped:
    # the normal (skip=False) path is unchanged; the skip path uses requirements, not documents.
    if isinstance(result, dict) and result.get('status') == 'OK':
        result['message'] = "Your sprint is created."
        _attach_sprint_link(result, result.get('testrun_id'), result.get('report_id'))
        if skip_enrich_requirements:
            result['skip_enrich'] = True
            result['next_step'] = (
                "This sprint SKIPS enrichment, so there is NO document upload and NO contextual "
                "questions. The source is the project's requirements. In plain language, ask the user "
                "which requirements to cover, offering BOTH options: (1) pick from the project's "
                "existing requirements — list them with bugasura_list_requirements (omit sprint_id), "
                "then link the chosen ids with bugasura_testpert_link_requirements; and/or (2) add "
                "brand-new ones with bugasura_create_requirement "
                f"(sprint_id={result.get('report_id')}, team_id={context['team_id']}, "
                f"project_id={context['project_id']}). Once at least one requirement is on the sprint, "
                f"call bugasura_testpert_start_skip_testplan(sprint_id={result.get('report_id')}, "
                f"testrun_id={result.get('testrun_id')}) to build the test plan. Do NOT call "
                "bugasura_testpert_upload_kb / generate_sprint_context for this sprint."
            )
        else:
            result['next_step'] = (
                "In plain language (no internal codes), tell the user the sprint is ready and ask which "
                "requirement documents or images they'd like to add. Then call bugasura_testpert_upload_kb "
                f"(sprint_id={result.get('report_id')}, team_id={context['team_id']}, "
                f"project_id={context['project_id']}). "
                "To upload files: in the web app, ask the user to share a Google Drive or Dropbox link "
                "('Anyone with the link') and use source_url+source_url_filename. "
                "In the terminal, ask for the exact absolute file path and use file_paths=[...]. "
                "For plain pasted text only, use text_content. "
                "Never encode files with Script or Bash tools. "
                f"(Keep testrun_id={result.get('testrun_id')} for the final sprint link.)"
            )
    return result


@mcp.tool(
    name = "bugasura_prepare_kb_upload",
    description = (
        "CALL THIS FIRST — before doing anything else — whenever the user wants to upload a file "
        "(PDF, DOCX, image, screenshot, or any other file) to a Bugasura TestPert sprint. "
        "Do NOT encode, read, or process any attached file before calling this tool. "
        "This tool returns the exact instructions to show the user so they can provide the file "
        "in a way that works. Only call bugasura_testpert_upload_kb after the user has responded "
        "to these instructions with a shareable link or a file path."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
)
async def prepare_kb_upload(
    sprint_id: Optional[int] = Field(default=None, description="Sprint to upload to (optional — helps personalise the message)"),
    kb_type: Optional[str] = Field(default=None, description="Type of KB content the user wants to upload (optional)"),
) -> ToolResponse:
    """Return the instructions Claude must show the user before any file upload."""
    sprint_hint = f" to sprint {sprint_id}" if sprint_id else ""
    return {
        'status': 'OK',
        'action': 'ask_user_for_link',
        'message_to_user': (
            f"To upload your file{sprint_hint}, please share a shareable link:\n\n"
            f"**Google Drive:** right-click the file → Share → make sure it is set to "
            f"**'Anyone with the link'** (this is required — private links can't be downloaded) "
            f"→ Copy link\n"
            f"**Dropbox:** click Share → Copy link\n"
            f"**Other:** any public direct download URL\n\n"
            f"Paste the link here and I'll upload it directly — no encoding needed. "
            f"The filename will be detected automatically where possible."
        ),
        'next_step': (
            "Show message_to_user to the user verbatim. Wait for them to paste a link. "
            "Then call bugasura_testpert_upload_kb with source_url=<link> and sprint_id as "
            "appropriate. source_url_filename is optional — omit it and the filename will be "
            "detected from the URL or response headers. Only pass source_url_filename if the "
            "user explicitly provides a filename or if detection fails. "
            "Do not run any Script, Analysis, or Bash tool at any point in this flow."
        )
    }


@mcp.tool(
    name = "bugasura_testpert_upload_kb",
    description = (
        "Upload a knowledge-base file to a TestPert sprint. "
        "IMPORTANT: Always call bugasura_prepare_kb_upload first — it returns the message "
        "to show the user so they can provide a shareable link. Only call this tool once "
        "the user has responded with a Google Drive / Dropbox link or a local file path. "
        "THREE WAYS TO PROVIDE CONTENT — pick ONE per call: "
        "(1) source_url + source_url_filename — paste the Google Drive/Dropbox/public link "
        "the user shared. The MCP server downloads the file directly. "
        "(2) file_paths — for terminal use: the exact absolute path the user provided. "
        "(3) text_content + text_content_filename — only for plain text pasted directly. "
        "Documents: .txt/.pdf/.doc/.docx/.md/.json — Images: .png/.jpg/.jpeg/.webp/.gif"
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def upload_testpert_kb(
    source_url: Optional[str] = Field(default=None, description="Google Drive share link, Dropbox share link, or any public direct download URL. The MCP server fetches the file — no encoding needed. Share links are auto-converted to direct download URLs. IMPORTANT: the link must be set to 'Anyone with the link' access."),
    source_url_filename: Optional[str] = Field(default=None, description="Original filename with extension (e.g. 'PRD.pdf', 'wireframe.png'). Optional — the filename is inferred from the URL path or HTTP Content-Disposition header when not provided. Only pass this if auto-detection fails or the user explicitly names the file."),
    file_paths: List[str] = Field(default=[], description="Absolute paths on the MCP server's local filesystem (terminal/CLI use). Ask the user for the exact path — never construct or guess it."),
    text_content: Optional[str] = Field(default=None, description="Plain text the user pasted directly into the chat. Only for text kb_types. Not for PDFs, DOCX, or images — use source_url for those."),
    text_content_filename: Optional[str] = Field(default=None, description="Filename for the text_content upload (e.g. 'notes.md'). Text-native extensions (.md, .json, .txt) are preserved as-is."),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (= report_id). If omitted, you'll be prompted to pick a sprint (ge=1)."),
    kb_type: Literal[
        'document', 'api_docs', 'meeting_notes', 'user_flow', 'test_data',
        'architecture_image', 'db_schema_image', 'wireframe_image', 'design_image', 'flow_image'
    ] = Field(default='document', description="Knowledge-base source type for these files. 'document'/'api_docs'/'meeting_notes'/'user_flow'/'test_data' take text docs; the '*_image' types take images."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Upload one or more knowledge-base files to a TestPert sprint.

    Posts to /v1/testpertKB/sprint/add as multipart/form-data. Each file is sent as
    its own field `<prefix>_<index>` (e.g. kbFilesUploaded_0) matching the backend's
    per-file parsing. Sends `testpertStatus=KNOWLEDGE_BASE`, which moves a brand-new
    sprint out of SPRINT_DETAILS and is a safe no-op on repeat calls, so files can be
    added incrementally before the analysis phase is started.

    Args:
        file_paths: Absolute local paths to upload (MCP server must be able to read them)
        text_content: Raw document text to upload as document.txt (use when file was attached
                      to the conversation and you have its text but no accessible local path)
        sprint_id: Sprint id (= report_id); prompts if omitted
        kb_type: Which KB source bucket the files belong to (default: document)
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: API response, including `trainingSourcesCount` and
        `totalTrainingCompletionEstimationStr` on success, plus a `next_step` hint.
    """
    # Validate API key before proceeding
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Resolve team/project context.
    context = await select_team_project_context(api_key, team_id, project_id,
                                                'bugasura_testpert_upload_kb')
    if 'status' in context and context['status'] == 'selection_required':
        return context

    # A sprint is required; prompt to pick one if not supplied.
    if not sprint_id:
        return _sprint_selection_required(context['team_id'], context['project_id'])

    # The project must be TestPert-enabled.
    proj_resp = await get_project_details.fn(team_id=context['team_id'], project_id=context['project_id'],
                                             response_format="json", api_key=api_key)
    app_record = proj_resp.get('project_details') if isinstance(proj_resp, dict) and proj_resp.get('status') == 'OK' else None
    if not _is_testpert_enabled(app_record):
        return {
            'status': 'failed',
            'error': 'Project is not TestPert-enabled',
            'error_type': 'ValidationError',
            'message': (f"Project {context['project_id']} does not have TestPert enabled, "
                        f"so it has no knowledge base to upload to.")
        }

    # Validate: need at least one source of content.
    if not file_paths and not source_url and not text_content:
        return {
            'status': 'failed',
            'error': 'No files provided',
            'error_type': 'ValidationError',
            'message': (
                'To upload a file, ask the user to share a Google Drive or Dropbox link. '
                'IMPORTANT: for Google Drive the link must be set to "Anyone with the link" '
                '(right-click the file → Share → change access to "Anyone with the link" → Copy link). '
                'Then call this tool with source_url=<link>. The filename is detected automatically; '
                'source_url_filename is only needed if auto-detection fails. '
                'For terminal use, ask for the exact absolute file path and use file_paths=[...].'
            )
        }

    field_prefix, allowed_exts = _KB_TYPE_FIELDS[kb_type]

    # Reject ambiguous calls that supply more than one inline content source.
    inline_sources = sum([bool(source_url), bool(text_content)])
    if inline_sources > 1 and not file_paths:
        return {
            'status': 'failed',
            'error': 'Multiple inline content sources provided',
            'error_type': 'ValidationError',
            'message': 'Provide only one of source_url or text_content per call. To upload multiple files, make separate calls.'
        }

    # _tmp_display maps each temp-file path -> its sanitised display name (original filename).
    # Every path registered here is unlinked in the finally block regardless of how the
    # function exits. To add a new inline content path: create the temp file via the helpers,
    # register it here, set file_paths — display-name lookup and cleanup are then automatic.
    _tmp_display: dict = {}

    try:
        # --- source_url path (MCP server fetches the file from a public URL) -------
        if source_url and not file_paths:
            download_url = _normalise_share_url(source_url)

            if source_url_filename:
                # User supplied a filename — validate extension then download.
                safe_name = os.path.basename(source_url_filename)
                url_ext = os.path.splitext(safe_name)[1].lstrip('.').lower()
                if not url_ext:
                    return {
                        'status': 'failed',
                        'error': 'source_url_filename must include a file extension',
                        'error_type': 'ValidationError',
                        'message': f"Cannot determine file type from '{safe_name}'. Add the extension (e.g. 'spec.pdf')."
                    }
                if url_ext not in allowed_exts:
                    return {
                        'status': 'failed',
                        'error': f'Unsupported extension .{url_ext} for kb_type={kb_type}',
                        'error_type': 'ValidationError',
                        'message': (f"'{safe_name}' has extension .{url_ext}, which "
                                    f"kb_type='{kb_type}' does not accept. Allowed: "
                                    f"{', '.join('.' + e for e in sorted(allowed_exts))}.")
                    }
                download_suffix = f'.{url_ext}'
            else:
                # No filename provided — try to infer from URL path first (cheap, no network).
                path_name = _infer_filename_from_url_path(download_url) or _infer_filename_from_url_path(source_url)
                if path_name:
                    inferred_ext = os.path.splitext(path_name)[1].lstrip('.').lower()
                    if inferred_ext in allowed_exts:
                        safe_name = os.path.basename(path_name)
                        url_ext = inferred_ext
                        download_suffix = f'.{url_ext}'
                    else:
                        path_name = None  # extension not usable, fall through to Content-Disposition
                if not path_name:
                    # Download with a neutral suffix; extract filename from Content-Disposition.
                    safe_name = None
                    url_ext = None
                    download_suffix = '.tmp'

            try:
                tmp_path, cd_name = _download_url_tmp(download_url, download_suffix)
            except Exception as e:
                return {
                    'status': 'failed',
                    'error': 'Failed to download file from source_url',
                    'error_type': 'IOError',
                    'message': (f"Could not download '{source_url}': {e}. "
                                "Make sure the link is set to 'Anyone with the link' (not restricted "
                                "to signed-in users).")
                }

            # If we still need a filename, use Content-Disposition from the response.
            if not source_url_filename and not path_name:
                if cd_name:
                    safe_name = os.path.basename(cd_name)
                    url_ext = os.path.splitext(safe_name)[1].lstrip('.').lower()
                if not safe_name or not url_ext:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                    return {
                        'status': 'failed',
                        'error': 'Could not determine filename from URL or response headers',
                        'error_type': 'ValidationError',
                        'message': (
                            "Could not auto-detect the filename from the URL or the server response. "
                            "Please provide source_url_filename with the original filename and extension "
                            "(e.g. 'PRD.pdf', 'wireframe.png')."
                        )
                    }
                if url_ext not in allowed_exts:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                    return {
                        'status': 'failed',
                        'error': f'Unsupported extension .{url_ext} for kb_type={kb_type}',
                        'error_type': 'ValidationError',
                        'message': (f"Detected filename '{safe_name}' has extension .{url_ext}, which "
                                    f"kb_type='{kb_type}' does not accept. Allowed: "
                                    f"{', '.join('.' + e for e in sorted(allowed_exts))}.")
                    }

            _tmp_display[tmp_path] = safe_name
            file_paths = [tmp_path]

        # --- text_content path (plain text only — last resort) --------------------
        elif text_content and not file_paths:
            if kb_type not in ('document', 'api_docs', 'meeting_notes', 'user_flow', 'test_data'):
                return {
                    'status': 'failed',
                    'error': f'text_content is only supported for text kb_types, not {kb_type}',
                    'error_type': 'ValidationError',
                    'message': (f"text_content cannot be used with kb_type='{kb_type}'. "
                                f"For images, ask the user for a Google Drive or Dropbox link and use source_url.")
                }
            if text_content_filename:
                safe_base, raw_ext = os.path.splitext(os.path.basename(text_content_filename))
                orig_ext = raw_ext.lstrip('.').lower()
                # Text-native formats keep their extension; binary-source formats (pdf, docx, doc)
                # must fall back to .txt because only extracted text is available from a conversation.
                use_ext = orig_ext if orig_ext in _KB_TEXT_NATIVE_EXTS else 'txt'
                use_name = f"{safe_base}.{use_ext}"
            else:
                use_ext = 'txt'
                use_name = 'document.txt'
            try:
                tmp_path = _write_text_tmp(text_content, f'.{use_ext}')
            except OSError as e:
                return {
                    'status': 'failed',
                    'error': 'Could not write temp file for text_content',
                    'error_type': 'IOError',
                    'message': str(e)
                }
            _tmp_display[tmp_path] = use_name
            file_paths = [tmp_path]

        files = []
        for idx, path in enumerate(file_paths):
            if not os.path.isfile(path):
                return {
                    'status': 'failed',
                    'error': f'File not found: {path}',
                    'error_type': 'ValidationError',
                    'message': (
                        f"Could not find a readable file at '{path}'. "
                        "Ask the user for the exact absolute path to the file on their machine, "
                        "or ask them to share a Google Drive/Dropbox link and use source_url."
                    )
                }
            # Extension check: only needed for real disk paths — temp paths are pre-validated above.
            if path not in _tmp_display:
                ext = os.path.splitext(path)[1].lstrip('.').lower()
                if ext not in allowed_exts:
                    return {
                        'status': 'failed',
                        'error': f'Unsupported extension .{ext} for kb_type={kb_type}',
                        'error_type': 'ValidationError',
                        'message': (f"'{os.path.basename(path)}' has extension .{ext}, which "
                                    f"kb_type='{kb_type}' does not accept. Allowed: "
                                    f"{', '.join('.' + e for e in sorted(allowed_exts))}.")
                    }
            try:
                with open(path, 'rb') as fh:
                    content = fh.read()
            except OSError as e:
                return {
                    'status': 'failed',
                    'error': f'Could not read file: {path}',
                    'error_type': 'IOError',
                    'message': str(e)
                }
            # Temp paths use their registered display name; real disk paths use their actual basename.
            display_name = _tmp_display.get(path) or os.path.basename(path)
            content_type = mimetypes.guess_type(display_name)[0] or 'application/octet-stream'
            # One field per file: kbFilesUploaded_0, kbFilesUploaded_1, ...
            files.append((f"{field_prefix}_{idx}", (display_name, content, content_type)))

    finally:
        for p in list(_tmp_display):
            try:
                if os.path.exists(p):
                    os.unlink(p)
            except OSError:
                pass

    data = {
        'appId': str(context['project_id']),
        'teamId': str(context['team_id']),
        'sprintId': str(sprint_id),
        'isSprintTestpert': '1',
        'selectedKBs': json.dumps(_build_selected_kbs_skeleton()),
        # KNOWLEDGE_BASE: advances a new sprint out of SPRINT_DETAILS; no-op if already there.
        'testpertStatus': 'KNOWLEDGE_BASE',
    }

    logger.info(f"Uploading {len(files)} TestPert KB file(s) [{kb_type}] to sprint_id={sprint_id}, "
                f"project_id={context['project_id']}")
    result = await make_api_request('POST', '/v1/testpertKB/sprint/add', api_key,
                                    data=data, files=files)

    if isinstance(result, dict) and result.get('status') == 'OK':
        result['message'] = "Added your document(s) to the knowledge base."
        result['next_step'] = (
            "Ask the user (plainly) if they want to add more documents or start the analysis. To start, "
            "call bugasura_testpert_generate_sprint_context — then, the moment it's ready, automatically "
            "show the questions; don't ask permission to pull them."
        )
        return await _attach_link_for_sprint(result, api_key, context['team_id'], context['project_id'], sprint_id)
    return result


# --- Skip-enrich kickoff: requirements -> test plan (no docs, no questions) -----
@mcp.tool(
    name = "bugasura_testpert_start_skip_testplan",
    description = (
        "SKIP-ENRICH sprints ONLY. For a TestPert sprint created with skip_enrich_requirements=1, this drives "
        "the front half of the flow WITHOUT document upload and WITHOUT the deepen/missing/risk questions, using "
        "the sprint's REQUIREMENTS as the source. It: verifies the sprint has >=1 requirement (add them first "
        "with bugasura_create_requirement using this sprint_id), sets ENRICH_REQUIREMENTS, attaches the "
        "requirements as the knowledge source and transitions to GENERATE_TEST_PLANING, then polls until "
        "TEST_PLANING. Re-callable (if it's still generating, call again). This tool refuses to run on a "
        "normal (non-skip) sprint — for those use bugasura_testpert_upload_kb + bugasura_testpert_generate_sprint_context."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def start_skip_testplan(
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (= report_id). Required (prompts if omitted, ge=1)."),
    testrun_id: Optional[int] = Field(default=None, description="The sprint's testrun_id (from the create response); when given, a clickable sprint link is included."),
    max_wait_seconds: int = Field(default=45, description="Upper bound on polling while the test plan is generated (0-45, default 45). Capped at 45s to stay under MCP client timeouts; re-call to keep waiting."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Skip-enrich front half: SPRINT_DETAILS -> ENRICH_REQUIREMENTS -> GENERATE_TEST_PLANING -> TEST_PLANING.

    Mirrors the web app's skip flow (requirementFilterSection.volt): set ENRICH_REQUIREMENTS once
    requirements exist, then POST /testpertKB/sprint/add with NO files + testpertStatus=GENERATE_TEST_PLANING
    + skipEnrichRequirements=1 (which attaches the project requirements as the KB source and kicks the plan).
    Guarded to skip-enrich sprints only so the normal flow is never affected.
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id,
                                                'bugasura_testpert_start_skip_testplan')
    if 'status' in context and context['status'] == 'selection_required':
        return context
    if not sprint_id:
        return _sprint_selection_required(context['team_id'], context['project_id'])

    tid, pid = context['team_id'], context['project_id']
    budget = max(0, min(int(max_wait_seconds), _KB_POLL_MAX_BUDGET_SECONDS))

    status_resp = await _get_sprint_testpert_status_raw(api_key, tid, pid, sprint_id)
    current = _extract_sprint_status(status_resp)
    skip_enrich = _extract_skip_enrich(status_resp)
    if not testrun_id:
        testrun_id = _extract_testrun_id(status_resp)

    # Guard: this tool is ONLY for skip-enrich sprints; never touch the normal flow.
    if not skip_enrich:
        return {
            'status': 'failed',
            'error': 'Not a skip-enrich sprint',
            'error_type': 'ValidationError',
            'message': ("This sprint does not skip enrichment, so it follows the normal flow. Use "
                        "bugasura_testpert_upload_kb to add documents, then bugasura_testpert_generate_sprint_context."),
            'current_status': current,
        }

    # Idempotent: already at or past the plan.
    if current == 'TEST_PLANING':
        return _attach_sprint_link({
            'status': 'OK', 'current_status': 'TEST_PLANING', 'reached': True,
            'message': "The test plan is ready.",
            'next_step': "Show the focus areas (get_testplan). This is a skip-enrich sprint, so do NOT show/edit features (no get_features). Do NOT ask first.",
        }, testrun_id, sprint_id)
    # Forward-only guard, SKIP-AWARE: in the skip flow the predecessor is ENRICH_REQUIREMENTS,
    # which sits *after* TEST_PLANING in the normal linear order (_STATUS_ORDER) — so the generic
    # _is_backward_transition() would wrongly reject a legitimate ENRICH_REQUIREMENTS re-entry.
    # Only block when the sprint is genuinely past the plan (coverage / test cases already done).
    if current in ('TEST_COVERAGE', 'GENERATE_TEST_CASES', 'TEST_CASES_IN_PROGRESS',
                   'TEST_CASES', 'TEST_CASES_ERROR'):
        return _backward_blocked_response(current, 'GENERATE_TEST_PLANING')

    # If the plan is already generating, just poll.
    if current != 'GENERATE_TEST_PLANING':
        # Need at least one requirement — that is the skip-enrich source.
        count = await _count_sprint_requirements(api_key, tid, pid, sprint_id)
        if count == 0:
            return {
                'status': 'failed',
                'error': 'No requirements on the sprint',
                'error_type': 'ValidationError',
                'message': ("Skip-enrich uses the sprint's requirements as the source, but this sprint has "
                            "none yet. Either link existing project requirements with "
                            "bugasura_testpert_link_requirements (after listing them via "
                            "bugasura_list_requirements), or add new ones with bugasura_create_requirement "
                            f"(sprint_id={sprint_id}, team_id={tid}, project_id={pid}), then call this again."),
            }

        # Set ENRICH_REQUIREMENTS (legal from SPRINT_DETAILS when skip==1).
        if current == 'SPRINT_DETAILS':
            enr = await make_api_request('POST', '/v1/testpert/sprint/updateStatus', api_key, data={
                'appId': str(pid), 'teamId': str(tid), 'sprintId': str(sprint_id),
                'testpertStatus': 'ENRICH_REQUIREMENTS',
            })
            if not (isinstance(enr, dict) and enr.get('status') == 'OK'):
                return {
                    'status': 'failed',
                    'error': 'Could not mark requirements ready',
                    'error_type': 'StatusTransitionError',
                    'message': (enr.get('message') if isinstance(enr, dict) else None)
                               or "The API rejected the move to ENRICH_REQUIREMENTS.",
                    'current_status': enr.get('currentTestpertStatus') if isinstance(enr, dict) else current,
                    'raw': enr,
                }
            current = 'ENRICH_REQUIREMENTS'

        # Attach the requirements as the KB source AND transition to GENERATE_TEST_PLANING.
        # This is the web app's "Next" call: /testpertKB/sprint/add with NO files.
        adv = await make_api_request('POST', '/v1/testpertKB/sprint/add', api_key, data={
            'appId': str(pid), 'teamId': str(tid), 'sprintId': str(sprint_id),
            'isSprintTestpert': '1',
            'testpertStatus': 'GENERATE_TEST_PLANING',
            'skipEnrichRequirements': '1',
        })
        if not (isinstance(adv, dict) and adv.get('status') == 'OK'):
            return {
                'status': 'failed',
                'error': 'Could not start test-plan generation',
                'error_type': 'StatusTransitionError',
                'message': (adv.get('message') if isinstance(adv, dict) else None)
                           or "The API rejected the move to GENERATE_TEST_PLANING.",
                'current_status': adv.get('currentTestpertStatus') if isinstance(adv, dict) else current,
                'raw': adv,
            }

    # Poll until the plan is ready.
    poll = await _poll_sprint_until(api_key, tid, pid, sprint_id, 'TEST_PLANING', budget)
    if poll['outcome'] == 'reached':
        return _attach_sprint_link({
            'status': 'OK', 'current_status': 'TEST_PLANING', 'reached': True,
            'message': "Your test plan is ready.",
            'next_step': "Show the focus areas (get_testplan). This is a skip-enrich sprint, so do NOT show/edit features (no get_features). Do NOT ask first.",
        }, testrun_id, sprint_id)
    if poll['outcome'] == 'error':
        return _engine_error_response(poll['current'],
                                      "Re-run bugasura_testpert_start_skip_testplan to retry.")
    if poll['outcome'] == 'read_error':
        return {
            'status': 'failed', 'error': 'Could not read sprint status',
            'error_type': 'StatusReadError', 'raw': poll.get('raw'),
            'message': "I couldn't read the sprint's progress just now — please try again.",
        }
    return _attach_sprint_link({
        'status': 'OK', 'current_status': poll['current'], 'reached': False, 'in_progress': True,
        'message': "Building the test plan — " + _working_message(),
        'next_step': "Call bugasura_testpert_start_skip_testplan again to keep checking.",
    }, testrun_id, sprint_id)


@mcp.tool(
    name = "bugasura_testpert_advance",
    description = (
        "Read the current TestPert phase OR advance the sprint to a new phase. "
        "ALWAYS call this (with to_status omitted) when the user asks for the sprint's status, "
        "current phase, or pipeline progress — e.g. 'what phase is this sprint at?', "
        "'check testpert status', 'what is the current testpert status?', 'where is my sprint?'. "
        "Do NOT use bugasura_testpert_get_testplan for status — it reads saved test plan content, "
        "not the current pipeline phase. "
        "To ADVANCE: set to_status to a GENERATE_* value to kick off an AI phase, then pass "
        "wait_for to poll until the engine reaches the matching terminal status. Re-callable: "
        "if still running when the time budget ends, call again (to_status omitted) to keep polling."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def advance_testpert(
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (= report_id). Required (prompts if omitted, ge=1)."),
    to_status: Optional[Literal[
        'KNOWLEDGE_BASE', 'GENERATE_SPRINT_CONTEXT', 'GENERATE_DEEPEN_REQUIREMENTS_QUESTIONS',
        'GENERATE_MISSING_REQUIREMENTS', 'RISKS_IN_REQUIREMENTS', 'GENERATE_TEST_PLANING',
        'GENERATE_ENRICH_REQUIREMENTS', 'TEST_COVERAGE', 'GENERATE_TEST_CASES'
    ]] = Field(default=None, description="Status to set before polling. Omit to only read/poll the current status. To continue polling a phase already kicked off, call again with this omitted."),
    wait_for: Optional[str] = Field(default=None, description="Status to poll until (e.g. 'DEEPEN_REQUIREMENTS_QUESTIONS', 'MISSING_REQUIREMENTS', 'TEST_PLANING', 'TEST_CASES'). Omit to skip polling. If omitted but to_status is set, the expected terminal is suggested in next_step."),
    requirement_analysis_json: Optional[str] = Field(default=None, description="JSON string for data-bearing transitions (sent as requirementAnalysisJsonData), e.g. when moving to RISKS_IN_REQUIREMENTS with the approved data."),
    testpert_flow_attempt: Optional[int] = Field(default=None, description="Retry attempt counter for REGENERATE flows (0-99). Usually omit."),
    testrun_id: Optional[int] = Field(default=None, description="The sprint's testrun_id (from the create response). When provided, a clickable sprint link is included once a phase is reached."),
    max_wait_seconds: int = Field(default=30, description="Upper bound on this call's polling (0-45, default 30). Capped at 45s; call again to keep waiting on long phases."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Advance and/or poll a TestPert sprint's status.

    - With `to_status`: POST /v1/testpert/sprint/updateStatus to set it (no `source`,
      so the admin gate is bypassed). Data-bearing transitions can carry
      `requirement_analysis_json`.
    - With `wait_for`: poll /v1/testpert/sprint/getStatus every few seconds (up to
      `max_wait_seconds`) until the status equals `wait_for`, hits an `*_ERROR`, or the
      budget runs out (returns in-progress so the caller can poll again).

    Returns:
        dict: {status, current_status, advanced_to?, reached?, in_progress?, message, next_step?}
    """
    # Validate API key.
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    # Resolve team/project context.
    context = await select_team_project_context(api_key, team_id, project_id,
                                                'bugasura_testpert_advance')
    if 'status' in context and context['status'] == 'selection_required':
        return context

    if not sprint_id:
        return _sprint_selection_required(context['team_id'], context['project_id'])

    tid, pid = context['team_id'], context['project_id']

    # 1. Advance, if requested.
    if to_status:
        # Refuse to move the sprint backward — the TestPert flow only advances.
        current_before = _extract_sprint_status(
            await _get_sprint_testpert_status_raw(api_key, tid, pid, sprint_id))
        if _is_backward_transition(current_before, to_status):
            return _backward_blocked_response(current_before, to_status)

        data = {
            'appId': str(pid),
            'teamId': str(tid),
            'sprintId': str(sprint_id),
            'testpertStatus': to_status,
        }
        if requirement_analysis_json:
            data['requirementAnalysisJsonData'] = requirement_analysis_json
        if testpert_flow_attempt is not None:
            data['testpertFlowAttempt'] = str(testpert_flow_attempt)

        logger.info(f"Advancing sprint_id={sprint_id} testpert status -> {to_status}")
        adv = await make_api_request('POST', '/v1/testpert/sprint/updateStatus', api_key, data=data)
        if not (isinstance(adv, dict) and adv.get('status') == 'OK'):
            return {
                'status': 'failed',
                'error': f"Could not set status to {to_status}",
                'error_type': 'StatusTransitionError',
                'message': (adv.get('message') if isinstance(adv, dict) else None)
                           or f"The API rejected the transition to {to_status}.",
                'current_status': adv.get('currentTestpertStatus') if isinstance(adv, dict) else None,
                'raw': adv,
            }

    # 2. Poll, if requested.
    if wait_for:
        budget = max(0, min(int(max_wait_seconds), _KB_POLL_MAX_BUDGET_SECONDS))
        deadline = time.monotonic() + budget
        while True:
            status_resp = await _get_sprint_testpert_status_raw(api_key, tid, pid, sprint_id)
            current = _extract_sprint_status(status_resp)
            if current is None:
                return {
                    'status': 'failed',
                    'error': 'Could not read sprint TestPert status',
                    'error_type': 'StatusReadError',
                    'message': 'getStatus did not return a sprint_testpert_status.',
                    'raw': status_resp,
                }
            if current == wait_for:
                if not testrun_id:
                    testrun_id = _extract_testrun_id(status_resp)
                msg, ns = _REACHED.get(current, (f"The {_friendly(current)} is ready.", ""))
                out = {
                    'status': 'OK',
                    'current_status': current,
                    'advanced_to': to_status,
                    'reached': True,
                    'message': msg,
                }
                if ns:
                    out['next_step'] = ns
                return _attach_sprint_link(out, testrun_id, sprint_id,
                                           tab='testcase' if current == 'TEST_CASES' else None)
            if current.endswith('_ERROR'):
                return _engine_error_response(
                    current, "Re-run the matching GENERATE/REGENERATE step to retry.")
            if time.monotonic() >= deadline:
                return {
                    'status': 'OK',
                    'current_status': current,
                    'advanced_to': to_status,
                    'reached': False,
                    'in_progress': True,
                    'message': _working_message(),
                    'next_step': (f"Call bugasura_testpert_advance again with to_status omitted and "
                                  f"wait_for='{wait_for}' to keep checking."),
                }
            await asyncio.sleep(_KB_POLL_INTERVAL_SECONDS)

    # 3. No polling requested — return the current status.
    status_resp = await _get_sprint_testpert_status_raw(api_key, tid, pid, sprint_id)
    current = _extract_sprint_status(status_resp)
    result = {
        'status': 'OK',
        'current_status': current,
        'advanced_to': to_status,
        'message': (f"This sprint is at the {_friendly(current)} stage." if current
                    else "Fetched sprint status."),
    }
    if to_status and to_status in _TESTPERT_EXPECTED_TERMINAL:
        expected = _TESTPERT_EXPECTED_TERMINAL[to_status]
        if expected != to_status:
            result['next_step'] = (
                f"Keep checking until ready: call bugasura_testpert_advance with wait_for='{expected}' "
                f"(to_status omitted)."
            )
    return result


@mcp.tool(
    name = "bugasura_testpert_get_requirements",
    description = (
        "Fetch a TestPert sprint's requirement-analysis context for user review: the engine's "
        "deepen-requirement questions, missing requirements, and requirement risks. Use after a "
        "phase lands on DEEPEN_REQUIREMENTS_QUESTIONS / MISSING_REQUIREMENTS / RISKS_IN_REQUIREMENTS "
        "to show the items, then collect the user's answers / approve-reject-edit decisions and "
        "write them back with bugasura_testpert_update_requirements."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def get_testpert_requirements(
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (= report_id). Required (prompts if omitted, ge=1)."),
    category: Literal['all', 'deepen_questions', 'missing', 'risk'] = Field(default='all', description="Which context set to return (default: all)."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Read requirement-context rows for a sprint and group them by category.

    GETs /v1/testpertrequirementcontexts/get in raw mode (the API's isManageReq=1
    formatted path is dropped by the response wrapper) and groups rows itself.

    Returns:
        dict: {status, sprint_id, deepen_questions?, missing?, risk?, counts, message}.
        If the engine hasn't produced any rows yet, returns status 'OK' with empty
        groups and a hint to ensure the phase has completed.
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id,
                                                'bugasura_testpert_get_requirements')
    if 'status' in context and context['status'] == 'selection_required':
        return context
    if not sprint_id:
        return _sprint_selection_required(context['team_id'], context['project_id'])

    resp = await make_api_request('GET', '/v1/testpertrequirementcontexts/get', api_key, params={
        'appId': context['project_id'],
        'reportId': sprint_id,
    })

    # The API returns ERROR/not_found when no rows exist yet — treat that as "empty".
    if not (isinstance(resp, dict) and resp.get('status') == 'OK'):
        msg = resp.get('message') if isinstance(resp, dict) else None
        return {
            'status': 'OK',
            'sprint_id': sprint_id,
            'deepen_questions': {},
            'missing': [],
            'risk': [],
            'counts': {'deepen_questions': 0, 'missing': 0, 'risk': 0},
            'message': (f"No requirement contexts available yet ({msg or 'none found'}). "
                        f"Make sure the phase has completed (status DEEPEN_REQUIREMENTS_QUESTIONS / "
                        f"MISSING_REQUIREMENTS / RISKS_IN_REQUIREMENTS) before fetching."),
        }

    rows = resp.get('testpertRequirementContexts') or []
    grouped = _group_requirement_contexts(rows)

    result: dict = {
        'status': 'OK',
        'sprint_id': sprint_id,
        'counts': {
            'deepen_questions': sum(len(v) for v in grouped['deepen_questions'].values()),
            'missing': len(grouped['missing']),
            'risk': len(grouped['risk']),
        },
    }
    if category in ('all', 'deepen_questions'):
        result['deepen_questions'] = grouped['deepen_questions']
        # Ordered, numbered list so the assistant can ask one question at a time.
        result['deepen_questions_list'] = _deepen_questions_flat(grouped['deepen_questions'])
    if category in ('all', 'missing'):
        result['missing'] = grouped['missing']
    if category in ('all', 'risk'):
        result['risk'] = grouped['risk']

    if category == 'deepen_questions' or (category == 'all' and result['counts']['deepen_questions']):
        # Quick testing depth makes the engine AUTO-ANSWER the deepen questions, so the rows come
        # back with their `response`/current_response already filled. Detect that and switch the
        # guidance to review-and-proceed instead of asking each one (which the platform doesn't do).
        deepen_list = result.get('deepen_questions_list') or []
        deepen_total = len(deepen_list)
        deepen_answered = sum(1 for q in deepen_list if (q.get('current_response') or '').strip())
        result['deepen_answered_count'] = deepen_answered
        if deepen_total and deepen_answered == deepen_total:
            result['all_deepen_preanswered'] = True
            result['message'] = (
                "These contextual questions are ALREADY answered (this is what Quick testing depth does — "
                "the engine auto-answers them; each one's current_response is filled). Do NOT ask them "
                "one-by-one. Instead tell the user they're pre-filled, optionally show a couple as "
                "examples, and let them either tweak any answer (save edits with "
                "bugasura_testpert_answer_context_questions) or just proceed. To move on, continue with "
                "bugasura_testpert_advance(to_status='GENERATE_MISSING_REQUIREMENTS', "
                "wait_for='MISSING_REQUIREMENTS'). Use plain language; never show status codes."
            )
        else:
            result['message'] = (
                "First give the user a short one-line overview (how many questions, the areas; note if "
                f"{deepen_answered} of {deepen_total} are already answered). Then ask them ONE QUESTION "
                "AT A TIME from deepen_questions_list (it is ordered): show 'Question 1 of N' + the "
                "question (and its current_response if it already has one), WAIT for their answer, then "
                "ask the next. Do NOT dump the whole list. Let them skip any (say 'skip') or stop early. "
                "When done, save with bugasura_testpert_answer_context_questions "
                "(answers=[{requirement_context_id, response}]); partial is fine. Use plain language "
                "only — never show status codes or field names."
            )
    else:
        result['message'] = (
            "Show these to the user in plain language for their approve/reject/edit decision, then save "
            "with bugasura_testpert_update_requirements and continue. No internal codes in what the user sees."
        )
    return await _attach_link_for_sprint(result, api_key, context['team_id'], context['project_id'], sprint_id)


@mcp.tool(
    name = "bugasura_testpert_add_context_question",
    description = (
        "Add a new contextual (deepen-requirement) question to a TestPert sprint, like the "
        "'Add Question' button in the platform's Deepen Requirements tab. The sprint must be at "
        "DEEPEN_REQUIREMENTS_QUESTIONS. After adding, call bugasura_testpert_get_requirements "
        "(category='deepen_questions') to show the updated list."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def add_testpert_context_question(
    question: str = Field(description="The question text to add (the 'title' / query of the new deepen-requirement question)."),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (= report_id). Required (prompts if omitted, ge=1)."),
    sub_category: str = Field(default='product', description="Sub-category for the question. One of: product, business, tech, test, user (default: product)."),
    answer: Optional[str] = Field(default=None, description="Optional initial answer/response for the question (default: empty — unanswered)."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """Add a new deepen-requirement context question via /v1/testpertrequirementcontexts/add."""
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id,
                                                'bugasura_testpert_add_context_question')
    if 'status' in context and context['status'] == 'selection_required':
        return context
    if not sprint_id:
        return _sprint_selection_required(context['team_id'], context['project_id'])

    if not (question or '').strip():
        return {'status': 'failed', 'error': 'question is required', 'error_type': 'ValidationError',
                'message': 'Provide the question text.'}

    valid_subcats = ('product', 'business', 'tech', 'test', 'user')
    sub = (sub_category or 'product').strip().lower()
    if sub not in valid_subcats:
        sub = 'product'

    resp = await make_api_request('POST', '/v1/testpertrequirementcontexts/add', api_key, data={
        'appId': str(context['project_id']),
        'reportId': str(sprint_id),
        'category': 'deepen_requirement_questions',
        'subCategory': sub,
        'title': question.strip(),
        'details': (answer or '').strip(),
        'isEdited': '1' if answer else '0',
        'isApproved': '0',
        'source': 'PLATFORM',
    })
    if isinstance(resp, dict) and resp.get('status') == 'OK':
        resp['next_step'] = (
            "Question added. Call bugasura_testpert_get_requirements(category='deepen_questions') "
            "to show the updated list."
        )
    return resp


@mcp.tool(
    name = "bugasura_testpert_delete_context_question",
    description = (
        "Delete a contextual (deepen-requirement) question from a TestPert sprint, like the "
        "delete/remove action in the platform's Deepen Requirements tab. Pass the "
        "requirement_context_id from bugasura_testpert_get_requirements(category='deepen_questions'). "
        "The sprint must be at DEEPEN_REQUIREMENTS_QUESTIONS."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def delete_testpert_context_question(
    requirement_context_id: int = Field(description="ID of the context question to delete (from get_requirements deepen_questions_list)."),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (= report_id). Required (prompts if omitted, ge=1)."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """Delete a deepen-requirement context question via /v1/testpertrequirementcontexts/delete."""
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id,
                                                'bugasura_testpert_delete_context_question')
    if 'status' in context and context['status'] == 'selection_required':
        return context
    if not sprint_id:
        return _sprint_selection_required(context['team_id'], context['project_id'])

    resp = await make_api_request('POST', '/v1/testpertrequirementcontexts/delete', api_key, data={
        'requirementContextId': str(requirement_context_id),
        'reportId': str(sprint_id),
    })
    if isinstance(resp, dict) and resp.get('status') == 'OK':
        resp['next_step'] = (
            "Question deleted. Call bugasura_testpert_get_requirements(category='deepen_questions') "
            "to show the updated list."
        )
    return resp


@mcp.tool(
    name = "bugasura_testpert_update_requirements",
    description = (
        "Write the user's review back to a TestPert sprint's requirement contexts: answers to "
        "deepen-requirement questions, and approve/reject/edit decisions on missing requirements "
        "and risks. Accepts a batch of per-row updates. Call after bugasura_testpert_get_requirements, "
        "before advancing to the next status."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def update_testpert_requirements(
    updates: List[dict] = Field(description=(
        "List of row updates. Each item: {'requirement_context_id': <int, required>, "
        "'details': <str answer/edited text, optional>, 'title': <str, optional>, "
        "'is_approved': <bool, optional>, 'is_edited': <bool, optional>}. "
        "If details/title are given and is_edited is omitted, is_edited defaults to true."
    )),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (= report_id). Required (prompts if omitted, ge=1)."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Apply per-row updates to requirement contexts via /v1/testpertrequirementcontexts/update.

    Each update targets one requirement_context_id and sends only the fields provided
    (partial update). Returns a per-item result list plus a summary count.
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id,
                                                'bugasura_testpert_update_requirements')
    if 'status' in context and context['status'] == 'selection_required':
        return context
    if not sprint_id:
        return _sprint_selection_required(context['team_id'], context['project_id'])

    if not updates:
        return {
            'status': 'failed',
            'error': 'No updates provided',
            'error_type': 'ValidationError',
            'message': 'Provide at least one item in updates.'
        }

    results = []
    succeeded = 0
    for u in updates:
        if not isinstance(u, dict):
            results.append({'requirement_context_id': None, 'status': 'failed',
                            'message': 'Each update must be an object.'})
            continue
        rcid = u.get('requirement_context_id')
        if not rcid:
            results.append({'requirement_context_id': None, 'status': 'failed',
                            'message': 'requirement_context_id is required.'})
            continue

        data = {
            'reportId': str(sprint_id),
            'appId': str(context['project_id']),
            'requirementContextId': str(rcid),
        }
        has_edit_field = False
        if u.get('details') is not None:
            data['details'] = str(u['details'])
            has_edit_field = True
        if u.get('title') is not None:
            data['title'] = str(u['title'])
            has_edit_field = True
        if u.get('is_approved') is not None:
            data['isApproved'] = '1' if u['is_approved'] else '0'
        if u.get('is_edited') is not None:
            data['isEdited'] = '1' if u['is_edited'] else '0'
        elif has_edit_field:
            # Content was changed but the caller didn't say — mark as edited.
            data['isEdited'] = '1'

        api_resp = await make_api_request('POST', '/v1/testpertrequirementcontexts/update',
                                          api_key, data=data)
        ok = isinstance(api_resp, dict) and api_resp.get('status') == 'OK'
        if ok:
            succeeded += 1
        results.append({
            'requirement_context_id': rcid,
            'status': 'OK' if ok else 'failed',
            'message': (api_resp.get('message') if isinstance(api_resp, dict) else None) or '',
        })

    overall_ok = succeeded == len(results) and succeeded > 0
    return {
        'status': 'OK' if overall_ok else 'failed',
        'sprint_id': sprint_id,
        'updated': succeeded,
        'total': len(results),
        'results': results,
        'message': (f"Saved {succeeded} of {len(results)} item(s)." +
                    ("" if overall_ok else " A few couldn't be saved — see results.")),
        'next_step': (
            "Once the user has reviewed everything, continue with bugasura_testpert_advance "
            "(to_status='GENERATE_MISSING_REQUIREMENTS' after the questions, 'RISKS_IN_REQUIREMENTS' "
            "after missing requirements, 'GENERATE_TEST_PLANING' after risks). Describe each step to "
            "the user in plain words — never show status codes or field names."
        ),
    }


@mcp.tool(
    name = "bugasura_testpert_get_testplan",
    description = (
        "Fetch a TestPert sprint's AI-generated test plan — the feature/sub-feature tree, test "
        "focus areas (with their EXHAUSTIVE/SUFFICIENT/MINIMAL/NONE levels), flows, scenarios, "
        "test models. Returns both the raw testPlanDetails and a compact edit_view (features tree + "
        "focus_areas flattened to {area: level} + allowed focus_levels + counts) for showing the "
        "user what to review and collecting edits. Use ONLY after the sprint reaches TEST_PLANING "
        "and the user wants to see or edit the plan content. "
        "Do NOT use this to check the current pipeline phase or status — call "
        "bugasura_testpert_advance (with to_status omitted) for that."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def get_testpert_testplan(
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (= report_id). Required (prompts if omitted, ge=1)."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """Read the sprint's test plan via /v1/testpert/sprint/testplan/get."""
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id,
                                                'bugasura_testpert_get_testplan')
    if 'status' in context and context['status'] == 'selection_required':
        return context
    if not sprint_id:
        return _sprint_selection_required(context['team_id'], context['project_id'])

    resp = await make_api_request('GET', '/v1/testpert/sprint/testplan/get', api_key, params={
        'appId': context['project_id'],
        'sprintId': sprint_id,
    })

    # Skip-enrich sprints hide the feature/sub-feature tree during planning (the web Features tab
    # is hidden when skipEnrichRequirements is set), so planning is focus-areas only.
    _status_resp = await _get_sprint_testpert_status_raw(api_key, context['team_id'], context['project_id'], sprint_id)
    skip_enrich = _extract_skip_enrich(_status_resp)
    _testrun_id = _extract_testrun_id(_status_resp)

    # Attach a compact, edit-ready view alongside the raw plan.
    if isinstance(resp, dict) and resp.get('status') == 'OK':
        plan = resp.get('testPlanDetails')
        if isinstance(plan, dict):
            # testplan/get returns the sprintTestPlan column or a generic default; the focus
            # areas the UI actually shows (engine output, rich) come from the KB/tab endpoint.
            rich_fa = await _fetch_sprint_focus_areas(api_key, context['team_id'],
                                                      context['project_id'], sprint_id)
            if rich_fa:
                plan['test_focus_areas'] = rich_fa
            resp['edit_view'] = _build_testplan_edit_view(plan)
            # If we only have the generic default, focus areas aren't reliably readable here —
            # warn so the assistant doesn't present/edit them as if real.
            if not rich_fa and _is_default_focus_placeholder(plan.get('test_focus_areas')):
                resp['edit_view']['focus_areas_unavailable'] = True
                resp['next_step'] = (
                    "Focus areas aren't reliably available for this sprint (only the generic default "
                    "set came back) — don't present/edit them here; bugasura_testpert_update_testplan "
                    "will refuse to avoid overwriting the real ones. Focus-area editing is reliable at "
                    "TEST_PLANING. You can still manage features via bugasura_testpert_get_features / "
                    "add_feature / delete_feature."
                )
            elif skip_enrich:
                resp['edit_view']['skip_enrich'] = True
                resp['edit_view']['features_hidden_skip_enrich'] = True
                resp['next_step'] = (
                    "Show the user edit_view.focus_areas (area -> level, options in edit_view.focus_levels) "
                    "for review/edit. This is a SKIP-ENRICH sprint, so the feature/sub-feature tree is NOT "
                    "part of planning — do NOT show or edit features (skip get_features / add_feature / "
                    "delete_feature). For focus-level edits call "
                    "bugasura_testpert_update_testplan(test_focus_areas={area: new_level}). When done, the "
                    "NEXT phase is coverage: call bugasura_testpert_generate_coverage (skip-enrich goes "
                    "straight to coverage), then bugasura_testpert_get_coverage (show the user the "
                    "coverage mind map), THEN bugasura_testpert_generate_testcases. Do NOT jump to "
                    "generate_testcases directly or skip showing coverage."
                )
            else:
                resp['next_step'] = (
                    "Show the user edit_view.focus_areas (area -> level, options in edit_view.focus_levels) "
                    "and the feature/sub-feature tree. For focus-level edits call "
                    "bugasura_testpert_update_testplan(test_focus_areas={area: new_level}). For the live "
                    "feature tree with add/delete, use bugasura_testpert_get_features + "
                    "bugasura_testpert_add_feature / bugasura_testpert_delete_feature. When the user is "
                    "done editing the plan, the NEXT phase is enrichment, then coverage: call "
                    "bugasura_testpert_enrich_requirements, then bugasura_testpert_generate_coverage, then "
                    "bugasura_testpert_get_coverage (show the user the coverage mind map), then "
                    "bugasura_testpert_generate_testcases. Do NOT jump straight to generate_testcases "
                    "or skip showing coverage."
                )
    _attach_sprint_link(resp, _testrun_id, sprint_id)
    return resp


@mcp.tool(
    name = "bugasura_testpert_update_testplan",
    description = (
        "Edit a TestPert sprint's test plan, the way the web Test Plan tab does. Set per-area focus "
        "levels (each focus area -> EXHAUSTIVE/SUFFICIENT/MINIMAL/NONE) and/or edit features, flows, "
        "scenarios, test_models and sprint_test_data. test_focus_areas MERGES: pass only the areas "
        "you want to change (by their key or display name) and the rest are preserved. The other "
        "fields (features/flows/scenarios/test_models/sprint_test_data) REPLACE wholesale, so send "
        "the complete structure from bugasura_testpert_get_testplan for those. Persists the plan "
        "only; does NOT change status (use bugasura_testpert_advance). Requires a team-admin API key."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def update_testpert_testplan(
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (= report_id). Required (prompts if omitted, ge=1)."),
    test_focus_areas: Optional[dict] = Field(default=None, description="Per-area focus levels keyed by the area name from get_testplan, e.g. {'Authentication':'EXHAUSTIVE','Reporting':'MINIMAL'}. Level is a string (or 1-item list); allowed: EXHAUSTIVE/SUFFICIENT/MINIMAL/NONE."),
    features: Optional[Any] = Field(default=None, description="Edited features structure (use the shape returned by get_testplan's testPlanDetails.features)."),
    flows: Optional[Any] = Field(default=None, description="Edited flows structure (shape from get_testplan)."),
    scenarios: Optional[Any] = Field(default=None, description="Edited scenarios structure (shape from get_testplan)."),
    test_models: Optional[Any] = Field(default=None, description="Test models: a list of names, or a comma-separated string."),
    sprint_test_data: Optional[Any] = Field(default=None, description="Edited sprint test data structure (shape from get_testplan)."),
    test_plan_details: Optional[dict] = Field(default=None, description="Advanced: full testPlanDetails object sent as-is; other params are merged on top of it."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Save test-plan edits via /v1/testpert/sprint/testplan/update (plan only, no status change).

    Mirrors the web Test Plan tab: sends testPlanDetails with only the keys provided. The backend
    persists test_focus_areas, features, flows, scenarios, test_models and sprint_test_data
    (devices/team are not updatable through this endpoint). Status transitions go through
    bugasura_testpert_advance. Backend requires the user to be a team admin.
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id,
                                                'bugasura_testpert_update_testplan')
    if 'status' in context and context['status'] == 'selection_required':
        return context
    if not sprint_id:
        return _sprint_selection_required(context['team_id'], context['project_id'])

    # Start from an optional full passthrough, then layer the individual fields on top.
    tpd = dict(test_plan_details) if isinstance(test_plan_details, dict) else {}
    if test_focus_areas is not None:
        # Read-modify-write: the backend REPLACES test_focus_areas wholesale, so merge the
        # requested changes into the CURRENT rich focus areas (the same engine data the UI shows,
        # via the KB/tab endpoint) to avoid wiping other areas / metadata and to keep the keys
        # (e.g. authentication/speed) aligned with the frontend.
        changes = _normalize_focus_areas(test_focus_areas)
        # Read the REAL current focus areas (never the default placeholder). If we can't get
        # them, REFUSE — merging into the placeholder would overwrite the real areas/keys/metadata
        # (the exact corruption seen as {"functionality":"MINIMAL","usability":["EXHAUSTIVE"],...}).
        existing_fa = await _fetch_sprint_focus_areas(api_key, context['team_id'],
                                                      context['project_id'], sprint_id)
        if not existing_fa:
            return {
                'status': 'failed',
                'error': 'Could not read the real focus areas to edit safely',
                'error_type': 'FocusAreasUnavailable',
                'message': ("Refusing to update test_focus_areas: the API returned only the generic "
                            "default set (or none) for this sprint, so merging would overwrite the real "
                            "focus areas and their metadata. Focus-area editing is reliable at the "
                            "TEST_PLANING stage; verify the api key's team matches the sprint's team."),
            }
        tpd['test_focus_areas'] = _merge_focus_areas(existing_fa, changes)
    if features is not None:
        tpd['features'] = features
    if flows is not None:
        tpd['flows'] = flows
    if scenarios is not None:
        tpd['scenarios'] = scenarios
    if sprint_test_data is not None:
        tpd['sprint_test_data'] = sprint_test_data
    if test_models is not None:
        tpd['test_models'] = ([m.strip() for m in test_models.split(',') if m.strip()]
                              if isinstance(test_models, str) else test_models)

    if not tpd:
        return {
            'status': 'failed',
            'error': 'Nothing to update',
            'error_type': 'ValidationError',
            'message': ('Provide at least one of: test_focus_areas, features, flows, scenarios, '
                        'test_models, sprint_test_data, or test_plan_details.')
        }

    data = {
        'teamId': str(context['team_id']),
        'appId': str(context['project_id']),
        'sprintId': str(sprint_id),
        'testPlanDetails': json.dumps(tpd),
    }

    logger.info(f"Saving test plan for sprint_id={sprint_id} (fields={sorted(tpd.keys())})")
    resp = await make_api_request('POST', '/v1/testpert/sprint/testplan/update', api_key, data=data)

    if isinstance(resp, dict) and resp.get('status') == 'OK':
        resp['updated_fields'] = sorted(tpd.keys())
        resp['message'] = "Saved your test-plan changes."
        resp['next_step'] = (
            "Tell the user the changes were saved (plain words, no codes). When they're done editing, the "
            "NEXT phase is enrichment, then coverage: call bugasura_testpert_enrich_requirements, then "
            "bugasura_testpert_generate_coverage, then bugasura_testpert_get_coverage (show the user the "
            "coverage mind map), then bugasura_testpert_generate_testcases. Do NOT jump straight to "
            "generate_testcases or skip showing the coverage."
        )
    return resp


@mcp.tool(
    name = "bugasura_testpert_get_coverage",
    description = (
        "Fetch a TestPert sprint's coverage mind map (feature x sub-feature tree) "
        "for display. Read-only view; to move the sprint to TEST_COVERAGE use "
        "bugasura_testpert_generate_coverage."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def get_testpert_coverage(
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (= report_id). Required (prompts if omitted, ge=1)."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """Get the coverage mind map via /v1/testpert/getSprintCoverageMindMap (flips to TEST_COVERAGE)."""
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id,
                                                'bugasura_testpert_get_coverage')
    if 'status' in context and context['status'] == 'selection_required':
        return context
    if not sprint_id:
        return _sprint_selection_required(context['team_id'], context['project_id'])

    resp = await make_api_request('GET', '/v1/testpert/getSprintCoverageMindMap', api_key, params={
        'appId': context['project_id'],
        'teamId': context['team_id'],
        'sprintId': sprint_id,
    })
    if isinstance(resp, dict) and resp.get('status') == 'OK':
        resp.pop('totalTrainingCompletionEstimationStr', None)
        resp.pop('totalTrainingCompletionCostEstimationStr', None)
        resp['next_step'] = (
            "Show the coverage mind map to the user and share the sprint_url so they can visit the "
            "Coverage tab in the platform directly. Then generate test cases with "
            "bugasura_testpert_generate_testcases."
        )
        return await _attach_link_for_sprint(resp, api_key, context['team_id'], context['project_id'],
                                             sprint_id, tab='testcoverage')
    return resp


@mcp.tool(
    name = "bugasura_testpert_generate_testcases",
    description = (
        "Generate test cases for a TestPert sprint: set the status to GENERATE_TEST_CASES and poll "
        "until either the sprint status reaches TEST_CASES OR all sub-features are COMPLETED — "
        "whichever comes first. The sprint must be at TEST_COVERAGE. While polling, each call also "
        "fetches sub-feature statuses and shows how many are COMPLETED (including the default "
        "Business Critical Flow feature) so the user can see live progress. Re-call with the "
        "returned elapsed_seconds to keep polling. Returns done and the sprint link on completion."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def generate_testpert_testcases(
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (= report_id). Required (prompts if omitted, ge=1)."),
    testrun_id: Optional[int] = Field(default=None, description="The sprint's testrun_id (for the sprint link). Optional — resolved automatically from the sprint if omitted."),
    elapsed_seconds: int = Field(default=0, description="Internal: cumulative seconds already spent polling across earlier re-calls. Pass back the value the previous response's next_step gives you."),
    max_wait_seconds: int = Field(default=30, description="Upper bound on this call's polling (0-45, default 30). Capped at 45s; call again to keep waiting."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Kick off test-case generation and poll completion via sub-feature status.

    Instead of waiting for the overall TEST_CASES sprint status, this polls
    /v1/testpert/testpertfeatures/getTestpertFeatures and counts sub-features with
    status=COMPLETED. When all sub-features are COMPLETED the sprint is done.
    This matches the platform's own progress display and avoids the need for the
    user to manually confirm or for the MCP to force-set the status.
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id,
                                                'bugasura_testpert_generate_testcases')
    if 'status' in context and context['status'] == 'selection_required':
        return context
    if not sprint_id:
        return _sprint_selection_required(context['team_id'], context['project_id'])

    tid, pid = context['team_id'], context['project_id']
    budget = max(0, min(int(max_wait_seconds), _KB_POLL_MAX_BUDGET_SECONDS))

    def _done(msg: str, completed: int = 0, total: int = 0) -> dict:
        progress = f" ({completed}/{total} sub-features)" if total else ""
        full_msg = f"{msg}{progress}"
        out = {
            'status': 'OK', 'current_status': 'TEST_CASES', 'reached': True, 'message': full_msg,
            'sub_features_completed': completed, 'sub_features_total': total,
            'next_step': _test_cases_ready_next_step(sprint_id),
        }
        url = _sprint_url(testrun_id, sprint_id, tab='testcase')
        if url:
            out['sprint_url'] = url
            out['message'] = f"{full_msg} Open the sprint: {url}"
        return out

    # Read current status; resolve testrun_id for the link.
    status_resp = await _get_sprint_testpert_status_raw(api_key, tid, pid, sprint_id)
    current = _extract_sprint_status(status_resp)
    if not testrun_id:
        testrun_id = _extract_testrun_id(status_resp)

    # Already done.
    if current == 'TEST_CASES':
        return _done("Test cases are already generated.")

    # Don't step backward into this phase from a later one.
    if _is_backward_transition(current, 'GENERATE_TEST_CASES'):
        return _backward_blocked_response(current, 'GENERATE_TEST_CASES')

    # Trigger generation if not already running.
    if current not in ('GENERATE_TEST_CASES', 'TEST_CASES_IN_PROGRESS'):
        # Use /testpert/updateSprintKBStatus (NOT /testpert/sprint/updateStatus): this is the
        # endpoint the web app uses, and it both transitions the status AND generates+uploads
        # ai-testpertkb/stats.json. The plain status-machine endpoint skips the stats.json upload,
        # after which getStats() fails for every TEST_CASES-stage read. source=PLATFORM required.
        adv = await make_api_request('POST', '/v1/testpert/updateSprintKBStatus', api_key, data={
            'appId': str(pid),
            'teamId': str(tid),
            'sprintId': str(sprint_id),
            'testpertStatus': 'GENERATE_TEST_CASES',
            'source': 'PLATFORM',
        })
        if not (isinstance(adv, dict) and adv.get('status') == 'OK'):
            return {
                'status': 'failed',
                'error': 'Could not start test-case generation',
                'error_type': 'StatusTransitionError',
                'message': (adv.get('message') if isinstance(adv, dict) else None)
                           or "The API rejected GENERATE_TEST_CASES. The sprint must be at TEST_COVERAGE.",
                'current_status': adv.get('currentTestpertStatus') if isinstance(adv, dict) else current,
                'raw': adv,
            }

    # Poll for TEST_CASES sprint status (primary completion signal).
    # On each cycle also fetch sub-features to show the user live progress.
    # Includes the default Business Critical Flow feature in the count.
    deadline = time.monotonic() + budget
    last_completed = 0
    last_total = 0

    while True:
        # Primary check: sprint status.
        status_resp2 = await _get_sprint_testpert_status_raw(api_key, tid, pid, sprint_id)
        current = _extract_sprint_status(status_resp2) or current
        if current == 'TEST_CASES':
            return _done("Test cases generated.", last_completed, last_total)
        if current and current.endswith('_ERROR'):
            return _engine_error_response(current,
                                          "Re-run bugasura_testpert_generate_testcases to retry.")

        # Secondary: fetch sub-features for progress display and as a fallback completion signal.
        # Includes the default Business Critical Flow feature in the count.
        feat_resp = await make_api_request('GET', '/v1/testpert/testpertfeatures/getTestpertFeatures',
                                           api_key, params={'appId': pid, 'report_id': sprint_id})
        if isinstance(feat_resp, dict) and feat_resp.get('status') == 'OK':
            features, _ = _group_testpert_features(feat_resp.get('testpertFeatures_details'))
            last_total = sum(len(f['sub_features']) for f in features)
            last_completed = sum(
                1 for f in features
                for sf in f['sub_features']
                if str(sf.get('status') or '').upper() == 'COMPLETED'
            )
            # All sub-features done — stop polling even if sprint status hasn't flipped yet.
            if last_total > 0 and last_completed == last_total:
                return _done("All sub-features completed — test cases generated.",
                             last_completed, last_total)

        if time.monotonic() >= deadline:
            break
        await asyncio.sleep(_KB_POLL_INTERVAL_SECONDS)

    # Timeout — return progress and ask to re-call.
    total_elapsed = max(0, int(elapsed_seconds)) + budget
    progress_msg = (f"{last_completed}/{last_total} sub-features completed"
                    if last_total else "still initialising")
    out: dict = {
        'status': 'OK',
        'current_status': current,
        'reached': False,
        'in_progress': True,
        'sub_features_completed': last_completed,
        'sub_features_total': last_total,
        'message': f"Generating test cases — {progress_msg}. " + _working_message(),
        'next_step': (
            f"Progress: {progress_msg} (~{total_elapsed}s so far). "
            f"Show the user the progress ({progress_msg}), then keep polling automatically: "
            f"call bugasura_testpert_generate_testcases again with elapsed_seconds={total_elapsed}. "
            "Do NOT ask the user to confirm — keep checking until TEST_CASES status is reached."
        ),
    }
    return _attach_sprint_link(out, testrun_id, sprint_id, tab='testcase')


@mcp.tool(
    name = "bugasura_testpert_regenerate_testcases",
    description = (
        "Regenerate test cases for a specific sub-feature once the sprint has reached TEST_CASES. "
        "Mirrors the regenerate button (green refresh icon) for COMPLETED sub-features and the "
        "retry button (circular arrow) for ERROR sub-features in the Generate tab. "
        "Get feature_id from bugasura_testpert_get_features — use the sub-feature's feature_id. "
        "IMPORTANT: this tool ALWAYS requires context input across three sections before regenerating "
        "(Gap Analysis, Test Focus Area Alignment, Context Discovery — matching the 3-step modal in "
        "the web app). When called with confirm_context=False (default) it returns the options for all "
        "three sections so the user can make their selections. You MUST present each section to the "
        "user, collect their answers, then re-call with confirm_context=True and the filled values. "
        "At least one option must be selected in EACH of the three sections. "
        "Maximum 5 attempts per sub-feature. "
        "Re-callable: if still generating when the time budget ends, call again with elapsed_seconds."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def regenerate_testpert_testcases(
    feature_id: int = Field(description="The sub-feature's feature_id to regenerate (from bugasura_testpert_get_features — the sub-feature row id, not the parent feature id)."),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (= report_id). Required (prompts if omitted, ge=1)."),
    confirm_context: bool = Field(default=False, description="Set to True only after the user has selected options for ALL THREE sections (gap_analysis, test_focus_area, context_discovery). When False (default), the tool returns the three-section options form for the user to fill in — you must show these to the user, collect their choices, then re-call with confirm_context=True."),
    gap_analysis: List[str] = Field(default=[], description="[Section 1] Selected gap analysis issues. Valid values: 'coverage_gaps', 'depth_issues', 'relevance_problems', 'technical_misalignment'. At least one required when confirm_context=True."),
    test_focus_area: List[str] = Field(default=[], description="[Section 2] Selected test focus area names from the sprint's test plan (e.g. 'Authentication', 'Reporting'). Use the labels returned in the context_required response. At least one required when confirm_context=True."),
    context_discovery: List[dict] = Field(default=[], description="[Section 3] Selected context discovery items as [{'key': str, 'value': str}] where key is one of 'missed_user_personas'/'business_constraints'/'integration_dependencies'/'risk_focus' and value is optional context text. At least one item required when confirm_context=True; value may be empty or omitted."),
    testrun_id: Optional[int] = Field(default=None, description="The sprint's testrun_id (for the sprint link). Optional — resolved automatically if omitted."),
    is_retry: bool = Field(default=False, description="True to retry a sub-feature in ERROR status (the retry/circular-arrow button); False (default) to regenerate a COMPLETED sub-feature (the green refresh icon)."),
    elapsed_seconds: int = Field(default=0, description="Internal: cumulative seconds already spent polling across earlier re-calls. Pass back the elapsed_seconds value from the previous response to keep polling."),
    max_wait_seconds: int = Field(default=30, description="Upper bound on this call's polling (0-45, default 30). Capped at 45s; call again to keep waiting."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Regenerate or retry test cases for a specific sub-feature in a TEST_CASES-phase sprint.

    Mirrors the web Generate tab's per-sub-feature regenerate (green icon, COMPLETED) and retry
    (circular arrow, ERROR) buttons. Always requires context input via the 3-section modal before
    triggering — confirm_context=False returns options, confirm_context=True proceeds with the POST.

    Maximum 5 regeneration attempts per sub-feature (same cap as the web app).

    Re-callable: pass back elapsed_seconds from the previous response to keep polling
    across call boundaries without re-triggering the generation.
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id,
                                                'bugasura_testpert_regenerate_testcases')
    if 'status' in context and context['status'] == 'selection_required':
        return context
    if not sprint_id:
        return _sprint_selection_required(context['team_id'], context['project_id'])

    tid, pid = context['team_id'], context['project_id']

    # -----------------------------------------------------------------------
    # Step 1: context_required — fetch focus areas and return the 3-section
    # options form (mirrors the 3-tab modal in the web app).
    # -----------------------------------------------------------------------
    if not confirm_context:
        raw_fa = await _fetch_sprint_focus_areas(api_key, tid, pid, sprint_id)
        fa_rows = _focus_areas_view(raw_fa) if raw_fa else []
        # Build Tab 2 options the same way the PHP controller does:
        #   ucfirst(str_replace('_', ' ', $focusIndex))
        # i.e. use the config KEY (not parent_category) formatted for display.
        seen: set = set()
        tab2_options = []
        for row in fa_rows:
            key = row.get('key') or ''
            if not key:
                continue
            display = key.replace('_', ' ')
            display = display[:1].upper() + display[1:]
            if display not in seen:
                seen.add(display)
                tab2_options.append({'value': display, 'label': display})
        if not tab2_options:
            tab2_options = [{'value': a, 'label': a}
                            for a in ('Functionality', 'Usability', 'Performance',
                                      'Security', 'Reliability')]

        return {
            'status': 'context_required',
            'feature_id': feature_id,
            'sprint_id': sprint_id,
            'message': (
                'Before regenerating, the user must choose at least one option from each of '
                'the three sections below (matching the 3-step modal in the web app). '
                'Present each section to the user one at a time and collect their selections.'
            ),
            'sections': [
                {
                    'section': 'gap_analysis',
                    'title': 'Gap Analysis',
                    'description': 'Looking at the current test cases, which specific aspects need improvement?',
                    'required': True,
                    'min_selections': 1,
                    'options': [
                        {'value': 'coverage_gaps',         'label': 'Coverage (missing scenarios, edge cases, user workflows)'},
                        {'value': 'depth_issues',          'label': 'Depth (too surface-level, missing negative tests)'},
                        {'value': 'relevance_problems',    'label': "Relevance problems (doesn't match your actual testing needs)"},
                        {'value': 'technical_misalignment','label': 'Technical misalignment (wrong level of detail, incorrect assumptions)'},
                    ],
                },
                {
                    'section': 'test_focus_area',
                    'title': 'Test Focus Area Alignment',
                    'description': 'What testing focus area aligns with your needs?',
                    'required': True,
                    'min_selections': 1,
                    'options': tab2_options,
                },
                {
                    'section': 'context_discovery',
                    'title': 'Context Discovery',
                    'description': 'What additional context should we consider?',
                    'required': True,
                    'min_selections': 1,
                    'options': [
                        {'value': 'missed_user_personas',    'label': 'Specific user personas or use cases we missed',    'needs_context': False},
                        {'value': 'business_constraints',    'label': 'Business rules or constraints not captured',       'needs_context': False},
                        {'value': 'integration_dependencies','label': 'Integration points or dependencies to test',       'needs_context': False},
                        {'value': 'risk_focus',              'label': 'Risk areas that need more focus',                  'needs_context': False},
                    ],
                    'context_format': (
                        "Pass each selected item as {'key': '<option_value>', 'value': '<context text>'} "
                        "in the context_discovery list. The value is optional and may be empty."
                    ),
                },
            ],
            'instruction': (
                'Show the user these three sections ONE AT A TIME (like a 3-step wizard). '
                'For each section, list the options and ask the user to select at least one. '
                'For Context Discovery, the user may optionally add a short description for each selected item — it is not required. '
                'After collecting all three sections, re-call this tool with confirm_context=True '
                'and the collected values in gap_analysis, test_focus_area, and context_discovery. '
                'IMPORTANT: the API caps the total context at 255 characters. Recommend the user '
                'select 1-2 Context Discovery items with brief descriptions (10-20 words each) to '
                'avoid auto-truncation. If they select all 4, context values will be trimmed to fit.'
            ),
            'next_call': (
                f'bugasura_testpert_regenerate_testcases('
                f'feature_id={feature_id}, sprint_id={sprint_id}, confirm_context=True, '
                f'gap_analysis=[...], test_focus_area=[...], '
                f"context_discovery=[{{'key': '...', 'value': '...'}}])"
            ),
        }

    # -----------------------------------------------------------------------
    # Step 2: confirm_context=True — validate all three sections, then
    # proceed with the regeneration POST.
    # -----------------------------------------------------------------------
    if not gap_analysis:
        return {
            'status': 'failed',
            'error': 'gap_analysis is required',
            'error_type': 'ValidationError',
            'message': (
                'Please select at least one option from Gap Analysis before regenerating. '
                'Call without confirm_context (or with confirm_context=False) to see the options.'
            ),
        }
    if not test_focus_area:
        return {
            'status': 'failed',
            'error': 'test_focus_area is required',
            'error_type': 'ValidationError',
            'message': (
                'Please select at least one Test Focus Area before regenerating. '
                'Call without confirm_context (or with confirm_context=False) to see the options.'
            ),
        }
    if not context_discovery:
        return {
            'status': 'failed',
            'error': 'context_discovery is required',
            'error_type': 'ValidationError',
            'message': (
                'Please select at least one Context Discovery item before regenerating. '
                'Call without confirm_context (or with confirm_context=False) to see the options.'
            ),
        }
    budget = max(0, min(int(max_wait_seconds), _KB_POLL_MAX_BUDGET_SECONDS))
    # elapsed_seconds > 0 means the POST was already sent in a prior call — skip it and
    # go straight to polling the current sub-feature status.
    is_continuation = elapsed_seconds > 0
    context_trimmed = False
    no_of_attempts = 0

    # Resolve testrun_id for the sprint link.
    if not testrun_id:
        status_resp = await _get_sprint_testpert_status_raw(api_key, tid, pid, sprint_id)
        testrun_id = _extract_testrun_id(status_resp)

    if not is_continuation:
        # Fetch the feature list to find the target sub-feature and its current attempt count.
        feat_resp = await make_api_request('GET', '/v1/testpert/testpertfeatures/getTestpertFeatures',
                                           api_key, params={'appId': pid, 'report_id': sprint_id})
        if not (isinstance(feat_resp, dict) and feat_resp.get('status') == 'OK'):
            return {
                'status': 'failed',
                'error': 'Could not fetch features',
                'error_type': 'StatusReadError',
                'message': "Could not read the sprint's feature list. Check the sprint ID and try again.",
            }

        rows = feat_resp.get('testpertFeatures_details') or []
        target_row = next(
            (r for r in rows if isinstance(r, dict) and str(r.get('feature_id')) == str(feature_id)),
            None,
        )
        if target_row is None:
            return {
                'status': 'failed',
                'error': f'Sub-feature {feature_id} not found in sprint {sprint_id}',
                'error_type': 'ValidationError',
                'message': (f"Sub-feature {feature_id} was not found in sprint {sprint_id}. "
                            "Call bugasura_testpert_get_features to list the available sub-feature IDs."),
            }

        no_of_attempts = int(target_row.get('no_of_attempts') or 0)

        # Enforce the 5-attempt limit (same cap as the web app frontend).
        if no_of_attempts >= 5:
            return {
                'status': 'failed',
                'error': 'Maximum regeneration attempts reached',
                'error_type': 'ValidationError',
                'message': (f"Sub-feature {feature_id} has reached the maximum of 5 regeneration attempts "
                            f"(current: {no_of_attempts}). No further regeneration is possible for this sub-feature."),
                'feature_id': feature_id,
                'no_of_attempts': no_of_attempts,
            }

        # Build the comments JSON (matches the 3-tab modal structure in the web app).
        # The API hard-limits comments to 255 chars. Auto-fit by first trimming context
        # values proportionally, then dropping trailing context items if still over.
        _MAX_COMMENTS = 255
        comments_obj: dict = {
            'gap_analysis': [str(v) for v in gap_analysis],
            'test_focus_area': [str(v) for v in test_focus_area],
            'context_discovery': [
                {'key': str(c.get('key', '')), 'value': str(c.get('value', ''))}
                for c in context_discovery if isinstance(c, dict)
            ],
        }
        comments_str = json.dumps(comments_obj, separators=(',', ':'), ensure_ascii=False)
        if len(comments_str) > _MAX_COMMENTS:
            cd = list(comments_obj['context_discovery'])
            # Phase 1: trim value strings proportionally until they fit or are empty.
            while len(comments_str) > _MAX_COMMENTS and any(c['value'] for c in cd):
                over = len(comments_str) - _MAX_COMMENTS
                total_val = sum(len(c['value']) for c in cd)
                if not total_val:
                    break
                new_cd = []
                for c in cd:
                    cut = max(1, round(len(c['value']) / total_val * over)) if c['value'] else 0
                    new_cd.append({'key': c['key'], 'value': c['value'][:max(0, len(c['value']) - cut)]})
                cd = new_cd
                tmp = dict(comments_obj)
                tmp['context_discovery'] = cd
                comments_str = json.dumps(tmp, separators=(',', ':'), ensure_ascii=False)
            # Phase 2: drop items from the end if the structure itself is still over 255.
            while len(comments_str) > _MAX_COMMENTS and cd:
                cd = cd[:-1]
                tmp = dict(comments_obj)
                tmp['context_discovery'] = cd
                comments_str = json.dumps(tmp, separators=(',', ':'), ensure_ascii=False)
            comments_obj['context_discovery'] = cd
            context_trimmed = True
            logger.warning(f"comments trimmed to {len(comments_str)} chars for feature_id={feature_id}")

        logger.info(f"{'Retrying' if is_retry else 'Regenerating'} feature_id={feature_id} "
                    f"in sprint_id={sprint_id} (attempt {no_of_attempts + 1}/5)")
        adv = await make_api_request(
            'POST', '/v1/testpert/testpertfeatures/updateTestpertFeatures', api_key,
            data={
                'appId': str(pid),
                'reportId': str(sprint_id),
                'featureId': str(feature_id),
                'comments': comments_str,
                'noOfAttempts': str(no_of_attempts + 1),
                'isReRun': '0' if is_retry else '1',
                'isRetry': '1' if is_retry else '0',
                'status': 'START',
            }
        )
        if not (isinstance(adv, dict) and adv.get('status') == 'OK'):
            return {
                'status': 'failed',
                'error': 'Could not start regeneration',
                'error_type': 'StatusTransitionError',
                'message': ((adv.get('message') if isinstance(adv, dict) else None)
                            or "The API rejected the regeneration request. "
                               "The sprint must be at TEST_CASES and the sub-feature must exist."),
                'raw': adv,
            }

    # Poll getTestpertFeatures until this specific sub-feature reaches COMPLETED or ERROR.
    deadline = time.monotonic() + budget
    while True:
        await asyncio.sleep(_KB_POLL_INTERVAL_SECONDS)
        poll_resp = await make_api_request('GET', '/v1/testpert/testpertfeatures/getTestpertFeatures',
                                           api_key, params={'appId': pid, 'report_id': sprint_id})
        if isinstance(poll_resp, dict) and poll_resp.get('status') == 'OK':
            for r in (poll_resp.get('testpertFeatures_details') or []):
                if not (isinstance(r, dict) and str(r.get('feature_id')) == str(feature_id)):
                    continue
                fs = str(r.get('status') or '').upper()
                if fs == 'COMPLETED':
                    out = {
                        'status': 'OK',
                        'feature_id': feature_id,
                        'feature_status': 'COMPLETED',
                        'no_of_attempts': no_of_attempts + 1,
                        'reached': True,
                        'message': f"Test cases regenerated for sub-feature {feature_id}.",
                        'next_step': (
                            "Tell the user their regenerated test cases are ready and share the "
                            "sprint_url. To regenerate another sub-feature call "
                            "bugasura_testpert_get_features to list remaining sub-features, then "
                            "bugasura_testpert_regenerate_testcases again with a different feature_id."
                        ),
                    }
                    if context_trimmed:
                        out['context_note'] = (
                            "The comments JSON was auto-trimmed to fit the API's 255-character limit. "
                            "To avoid trimming, provide shorter context values or select fewer Context "
                            "Discovery items (1-2 recommended)."
                        )
                    return _attach_sprint_link(out, testrun_id, sprint_id, tab='testcase')
                if fs == 'ERROR':
                    return {
                        'status': 'failed',
                        'feature_id': feature_id,
                        'feature_status': 'ERROR',
                        'error': 'Regeneration failed for this sub-feature',
                        'error_type': 'TestpertEngineError',
                        'message': (
                            f"The regeneration of sub-feature {feature_id} failed (attempt "
                            f"{no_of_attempts + 1}/5). You can retry it: call "
                            "bugasura_testpert_regenerate_testcases with "
                            f"feature_id={feature_id}, sprint_id={sprint_id}, is_retry=True."
                        ),
                    }
                break  # Still in progress — keep polling

        if time.monotonic() >= deadline:
            break

    total_elapsed = max(0, int(elapsed_seconds)) + budget
    out = {
        'status': 'OK',
        'feature_id': feature_id,
        'reached': False,
        'in_progress': True,
        'message': f"Regenerating test cases for sub-feature {feature_id} — " + _working_message(),
        'next_step': (
            f"Keep polling: call bugasura_testpert_regenerate_testcases again with "
            f"feature_id={feature_id}, sprint_id={sprint_id}, confirm_context=True, "
            f"gap_analysis={gap_analysis!r}, test_focus_area={test_focus_area!r}, "
            f"context_discovery={context_discovery!r}, elapsed_seconds={total_elapsed}. "
            "Do NOT ask the user to confirm — keep checking until the sub-feature is COMPLETED."
        ),
    }
    return _attach_sprint_link(out, testrun_id, sprint_id, tab='testcase')


# --- Enrich requirements (TEST_PLANING -> ENRICH_REQUIREMENTS) — visible step --
@mcp.tool(
    name = "bugasura_testpert_enrich_requirements",
    description = (
        "Run the requirements-enrichment phase as a visible step: set GENERATE_ENRICH_REQUIREMENTS and "
        "poll until ENRICH_REQUIREMENTS. Use this after the test plan (TEST_PLANING) and before coverage "
        "so enrichment is explicit. Re-callable; if it's still enriching, call again. NOT used for "
        "skip-enrich sprints (those already reach ENRICH_REQUIREMENTS via the requirements step). "
        "After this, continue with bugasura_testpert_generate_coverage. (generate_coverage can also run "
        "enrichment itself, so this tool is optional — it just makes the phase visible.)"
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def enrich_testpert_requirements(
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (= report_id). Required (prompts if omitted, ge=1)."),
    testrun_id: Optional[int] = Field(default=None, description="The sprint's testrun_id (for the sprint link). Optional — resolved automatically if omitted."),
    max_wait_seconds: int = Field(default=45, description="Upper bound on polling while enrichment runs (0-45, default 45). Capped at 45s; re-call to keep waiting."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Drive the enrichment phase TEST_PLANING -> GENERATE_ENRICH_REQUIREMENTS -> ENRICH_REQUIREMENTS.

    Re-callable: returns done if already ENRICH_REQUIREMENTS; if already generating it just polls;
    otherwise (at TEST_PLANING / *_ERROR) it sets GENERATE_ENRICH_REQUIREMENTS then polls. Skip-enrich
    sprints don't use this (they reach ENRICH_REQUIREMENTS via start_skip_testplan). generate_coverage
    still bundles enrichment, so this tool is an optional, visible front-half of that.
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id,
                                                'bugasura_testpert_enrich_requirements')
    if 'status' in context and context['status'] == 'selection_required':
        return context
    if not sprint_id:
        return _sprint_selection_required(context['team_id'], context['project_id'])

    tid, pid = context['team_id'], context['project_id']
    budget = max(0, min(int(max_wait_seconds), _KB_POLL_MAX_BUDGET_SECONDS))

    status_resp = await _get_sprint_testpert_status_raw(api_key, tid, pid, sprint_id)
    current = _extract_sprint_status(status_resp)
    skip_enrich = _extract_skip_enrich(status_resp)
    if not testrun_id:
        testrun_id = _extract_testrun_id(status_resp)

    # Skip-enrich sprints reach ENRICH_REQUIREMENTS through the requirements step, not here.
    if skip_enrich:
        return {
            'status': 'failed',
            'error': 'Not used for skip-enrich sprints',
            'error_type': 'ValidationError',
            'message': ("This is a skip-enrich sprint — it reaches the enriched state via the "
                        "requirements step (bugasura_testpert_start_skip_testplan), not a separate enrich "
                        "phase. Continue with bugasura_testpert_generate_coverage."),
            'current_status': current,
        }

    if current == 'ENRICH_REQUIREMENTS':
        return _attach_sprint_link({
            'status': 'OK', 'current_status': 'ENRICH_REQUIREMENTS', 'reached': True,
            'message': "The requirements are enriched.",
            'next_step': (
                "Next phase is coverage: call bugasura_testpert_generate_coverage, then "
                "bugasura_testpert_get_coverage (show the user the coverage mind map), then "
                "bugasura_testpert_generate_testcases."
            ),
        }, testrun_id, sprint_id)

    # Don't step backward into enrichment from a later phase.
    if _is_backward_transition(current, 'GENERATE_ENRICH_REQUIREMENTS'):
        return _backward_blocked_response(current, 'GENERATE_ENRICH_REQUIREMENTS')

    # Set GENERATE_ENRICH_REQUIREMENTS unless it's already generating.
    if current != 'GENERATE_ENRICH_REQUIREMENTS':
        if current not in ('TEST_PLANING', 'ENRICH_REQUIREMENTS_ERROR'):
            return {
                'status': 'failed',
                'error': 'Enrichment runs after the test plan',
                'error_type': 'StatusTransitionError',
                'message': ("Requirements enrichment runs from the test plan stage (TEST_PLANING). "
                            f"The sprint is at the {_friendly(current)} stage."),
                'current_status': current,
            }
        enr = await make_api_request('POST', '/v1/testpert/sprint/updateStatus', api_key, data={
            'appId': str(pid), 'teamId': str(tid), 'sprintId': str(sprint_id),
            'testpertStatus': 'GENERATE_ENRICH_REQUIREMENTS',
        })
        if not (isinstance(enr, dict) and enr.get('status') == 'OK'):
            return {
                'status': 'failed',
                'error': 'Could not start requirements enrichment',
                'error_type': 'StatusTransitionError',
                'message': (enr.get('message') if isinstance(enr, dict) else None)
                           or "The API rejected GENERATE_ENRICH_REQUIREMENTS.",
                'current_status': enr.get('currentTestpertStatus') if isinstance(enr, dict) else current,
                'raw': enr,
            }

    poll = await _poll_sprint_until(api_key, tid, pid, sprint_id, 'ENRICH_REQUIREMENTS', budget)
    if poll['outcome'] == 'reached':
        return _attach_sprint_link({
            'status': 'OK', 'current_status': 'ENRICH_REQUIREMENTS', 'reached': True,
            'message': "I've enriched the requirements.",
            'next_step': (
                "Next phase is coverage: call bugasura_testpert_generate_coverage, then "
                "bugasura_testpert_get_coverage (show the user the coverage mind map), then "
                "bugasura_testpert_generate_testcases."
            ),
        }, testrun_id, sprint_id)
    if poll['outcome'] == 'error':
        return _engine_error_response(poll['current'],
                                      "Re-run bugasura_testpert_enrich_requirements to retry.")
    if poll['outcome'] == 'read_error':
        return {
            'status': 'failed', 'error': 'Could not read sprint status',
            'error_type': 'StatusReadError', 'raw': poll.get('raw'),
            'message': "I couldn't read the sprint's progress just now — please try again.",
        }
    return _attach_sprint_link({
        'status': 'OK', 'current_status': poll['current'], 'reached': False, 'in_progress': True,
        'message': "Enriching the requirements — " + _working_message(),
        'next_step': "Call bugasura_testpert_enrich_requirements again to keep checking.",
    }, testrun_id, sprint_id)


# --- Move to test coverage (ENRICH_REQUIREMENTS -> TEST_COVERAGE) -----------
@mcp.tool(
    name = "bugasura_testpert_generate_coverage",
    description = (
        "Move a TestPert sprint to TEST_COVERAGE (required before generating test cases). Honors the "
        "sprint's enrich setting: if requirements-enrichment is NOT skipped, this first runs the enrich "
        "phase (GENERATE_ENRICH_REQUIREMENTS -> ENRICH_REQUIREMENTS) and only then sets TEST_COVERAGE, "
        "so the enrich step is never silently jumped. If enrich is skipped for the sprint, it goes "
        "TEST_PLANING -> TEST_COVERAGE directly. Re-callable; if enrich is still running it reports "
        "progress and you call again."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def generate_testpert_coverage(
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (= report_id). Required (prompts if omitted, ge=1)."),
    testrun_id: Optional[int] = Field(default=None, description="The sprint's testrun_id (from the create response); when given, a clickable sprint link is included."),
    max_wait_seconds: int = Field(default=45, description="Upper bound on polling while the enrich phase runs (0-45, default 45). Capped at 45s; re-call to keep waiting."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Set TEST_COVERAGE via /v1/testpert/sprint/updateStatus.

    TEST_COVERAGE is a valid direct transition from ENRICH_REQUIREMENTS / TEST_PLANING in the
    status switch (Testpert.php:1540), so this is a single synchronous status update — no
    GENERATE_TEST_COVERAGE marker, no test-plan write, no admin requirement.
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id,
                                                'bugasura_testpert_generate_coverage')
    if 'status' in context and context['status'] == 'selection_required':
        return context
    if not sprint_id:
        return _sprint_selection_required(context['team_id'], context['project_id'])

    tid, pid = context['team_id'], context['project_id']
    budget = max(0, min(int(max_wait_seconds), _KB_POLL_MAX_BUDGET_SECONDS))

    status_resp = await _get_sprint_testpert_status_raw(api_key, tid, pid, sprint_id)
    current = _extract_sprint_status(status_resp)
    skip_enrich = _extract_skip_enrich(status_resp)
    if not testrun_id:
        testrun_id = _extract_testrun_id(status_resp)

    if current == 'TEST_COVERAGE':
        return _attach_sprint_link({
            'status': 'OK', 'current_status': 'TEST_COVERAGE', 'reached': True,
            'message': "Test coverage is ready.",
            'next_step': (
                "Show the user the coverage mind map: call bugasura_testpert_get_coverage and display "
                "the features, sub-features, and time/cost estimates. Share the sprint_url so they can "
                "visit the Coverage tab in the platform. Then proceed to bugasura_testpert_generate_testcases."
            ),
        }, testrun_id, sprint_id, tab='testcoverage')

    # Don't step backward into test coverage from a later phase (e.g. TEST_CASES).
    if _is_backward_transition(current, 'TEST_COVERAGE'):
        return _backward_blocked_response(current, 'TEST_COVERAGE')

    # Enrich gate: unless the sprint was created to skip enrichment, we must NOT jump straight
    # from TEST_PLANING to TEST_COVERAGE (the status machine allows it, but doing so skips the
    # GENERATE_ENRICH_REQUIREMENTS -> ENRICH_REQUIREMENTS phase). Drive enrich first, then poll.
    if not skip_enrich and current in ('TEST_PLANING', 'GENERATE_ENRICH_REQUIREMENTS', 'ENRICH_REQUIREMENTS_ERROR'):
        if current in ('TEST_PLANING', 'ENRICH_REQUIREMENTS_ERROR'):
            enr = await make_api_request('POST', '/v1/testpert/sprint/updateStatus', api_key, data={
                'appId': str(pid),
                'teamId': str(tid),
                'sprintId': str(sprint_id),
                'testpertStatus': 'GENERATE_ENRICH_REQUIREMENTS',
            })
            if not (isinstance(enr, dict) and enr.get('status') == 'OK'):
                return {
                    'status': 'failed',
                    'error': 'Could not start requirements enrichment',
                    'error_type': 'StatusTransitionError',
                    'message': (enr.get('message') if isinstance(enr, dict) else None)
                               or "The API rejected GENERATE_ENRICH_REQUIREMENTS.",
                    'current_status': enr.get('currentTestpertStatus') if isinstance(enr, dict) else current,
                    'raw': enr,
                }

        # Poll until the engine finishes enrichment.
        poll = await _poll_sprint_until(api_key, tid, pid, sprint_id, 'ENRICH_REQUIREMENTS', budget)
        if poll['outcome'] == 'error':
            return _engine_error_response(poll['current'],
                                          "Re-run bugasura_testpert_generate_coverage to retry enrichment.")
        if poll['outcome'] == 'read_error':
            return {
                'status': 'failed', 'error': 'Could not read sprint status',
                'error_type': 'StatusReadError', 'raw': poll.get('raw'),
                'message': "I couldn't read the sprint's progress just now — please try again.",
            }
        if poll['outcome'] != 'reached':  # timeout — still enriching
            return _attach_sprint_link({
                'status': 'OK', 'current_status': poll['current'], 'reached': False, 'in_progress': True,
                'message': "Enriching the requirements — " + _working_message(),
                'next_step': "Call bugasura_testpert_generate_coverage again to keep going (it will move to coverage once enrichment finishes).",
            }, testrun_id, sprint_id)
        current = 'ENRICH_REQUIREMENTS'

    adv = await make_api_request('POST', '/v1/testpert/sprint/updateStatus', api_key, data={
        'appId': str(pid),
        'teamId': str(tid),
        'sprintId': str(sprint_id),
        'testpertStatus': 'TEST_COVERAGE',
    })
    if not (isinstance(adv, dict) and adv.get('status') == 'OK'):
        return {
            'status': 'failed',
            'error': 'Could not set TEST_COVERAGE',
            'error_type': 'StatusTransitionError',
            'message': (adv.get('message') if isinstance(adv, dict) else None)
                       or "The API rejected TEST_COVERAGE. It is valid only from ENRICH_REQUIREMENTS or TEST_PLANING.",
            'current_status': adv.get('currentTestpertStatus') if isinstance(adv, dict) else current,
            'raw': adv,
        }

    return _attach_sprint_link({
        'status': 'OK', 'current_status': 'TEST_COVERAGE', 'reached': True,
        'message': "Test coverage is ready.",
        'next_step': (
            "Show the user the coverage mind map first: call bugasura_testpert_get_coverage and "
            "display the features, sub-features, and time/cost estimates. Also share the sprint_url "
            "so the user can visit the Coverage tab in the platform. Do NOT jump straight to "
            "bugasura_testpert_generate_testcases — the user must see the coverage before generation."
        ),
    }, testrun_id, sprint_id, tab='testcoverage')


@mcp.tool(
    name = "bugasura_testpert_get_features",
    description = (
        "List a TestPert sprint's features and sub-features as a tree (the live set the Features tab "
        "edits). Use this to show the feature/sub-feature breakdown in the test-plan phase and to get "
        "the feature_ids needed to add or delete. Pairs with bugasura_testpert_add_feature and "
        "bugasura_testpert_delete_feature."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def get_testpert_features(
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (= report_id). Required (prompts if omitted, ge=1)."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """Read the feature tree via /v1/testpert/testpertfeatures/getTestpertFeatures and group it."""
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id,
                                                'bugasura_testpert_get_features')
    if 'status' in context and context['status'] == 'selection_required':
        return context
    if not sprint_id:
        return _sprint_selection_required(context['team_id'], context['project_id'])

    _feat_params = {'appId': context['project_id'], 'report_id': sprint_id}
    resp = await make_api_request('GET', '/v1/testpert/testpertfeatures/getTestpertFeatures', api_key, params=_feat_params)
    if not (isinstance(resp, dict) and resp.get('status') == 'OK'):
        return resp

    features, orphans = _group_testpert_features(resp.get('testpertFeatures_details'))
    # Exclude the platform's built-in "Business Critical Flow" default feature from the
    # editable list — it is hidden in the web Features tab as well.
    features = [f for f in features if str(f.get('is_default') or '0') != '1']

    # At TEST_PLANING the engine may write features to the DB just after setting the status.
    # Retry once with a short delay to handle that race window (filter first so a response
    # containing only the default feature also triggers the retry).
    if not features:
        await asyncio.sleep(3)
        resp = await make_api_request('GET', '/v1/testpert/testpertfeatures/getTestpertFeatures', api_key, params=_feat_params)
        if isinstance(resp, dict) and resp.get('status') == 'OK':
            features, orphans = _group_testpert_features(resp.get('testpertFeatures_details'))
            features = [f for f in features if str(f.get('is_default') or '0') != '1']

    result = {
        'status': 'OK',
        'sprint_id': sprint_id,
        'features': features,
        'counts': {
            'features': len(features),
            'sub_features': sum(len(f['sub_features']) for f in features),
        },
        'message': ("Show features and their sub-features. Add with bugasura_testpert_add_feature "
                    "(parent_feature_id = the feature's id) or delete with "
                    "bugasura_testpert_delete_feature (feature_id). When feature edits are done, the NEXT "
                    "phase is enrichment, then coverage: call bugasura_testpert_enrich_requirements, then "
                    "bugasura_testpert_generate_coverage, then bugasura_testpert_get_coverage (show the "
                    "user the coverage mind map), then bugasura_testpert_generate_testcases — do NOT go "
                    "straight to test cases or skip showing coverage."),
    }
    if not features:
        result['message'] = (
            "No features found yet. If the sprint just reached TEST_PLANING, try calling "
            "bugasura_testpert_get_features again in a moment — the engine may still be writing them. "
            "Otherwise check that the sprint is at TEST_PLANING or later."
        )
    if orphans:
        result['orphan_sub_features'] = orphans
    return await _attach_link_for_sprint(result, api_key, context['team_id'], context['project_id'], sprint_id)


@mcp.tool(
    name = "bugasura_testpert_add_feature",
    description = (
        "Add a feature or sub-feature to a TestPert sprint, like the '+Add' control in the web "
        "Features tab. For a sub-feature (the common case) pass parent_feature_id and is_parent=False; "
        "for a new top-level feature pass is_parent=True. Get feature_ids from "
        "bugasura_testpert_get_features."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def add_testpert_feature(
    feature_name: str = Field(description="Name of the feature / sub-feature to add."),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (= report_id). Required (prompts if omitted, ge=1)."),
    parent_feature_id: Optional[int] = Field(default=None, description="Parent feature's id — required when adding a sub-feature (is_parent=False)."),
    is_parent: bool = Field(default=False, description="True to add a top-level feature; False (default) to add a sub-feature under parent_feature_id."),
    is_api_endpoint: bool = Field(default=False, description="Mark the feature as an API endpoint (default False)."),
    requirement_id: Optional[int] = Field(default=None, description="Optional requirement id to link the sub-feature to."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """Add a feature/sub-feature via /v1/testpert/testpertfeatures/addTestpertFeatures."""
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id,
                                                'bugasura_testpert_add_feature')
    if 'status' in context and context['status'] == 'selection_required':
        return context
    if not sprint_id:
        return _sprint_selection_required(context['team_id'], context['project_id'])

    if not (feature_name or '').strip():
        return {'status': 'failed', 'error': 'feature_name is required',
                'error_type': 'ValidationError', 'message': 'Provide a feature_name.'}
    if not is_parent and not parent_feature_id:
        return {'status': 'failed', 'error': 'parent_feature_id required for a sub-feature',
                'error_type': 'ValidationError',
                'message': 'Adding a sub-feature needs parent_feature_id (or set is_parent=True for a top-level feature).'}

    data = {
        'appId': str(context['project_id']),
        'reportId': str(sprint_id),
        'featureName': feature_name.strip(),
        'isParentFeatureId': '1' if is_parent else '0',
        'parentFeatureId': str(parent_feature_id) if parent_feature_id else '',
        'isApiEndpoint': '1' if is_api_endpoint else '0',
    }
    if requirement_id is not None:
        data['requirementId'] = str(requirement_id)

    logger.info(f"Adding {'feature' if is_parent else 'sub-feature'} '{feature_name}' to sprint_id={sprint_id}")
    resp = await make_api_request('POST', '/v1/testpert/testpertfeatures/addTestpertFeatures', api_key, data=data)
    if isinstance(resp, dict) and resp.get('status') == 'OK':
        resp['next_step'] = "Re-read with bugasura_testpert_get_features to show the updated tree."
    return resp


@mcp.tool(
    name = "bugasura_testpert_delete_feature",
    description = (
        "Delete a feature or sub-feature from a TestPert sprint, like the 'x' on a feature in the web "
        "Features tab. Pass the feature_id (from bugasura_testpert_get_features)."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def delete_testpert_feature(
    feature_id: int = Field(description="Id of the feature / sub-feature to delete."),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (= report_id). Required (prompts if omitted, ge=1)."),
    requirement_id: Optional[Any] = Field(default=None, description="Optional requirement id (or list of ids) linked to the feature, to unlink on delete."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """Delete a feature/sub-feature via /v1/testpert/testpertfeatures/deleteTestpertFeatures."""
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id,
                                                'bugasura_testpert_delete_feature')
    if 'status' in context and context['status'] == 'selection_required':
        return context
    if not sprint_id:
        return _sprint_selection_required(context['team_id'], context['project_id'])

    data = {
        'featureId': str(feature_id),
        'appId': str(context['project_id']),
        'reportId': str(sprint_id),
    }
    if requirement_id is not None:
        # Backend json_decodes requirementId; accept a single id or a list.
        data['requirementId'] = json.dumps(requirement_id)

    logger.info(f"Deleting feature_id={feature_id} from sprint_id={sprint_id}")
    resp = await make_api_request('POST', '/v1/testpert/testpertfeatures/deleteTestpertFeatures', api_key, data=data)
    if isinstance(resp, dict) and resp.get('status') == 'OK':
        resp['next_step'] = "Re-read with bugasura_testpert_get_features to show the updated tree."
    return resp


# --- Start requirement analysis (GENERATE_SPRINT_CONTEXT -> DEEPEN_REQUIREMENTS_QUESTIONS) ---
@mcp.tool(
    name = "bugasura_testpert_generate_sprint_context",
    description = (
        "Start requirement analysis after the knowledge base is uploaded: set the status to "
        "GENERATE_SPRINT_CONTEXT and poll until it becomes DEEPEN_REQUIREMENTS_QUESTIONS. The sprint "
        "must be at KNOWLEDGE_BASE (where bugasura_testpert_upload_kb leaves it) and have at least one "
        "connected KB. If it's still running when the time budget ends, call again to keep polling."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def generate_testpert_sprint_context(
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (= report_id). Required (prompts if omitted, ge=1)."),
    testrun_id: Optional[int] = Field(default=None, description="The sprint's testrun_id (from the create response); when given, a clickable sprint link is included."),
    max_wait_seconds: int = Field(default=30, description="Upper bound on this call's polling (0-45, default 30). Capped at 45s; call again to keep waiting."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Kick off sprint-context / requirement analysis and poll to the questions stage.

    Reads the current status first (re-callable): returns done if already
    DEEPEN_REQUIREMENTS_QUESTIONS; if already generating it just polls; otherwise it sets
    GENERATE_SPRINT_CONTEXT (valid from KNOWLEDGE_BASE) then polls until
    DEEPEN_REQUIREMENTS_QUESTIONS.
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id,
                                                'bugasura_testpert_generate_sprint_context')
    if 'status' in context and context['status'] == 'selection_required':
        return context
    if not sprint_id:
        return _sprint_selection_required(context['team_id'], context['project_id'])

    tid, pid = context['team_id'], context['project_id']
    budget = max(0, min(int(max_wait_seconds), _KB_POLL_MAX_BUDGET_SECONDS))

    status_resp = await _get_sprint_testpert_status_raw(api_key, tid, pid, sprint_id)
    current = _extract_sprint_status(status_resp)
    if not testrun_id:
        testrun_id = _extract_testrun_id(status_resp)

    if current == 'DEEPEN_REQUIREMENTS_QUESTIONS':
        msg, ns = _REACHED['DEEPEN_REQUIREMENTS_QUESTIONS']
        return _attach_sprint_link({'status': 'OK', 'current_status': 'DEEPEN_REQUIREMENTS_QUESTIONS',
                'reached': True, 'message': msg, 'next_step': ns}, testrun_id, sprint_id)

    # Don't restart requirement analysis from a later phase — that's a backward move.
    if _is_backward_transition(current, 'GENERATE_SPRINT_CONTEXT'):
        return _backward_blocked_response(current, 'GENERATE_SPRINT_CONTEXT')

    # Only set GENERATE_SPRINT_CONTEXT if not already generating.
    if current not in ('GENERATE_SPRINT_CONTEXT', 'SPRINT_CONTEXT_IN_PROGRESS'):
        adv = await make_api_request('POST', '/v1/testpert/sprint/updateStatus', api_key, data={
            'appId': str(pid),
            'teamId': str(tid),
            'sprintId': str(sprint_id),
            'testpertStatus': 'GENERATE_SPRINT_CONTEXT',
        })
        if not (isinstance(adv, dict) and adv.get('status') == 'OK'):
            return {
                'status': 'failed',
                'error': 'Could not start sprint context generation',
                'error_type': 'StatusTransitionError',
                'message': (adv.get('message') if isinstance(adv, dict) else None)
                           or ("The API rejected GENERATE_SPRINT_CONTEXT. The sprint must be at "
                               "KNOWLEDGE_BASE with at least one connected KB — upload documents first."),
                'current_status': adv.get('currentTestpertStatus') if isinstance(adv, dict) else current,
                'raw': adv,
            }

    poll = await _poll_sprint_until(api_key, tid, pid, sprint_id, 'DEEPEN_REQUIREMENTS_QUESTIONS', budget)
    if poll['outcome'] == 'reached':
        msg, ns = _REACHED['DEEPEN_REQUIREMENTS_QUESTIONS']
        return _attach_sprint_link({'status': 'OK', 'current_status': 'DEEPEN_REQUIREMENTS_QUESTIONS',
                'reached': True, 'message': msg, 'next_step': ns}, testrun_id, sprint_id)
    if poll['outcome'] == 'error':
        return _engine_error_response(
            poll['current'], "Re-run bugasura_testpert_generate_sprint_context to retry, or revisit the knowledge base.")
    if poll['outcome'] == 'read_error':
        return {
            'status': 'failed', 'error': 'Could not read sprint status',
            'error_type': 'StatusReadError', 'raw': poll.get('raw'),
            'message': "I couldn't read the sprint's progress just now — please try again.",
        }
    # timeout
    return {
        'status': 'OK', 'current_status': poll['current'], 'reached': False, 'in_progress': True,
        'message': _working_message(),
        'next_step': "Call bugasura_testpert_generate_sprint_context again to keep checking.",
    }


# --- Answer the contextual (deepen) questions ------------------------------
@mcp.tool(
    name = "bugasura_testpert_answer_context_questions",
    description = (
        "Submit the user's answers to a TestPert sprint's contextual (deepen-requirement) questions. "
        "Each answer is saved per-row via /testpertrequirementcontexts/update (writes the answer to the "
        "row's details column, isEdited=1) — no status change on save. Partial answers are fine (answer "
        "only the questions you want). By default this then advances to GENERATE_MISSING_REQUIREMENTS and "
        "polls until MISSING_REQUIREMENTS. Requires a team-admin API key. "
        "Use this for the DEEPEN questions; use bugasura_testpert_update_requirements for missing-req / risk edits."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def answer_testpert_context_questions(
    answers: List[dict] = Field(description=(
        "List of answers, each {'requirement_context_id': <int>, 'response': <str>}. "
        "Use the requirement_context_id and query from bugasura_testpert_get_requirements(category='deepen_questions'). "
        "Only the questions you include are answered; the rest keep their current response."
    )),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (= report_id). Required (prompts if omitted, ge=1)."),
    advance: bool = Field(default=True, description="If True (default), advance to GENERATE_MISSING_REQUIREMENTS and poll until MISSING_REQUIREMENTS. If False, just save the answers."),
    max_wait_seconds: int = Field(default=30, description="Upper bound on polling when advance=True (0-45, default 30). Capped at 45s; call again to keep waiting."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Persist contextual-question answers per-row via /v1/testpertrequirementcontexts/update.

    Fetches the current deepen questions to validate the provided requirement_context_ids, then
    writes each answer to its row's `details` column (isEdited=1). Saving does not change the
    sprint status; when advance=True a separate /testpert/sprint/updateStatus call moves the
    sprint to GENERATE_MISSING_REQUIREMENTS and polls until MISSING_REQUIREMENTS.
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id,
                                                'bugasura_testpert_answer_context_questions')
    if 'status' in context and context['status'] == 'selection_required':
        return context
    if not sprint_id:
        return _sprint_selection_required(context['team_id'], context['project_id'])

    tid, pid = context['team_id'], context['project_id']

    if not answers:
        return {'status': 'failed', 'error': 'No answers provided', 'error_type': 'ValidationError',
                'message': 'Provide at least one {requirement_context_id, response} in answers.'}

    # Answering the deepen questions belongs to that phase; refuse if the sprint has
    # already moved past it (the status this would set would step the flow backward).
    target_status = 'GENERATE_MISSING_REQUIREMENTS' if advance else 'DEEPEN_REQUIREMENTS_QUESTIONS'
    _status_before_resp = await _get_sprint_testpert_status_raw(api_key, tid, pid, sprint_id)
    current_before = _extract_sprint_status(_status_before_resp)
    _testrun_id = _extract_testrun_id(_status_before_resp)
    if _is_backward_transition(current_before, target_status):
        return _backward_blocked_response(current_before, target_status)

    # Read current deepen questions to merge answers into (preserves query / sub-category / others).
    ctx_resp = await make_api_request('GET', '/v1/testpertrequirementcontexts/get', api_key, params={
        'appId': pid, 'reportId': sprint_id,
    })
    grouped = _group_requirement_contexts(
        ctx_resp.get('testpertRequirementContexts') if isinstance(ctx_resp, dict) and ctx_resp.get('status') == 'OK' else [])
    deepen = grouped['deepen_questions']
    if not deepen:
        return {
            'status': 'failed', 'error': 'No contextual questions to answer',
            'error_type': 'ValidationError',
            'message': ("No deepen-requirement questions found. Make sure the sprint is at "
                        "DEEPEN_REQUIREMENTS_QUESTIONS (run bugasura_testpert_generate_sprint_context first)."),
        }

    # Build {rcid: response} lookup from the caller's answers.
    lookup = {}
    for a in answers:
        if isinstance(a, dict) and a.get('requirement_context_id') is not None:
            lookup[str(a['requirement_context_id'])] = a.get('response', '') or ''

    # Index the live deepen rows by requirement_context_id (the answer lives in the
    # `details` column; the question text is in `title`).
    rows_by_id = {}
    total = 0
    for questions in deepen.values():
        for q in questions:
            total += 1
            rows_by_id[str(q.get('requirement_context_id'))] = q

    # Step 1 — SAVE each answer per row via /testpertrequirementcontexts/update. This writes
    # the answer to the row's `details` column (isEdited=1) WITHOUT touching the status machine.
    # We deliberately do NOT use /testpertKB/sprintProblemContext/addUpdate here: that endpoint
    # force-updates the sprint status to one of CONTEXT_APPROVE/GENERATE_TEST_PLANING/
    # TEST_PLANING_IN_PROGRESS (KnowledgeBase.php:4054 + 4261-4276, gate commented out), none of
    # which are legal from DEEPEN_REQUIREMENTS_QUESTIONS — so it errors regardless of payload.
    answered = 0
    matched = set()
    failed = []
    for key, resp in lookup.items():
        if key not in rows_by_id:
            continue
        matched.add(key)
        upd = await make_api_request('POST', '/v1/testpertrequirementcontexts/update', api_key, data={
            'appId': str(pid),
            'reportId': str(sprint_id),
            'requirementContextId': key,
            'details': resp,
            'isEdited': '1',
        })
        if isinstance(upd, dict) and upd.get('status') == 'OK':
            if resp:
                answered += 1
        else:
            failed.append({'requirement_context_id': key,
                           'error': (upd.get('message') if isinstance(upd, dict) else None) or 'update failed'})

    unmatched = sorted(k for k in lookup if k not in matched)

    logger.info(f"Saved {answered}/{total} context answers for sprint_id={sprint_id} "
                f"(matched={len(matched)}, failed={len(failed)}, advance={advance})")

    # If every requested answer failed to save, treat the whole call as failed.
    if matched and len(failed) == len(matched):
        return {
            'status': 'failed',
            'error': 'Could not save context answers',
            'error_type': 'ContextSaveError',
            'message': failed[0]['error'] if failed else 'The API rejected the context updates.',
            'failures': failed,
        }

    result = {
        'status': 'OK',
        'sprint_id': sprint_id,
        'answered': answered,
        'total_questions': total,
        'message': f"Saved your answers ({answered} of {total} answered).",
    }
    if unmatched:
        result['unmatched_requirement_context_ids'] = unmatched
    if failed:
        result['partial_failures'] = failed
        result['message'] += f" ({len(failed)} couldn't be saved.)"

    if advance:
        # Step 2 — ADVANCE via the status machine. GENERATE_MISSING_REQUIREMENTS is legal
        # from DEEPEN_REQUIREMENTS_QUESTIONS here (Testpert.php:1490-1491).
        logger.info(f"Advancing sprint_id={sprint_id} -> GENERATE_MISSING_REQUIREMENTS")
        adv = await make_api_request('POST', '/v1/testpert/sprint/updateStatus', api_key, data={
            'appId': str(pid),
            'teamId': str(tid),
            'sprintId': str(sprint_id),
            'testpertStatus': 'GENERATE_MISSING_REQUIREMENTS',
        })
        if not (isinstance(adv, dict) and adv.get('status') == 'OK'):
            result['advanced'] = False
            result['advance_error'] = (adv.get('message') if isinstance(adv, dict) else None) \
                or "The API rejected the transition to GENERATE_MISSING_REQUIREMENTS."
            result['message'] += (" Your answers were saved, but I couldn't start the next step "
                                  "(missing requirements) — the sprint may not be at the right stage.")
            result['next_step'] = ("Saved. To continue, retry "
                                   "bugasura_testpert_advance(to_status='GENERATE_MISSING_REQUIREMENTS', "
                                   "wait_for='MISSING_REQUIREMENTS').")
            return result

        poll = await _poll_sprint_until(api_key, tid, pid, sprint_id, 'MISSING_REQUIREMENTS', max(0, min(int(max_wait_seconds), _KB_POLL_MAX_BUDGET_SECONDS)))
        if poll['outcome'] == 'reached':
            result['current_status'] = 'MISSING_REQUIREMENTS'
            result['reached'] = True
            result['message'] += " I've also identified the missing requirements."
            result['next_step'] = ("Immediately show the user the missing requirements for approve/edit "
                                   "(get_requirements category='missing'). Do NOT ask first.")
        elif poll['outcome'] == 'error':
            result['status'] = 'failed'
            result['current_status'] = poll['current']
            result['error_type'] = 'TestpertEngineError'
            result['message'] += (" Your answers were saved, but something went wrong preparing the missing "
                                  "requirements — the documents may not have been enough. We can try again.")
        elif poll['outcome'] == 'read_error':
            result['note'] = 'Saved, but I could not read the result just now.'
        else:  # timeout
            result['current_status'] = poll['current']
            result['in_progress'] = True
            result['message'] += " " + _working_message()
            result['next_step'] = ("Call bugasura_testpert_advance(wait_for='MISSING_REQUIREMENTS') to keep checking.")
    else:
        result['next_step'] = ("Answers saved. When ready, continue with "
                               "bugasura_testpert_advance(to_status='GENERATE_MISSING_REQUIREMENTS', "
                               "wait_for='MISSING_REQUIREMENTS').")
    return _attach_sprint_link(result, _testrun_id, sprint_id)


@mcp.tool(
    name = "bugasura_testpert_list_kb",
    description = (
        "List the documents/sources currently in a TestPert sprint's knowledge base, with the id "
        "needed to remove any of them. Use this to show what's uploaded and to let the user delete "
        "anything added by mistake (pair with bugasura_testpert_delete_kb)."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def list_testpert_kb(
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (= report_id). Required (prompts if omitted, ge=1)."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """List knowledge-base items via /v1/testpertKB/sprint/get."""
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_testpert_list_kb')
    if 'status' in context and context['status'] == 'selection_required':
        return context
    if not sprint_id:
        return _sprint_selection_required(context['team_id'], context['project_id'])

    resp = await make_api_request('GET', '/v1/testpertKB/sprint/get', api_key, params={
        'appId': context['project_id'], 'teamId': context['team_id'], 'sprintId': sprint_id,
    })
    items = _parse_kb_items(resp.get('kbDetails') if isinstance(resp, dict) else None)
    return {
        'status': 'OK',
        'sprint_id': sprint_id,
        'documents': items,
        'count': len(items),
        'message': (f"{len(items)} document(s) in the knowledge base." if items
                    else "No documents in the knowledge base yet."),
        'next_step': ("Show the user the documents (filename) and let them remove any with "
                      "bugasura_testpert_delete_kb (pass its id). Use plain language; don't show codes."),
    }


@mcp.tool(
    name = "bugasura_testpert_delete_kb",
    description = (
        "Remove a document/source from a TestPert sprint's knowledge base (e.g. one uploaded by "
        "mistake). Get the id from bugasura_testpert_list_kb. Do this before starting the analysis."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def delete_testpert_kb(
    kb_id: int = Field(description="The knowledge-base item id to remove (from bugasura_testpert_list_kb)."),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (= report_id). Required (prompts if omitted, ge=1)."),
    kb_source: Optional[str] = Field(default=None, description="Optional source of the item (e.g. FILE_UPLOAD), as listed by list_kb."),
    kb_source_type: Optional[str] = Field(default=None, description="Optional source type (e.g. REQUIREMENTS), as listed by list_kb."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """Delete a knowledge-base item via /v1/testpertKB/sprint/delete."""
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation
    context = await select_team_project_context(api_key, team_id, project_id, 'bugasura_testpert_delete_kb')
    if 'status' in context and context['status'] == 'selection_required':
        return context
    if not sprint_id:
        return _sprint_selection_required(context['team_id'], context['project_id'])

    data = {
        'appId': str(context['project_id']),
        'teamId': str(context['team_id']),
        'sprintId': str(sprint_id),
        'kbId': str(kb_id),
    }
    if kb_source:
        data['kbSource'] = kb_source
    if kb_source_type:
        data['kbSourceType'] = kb_source_type

    resp = await make_api_request('POST', '/v1/testpertKB/sprint/delete', api_key, data=data)
    if isinstance(resp, dict) and resp.get('status') == 'OK':
        resp['message'] = "Removed the document from the knowledge base."
        resp['next_step'] = "Re-list with bugasura_testpert_list_kb to confirm what remains."
    return resp


# --- Link EXISTING project requirements to a sprint (skip-enrich source) -----
@mcp.tool(
    name = "bugasura_testpert_link_requirements",
    description = (
        "Link one or more EXISTING project requirements to a sprint. In the skip-enrich flow this is "
        "how the user picks, from the project's existing requirements, the ones that drive the test "
        "plan. First list candidates with bugasura_list_requirements (omit sprint_id to see the "
        "project's requirements), then pass each item's internal `requirement_id` here — NOT the "
        "display `id`. Each is linked via /v1/requirements/sprint/link; already-linked ids are a "
        "harmless no-op. To create "
        "BRAND-NEW requirements instead, use bugasura_create_requirement with this sprint_id. After "
        "linking, continue the skip flow with bugasura_testpert_start_skip_testplan."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def link_testpert_requirements(
    requirement_ids: List[int] = Field(description="Internal requirement_id values to link (the `requirement_id` field from bugasura_list_requirements — NOT the display `id`)."),
    sprint_id: Optional[int] = Field(default=None, description="Sprint identifier (= report_id). Required (prompts if omitted, ge=1)."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Link existing project requirements to a sprint via GET /v1/requirements/sprint/link.

    Links one requirement per call (teamId, appId, reportId=sprintId, requirementId), idempotent
    (already-linked => OK). IMPORTANT: link by the internal `requirement_id` from
    bugasura_list_requirements, NOT the display `id` — the endpoint uses INSERT IGNORE with no
    existence check, so a display id silently writes a dangling row the sprint read never matches.
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id,
                                                'bugasura_testpert_link_requirements')
    if 'status' in context and context['status'] == 'selection_required':
        return context
    if not sprint_id:
        return _sprint_selection_required(context['team_id'], context['project_id'])

    tid, pid = context['team_id'], context['project_id']

    # De-dupe while preserving order; drop empties.
    ids, seen = [], set()
    for rid in (requirement_ids or []):
        key = str(rid).strip()
        if key and key not in seen:
            seen.add(key)
            ids.append(key)
    if not ids:
        return {'status': 'failed', 'error': 'No requirement_ids provided',
                'error_type': 'ValidationError',
                'message': 'Provide at least one requirement_id to link (from bugasura_list_requirements).'}

    results = []
    linked = 0
    for rid in ids:
        resp = await make_api_request('GET', '/v1/requirements/sprint/link', api_key, params={
            'teamId': tid, 'appId': pid, 'reportId': sprint_id, 'requirementId': rid,
        })
        ok = isinstance(resp, dict) and resp.get('status') == 'OK'
        if ok:
            linked += 1
        results.append({
            'requirement_id': rid,
            'status': 'OK' if ok else 'failed',
            'message': (resp.get('message') if isinstance(resp, dict) else None) or '',
        })

    overall_ok = linked == len(results) and linked > 0
    return {
        'status': 'OK' if overall_ok else 'failed',
        'sprint_id': sprint_id,
        'linked': linked,
        'total': len(results),
        'results': results,
        'message': (f"Linked {linked} of {len(results)} requirement(s) to the sprint."
                    + ("" if overall_ok else " Some couldn't be linked — see results.")),
        'next_step': ("When the requirements are set, build the test plan with "
                      "bugasura_testpert_start_skip_testplan(sprint_id, testrun_id)."),
    }


def _sprint_url(testrun_id: Any, report_id: Any, tab: Optional[str] = None) -> Optional[str]:
    """
    Build a user-facing TestPert sprint link:
    {web}testpert/sprintDetails/{testrun_id}/App/{report_id}[?tabName=<tab>]
    (segment 'App' matches the web routes). `tab='testcase'` deep-links the Test Cases tab;
    `tab='testcoverage'` deep-links the Coverage tab; omit `tab` for the sprint overview.
    Returns None if the web base or testrun_id is unknown.
    """
    if not WEB_BASE_URL or not testrun_id or not report_id:
        return None
    url = f"{WEB_BASE_URL}testpert/sprintDetails/{testrun_id}/App/{report_id}"
    return f"{url}?tabName={tab}" if tab else url


def _attach_sprint_link(result: dict, testrun_id: Any, report_id: Any, tab: Optional[str] = None) -> dict:
    """
    Add `sprint_url` to a successful result dict (and a friendly pointer) when the link is buildable.

    Only attaches to OK responses — error/failed dicts don't get a sprint link appended.
    """
    if not (isinstance(result, dict) and result.get('status') == 'OK'):
        return result
    url = _sprint_url(testrun_id, report_id, tab)
    if url:
        result['sprint_url'] = url
        msg = result.get('message') or ''
        result['message'] = (msg + f" You can view the sprint here: {url}").strip()
    return result


def _build_selected_kbs_skeleton() -> dict:
    """
    Minimal `selectedKBs` payload for a files-only KB upload.

    The backend dereferences several `selectedKBs` sub-keys without isset()
    guards (e.g. count($selectedKBs['pm_tools']['jira']['projectDetails']),
    $selectedKBs['design']['figma'], ['requirements']['customFiles'],
    ['context']['context']). This mirrors the web client's `selectedTestpertKBs`
    object so every dereferenced key exists and resolves to "nothing selected".
    Uploaded files travel as multipart parts, not inside this blob.
    """
    return {
        "requirements": {
            "filesUploaded": [], "apiDocs": [], "meetingNotes": [], "customFiles": [],
            "architectureImages": [], "dbschemaImages": [], "wireframeImages": [],
            "designImages": [], "flowImages": [], "userFlow": [], "testData": [],
            "googleDocs": [],
        },
        "pm_tools": {"jira": {"projectKeys": [], "projectDetails": []}},
        "design": {"figma": []},
        "requirementAnalysis": {
            "feature_details": [], "requirement_risks": [], "improvements_in_requirement": [],
        },
        "context": {"context": ""},
        "production": {"googleAnalytics": {}},
    }


def _is_testpert_enabled(app_record: Optional[dict]) -> bool:
    """True when the app row flags the project as TestPert-enabled."""
    if not app_record:
        return False
    return str(app_record.get('is_testpert_enabled') or '0') == '1'


def _normalize_testing_type(testing_type: Optional[str]) -> str:
    """
    Map a user-facing Testing Type to the backend execution mode.

    'Human'/'Agent'/'Automation' (any case) -> 'HUMAN'/'AGENT'/'AUTOMATION'.
    Defaults to 'AGENT' (the web frontend's default for a TestPert sprint).
    """
    v = (testing_type or '').strip().upper()
    if v in ('HUMAN', 'AGENT', 'AUTOMATION'):
        return v
    return 'AGENT'


def _normalize_testing_depth(testing_depth: Optional[str]) -> str:
    """
    Map a user-facing Testing Depth to the backend testpert value.

    'Quick'/'Deep' (any case) -> 'QUICK'/'DEEP'. Defaults to 'DEEP'.
    """
    v = (testing_depth or '').strip().upper()
    if v == 'QUICK':
        return 'QUICK'
    return 'DEEP'


def _validate_sprint_name(sprint_name: str) -> Optional[dict]:
    """Backend requires 5-250 chars. Returns an error dict, or None if valid."""
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
    return None


async def _create_testpert_sprint(api_key: str, team_id: int, project_id: int,
                                  app_record: dict, sprint_name: str,
                                  start_date: Optional[str], end_date: Optional[str],
                                  duration: Optional[int], sprint_status: str,
                                  feature_name: Optional[str],
                                  testing_type: str = 'AGENT',
                                  testing_depth: str = 'DEEP',
                                  skip_enrich_requirements: int = 0) -> dict:
    """
    Create a TestPert-enabled sprint via the platform's /v1/sprint/create endpoint.

    Mirrors the web frontend's createFunctionalReport payload for an existing
    project. Must POST `source=PLATFORM` — the backend zeroes the testpert flag
    for any other source.

    testing_type           -> execution mode ('HUMAN'/'AGENT'/'AUTOMATION').
    testing_depth          -> testpert value ('QUICK'/'DEEP').
    skip_enrich_requirements (0/1) -> skip the AI requirements-enrichment step.
    """
    app_name = app_record.get('project_name') or app_record.get('name') or app_record.get('app_name') or ''
    platform = app_record.get('platform') or 'Desktop'
    platform_type = app_record.get('platform_type') or 'Web'
    # A feature name is mandatory for a testpert sprint; default to the sprint name.
    report_feature_name = (feature_name or '').strip() or sprint_name
    skip_enrich_flag = 1 if skip_enrich_requirements else 0

    common = {
        "testrun": 0,
        "testrun_name": sprint_name,
        "report": 0,
        "report_name": sprint_name,
        "report_feature_name": report_feature_name,
        "startDate": start_date or "",
        "endDate": end_date or "",
        "duration": duration if duration else "",
        "sprintStatus": sprint_status,
        "testpertValue": testing_depth,
        "isTestpertEnabled": 1,
        "build": 0,
        "app_id": project_id,
        "app_name": app_name,
        "build_name": app_name,
        "testing_type": "EXPLORATORY_TESTFLOW",
        "is_platform": 1,
        "isNewApp": 0,
        "platform": platform,
        "platform_type": platform_type,
    }

    if platform_type in ('Web', 'Multiple'):
        test_details = {
            **common,
            "executionMode": testing_type,
            "is_public_project": 0,
            "is_public_issues": 0,
            "public_team_name": "",
            "public_app_name": "",
            "network": "Wifi",
            "browser_name": "Chrome",
            "browser_version": "84",
            "os_name": "Windows",
            "os_version": "10",
            "resolution": "1536 x 864",
            "perfMonUrl": "",
            "testCaseIds": "",
            "skipEnrichRequirements": skip_enrich_flag,
            "api_spec_file_path": "",
        }
    else:
        # Mobile / apps path mirrors the frontend's bugninja branch.
        build_details = {
            "appName": app_name,
            "buildName": app_name,
            "platform": platform,
            "platform_type": platform_type,
            "is_bugninja_upload": 1,
            "app_package": "",
            "isNewApp": 0,
            "is_public_project": 0,
            "is_public_issues": 0,
            "public_team_name": "",
            "public_app_name": "",
        }
        testrun_details = {
            "name": f"{app_name} Functional Testplan",
            "report_name": sprint_name,
            "report_feature_name": report_feature_name,
            "startDate": start_date or "",
            "endDate": end_date or "",
            "duration": duration if duration else "",
            "testpertValue": testing_depth,
            "sprintStatus": sprint_status,
            "execution_mode": testing_type,
            "skipEnrichRequirements": skip_enrich_flag,
            "platform": platform,
            "platform_type": platform_type,
            "status": "RECORDING",
            "build_name": app_name,
            "device_group": "CUSTOM",
            "testrun_type": "MANUAL",
            "prev_status": "PLAYBACK",
            "is_auto_push_bugs": "0",
            "testrun_status": "RECORDING",
            "api_version": "3",
            "jira_setting": "",
            "testing_type": "EXPLORATORY_TESTFLOW",
            "tc_is_auto_increment": 0,
            "tc_prefix": "",
            "tc_counter": "",
            "isTestpertEnabled": 1,
        }
        test_details = {
            **common,
            "network": "Wifi",
            "execution_mode": "",
            "build_details": json.dumps(build_details),
            "testrun_details": json.dumps(testrun_details),
            "isPublicProject": 0,
            "isPublicIssues": 0,
        }

    payload = {
        "source": "PLATFORM",          # required: testpert is zeroed for any other source
        "teamId": team_id,
        "platformType": platform_type,
        "testDetails": json.dumps(test_details),
        "isCopyTestCases": 0,
    }

    logger.info(f"Creating TestPert sprint '{sprint_name}' for project_id={project_id} "
                f"(platform_type={platform_type})")
    return await make_api_request('POST', '/v1/sprint/create', api_key, data=payload)


def testpert_options_prompt(team_id: int, project_id: int, sprint_name: str,
                            feature_name: Optional[str], project_label: Any) -> dict:
    """
    Build the interactive prompt that asks the user to confirm/choose the
    configurable options for a TestPert sprint before it is created.

    Returned when the project is TestPert-enabled and the caller has not yet set
    `confirm_options=True`. The assistant should surface these fields to the user,
    then re-call the tool with the chosen values plus `confirm_options=True`.
    """
    return {
        'status': 'selection_required',
        'selection_type': 'testpert_options',
        'message': (f"Project '{project_label}' is TestPert-enabled. "
                    f"Confirm or change these options, then create the sprint."),
        'fields': [
            {
                'name': 'sprint_name',
                'label': 'Sprint name',
                'required': True,
                'current': sprint_name,
                'help': '5-250 characters.'
            },
            {
                'name': 'feature_name',
                'label': 'Feature name',
                'required': False,
                'current': (feature_name or '').strip() or sprint_name,
                'help': 'Feature the sprint covers (defaults to the sprint name).'
            },
            {
                'name': 'testing_type',
                'label': 'Testing Type',
                'required': False,
                'default': 'Agent',
                'options': ['Human', 'Agent', 'Automation'],
                'help': 'Who runs the tests.'
            },
            {
                'name': 'testing_depth',
                'label': 'Testing Depth',
                'required': False,
                'default': 'Deep',
                'options': ['Quick', 'Deep'],
                'help': 'Quick = lighter pass; Deep = full enrichment.'
            },
            {
                'name': 'skip_enrich_requirements',
                'label': 'Skip requirements enrich check',
                'required': False,
                'default': False,
                'options': [True, False],
                'help': 'Skip the AI requirements-enrichment step.'
            },
        ],
        'next_call': (f'bugasura_create_testpert_sprint with team_id={team_id}, '
                      f'project_id={project_id}, sprint_name="...", feature_name="...", '
                      f'testing_type="Human|Agent|Automation", testing_depth="Quick|Deep", '
                      f'skip_enrich_requirements=true|false, confirm_options=true')
    }


def _sprint_selection_required(team_id: int, project_id: int) -> dict:
    """Prompt to pick a sprint when sprint_id wasn't supplied for a KB upload."""
    return {
        'status': 'selection_required',
        'selection_type': 'sprint',
        'message': ("Which sprint should the knowledge-base files be uploaded to? "
                    "List the sprints and ask the user to choose one."),
        'next_call': (f'bugasura_list_sprints with team_id={team_id}, project_id={project_id} '
                      f'to get sprint ids, then bugasura_testpert_upload_kb with the chosen sprint_id')
    }


def _status_ordinal(status: Optional[str]) -> Optional[int]:
    """
    Position of a status in the forward pipeline (_STATUS_ORDER), or None if it
    can't be placed (unknown, or a mid-generation *_IN_PROGRESS marker).

    Normalizes the variants getStatus / the GENERATE_* triggers report: a
    GENERATE_* trigger maps to the terminal stage it produces, and a trailing
    '_ERROR' is stripped to the stage it errored in.
    """
    if not status:
        return None
    s = status[:-6] if status.endswith('_ERROR') else status
    if s in _STATUS_ORDER:
        return _STATUS_ORDER[s]
    terminal = _TESTPERT_EXPECTED_TERMINAL.get(s)
    if terminal in _STATUS_ORDER:
        return _STATUS_ORDER[terminal]
    return None


def _is_backward_transition(current: Optional[str], to_status: str) -> bool:
    """
    True when moving to `to_status` would step the sprint *backward* to an earlier
    pipeline stage than `current`. Re-running the current stage is not backward.

    Fails open: returns False whenever either status can't be placed on the
    pipeline (unknown / in-progress), so we never block on an ambiguous status.
    """
    cur = _status_ordinal(current)
    tgt = _status_ordinal(to_status)
    if cur is None or tgt is None:
        return False
    return tgt < cur


def _backward_blocked_response(current: Optional[str], to_status: str) -> dict:
    """Standard refusal when a requested transition would move the sprint backward."""
    target = _TESTPERT_EXPECTED_TERMINAL.get(to_status, to_status)
    return {
        'status': 'failed',
        'error': 'Backward TestPert status transition is not allowed',
        'error_type': 'BackwardTransitionError',
        'current_status': current,
        'requested_status': to_status,
        'message': (f"This sprint is already at the {_friendly(current)} stage, which is past the "
                    f"{_friendly(target)} stage. The TestPert flow only moves forward — you can "
                    f"re-run the current stage or continue to the next one, but it can't go back."),
    }


async def _get_sprint_testpert_status_raw(api_key: str, team_id: int, project_id: int,
                                          sprint_id: int) -> dict:
    """GET the sprint's TestPert status row."""
    return await make_api_request('GET', '/v1/testpert/sprint/getStatus', api_key, params={
        'teamId': team_id,
        'appId': project_id,
        'sprintId': sprint_id,
        'maxRows': 1,
    })


def _extract_sprint_status(status_resp: Any) -> Optional[str]:
    """Pull `sprint_testpert_status` out of a getStatus response (or None)."""
    if isinstance(status_resp, dict) and status_resp.get('status') == 'OK':
        # Note the upstream key spelling: testpertStausDetails.
        details = status_resp.get('testpertStausDetails') or []
        if isinstance(details, list) and details:
            return details[0].get('sprint_testpert_status')
    return None


def _extract_skip_enrich(status_resp: Any) -> bool:
    """True if the sprint was created to skip requirements enrichment (getStatus row)."""
    if isinstance(status_resp, dict) and status_resp.get('status') == 'OK':
        details = status_resp.get('testpertStausDetails') or []
        if isinstance(details, list) and details:
            return str(details[0].get('skip_enrich_requirements') or '0') == '1'
    return False


def _extract_testrun_id(status_resp: Any) -> Optional[Any]:
    """Pull `testrun_id` from a getStatus row (or None) — used to build the sprint link."""
    if isinstance(status_resp, dict) and status_resp.get('status') == 'OK':
        details = status_resp.get('testpertStausDetails') or []
        if isinstance(details, list) and details:
            return details[0].get('testrun_id')
    return None


async def _attach_link_for_sprint(result: dict, api_key: str, team_id: int, project_id: int,
                                  sprint_id: int, tab: Optional[str] = None) -> dict:
    """
    Resolve the sprint's testrun_id (one getStatus read) and attach the user-facing link.

    Lets read tools that don't already know testrun_id still surface the sprint link after a phase,
    so every phase can show "view the sprint here". No-op if the link can't be built.
    """
    # Skip the extra getStatus when no link could be built anyway (web base not configured, or the
    # result isn't a successful one _attach_sprint_link would decorate).
    if not WEB_BASE_URL or not (isinstance(result, dict) and result.get('status') == 'OK'):
        return result
    testrun_id = _extract_testrun_id(
        await _get_sprint_testpert_status_raw(api_key, team_id, project_id, sprint_id))
    return _attach_sprint_link(result, testrun_id, sprint_id, tab)


async def _count_sprint_requirements(api_key: str, team_id: int, project_id: int,
                                     sprint_id: int) -> Optional[int]:
    """
    Best-effort count of requirements attached to a sprint (the skip-enrich source).

    Returns an int when determinable, or None when the response shape is unrecognized
    (callers should treat None as "unknown" and not block on it).
    """
    resp = await make_api_request('GET', '/v1/requirements/list', api_key, params={
        'teamId': team_id, 'appId': project_id, 'sprintId': sprint_id,
        'isFirstLoad': 1, 'max_results': 1,
    })
    if not (isinstance(resp, dict) and resp.get('status') == 'OK'):
        return None
    for key in ('totalRequirementsCount', 'requirementsCount', 'totalCount', 'total'):
        v = resp.get(key)
        if isinstance(v, int):
            return v
        if isinstance(v, str) and v.isdigit():
            return int(v)
    rl = resp.get('requirementsList')
    if isinstance(rl, list):
        return len(rl)
    reqs = resp.get('requirements')
    if isinstance(reqs, list):
        return len(reqs)
    if isinstance(reqs, dict):
        total = 0
        for k in ('parents', 'childs', 'others'):
            if isinstance(reqs.get(k), list):
                total += len(reqs[k])
        return total
    return None


# --- Requirement contexts (deepen questions / missing reqs / risks) --------
# The engine writes these rows to testpertRequirementContextsTable; the user reviews
# them (answer / approve / reject / edit) and we write the edits back, then advance.
def _group_requirement_contexts(rows: List[dict]) -> dict:
    """
    Group raw requirement-context rows by their `category` column.

    Returns {'deepen_questions': {<sub_category>: [...]}, 'missing': [...], 'risk': [...]}.
    Deepen questions are nested by sub_category (product/business/tech/test/user) and
    expose query/response so answers can be collected per question.
    """
    deepen: dict = {}
    missing: List[dict] = []
    risk: List[dict] = []
    for r in rows:
        cat = (r.get('category') or '').strip().lower()
        rcid = r.get('requirement_context_id')
        if cat == 'deepen_requirement_questions':
            sub = (r.get('sub_category') or '').strip().lower() or 'general'
            ad = r.get('additional_details')
            if isinstance(ad, str) and ad:
                try:
                    ad = json.loads(ad)
                except (ValueError, TypeError):
                    pass
            deepen.setdefault(sub, []).append({
                'requirement_context_id': rcid,
                'query': r.get('title'),
                'response': r.get('details'),
                'additionalDetails': ad,
            })
        elif cat in ('missing_requirement', 'risk_in_requirement'):
            item = {
                'requirement_context_id': rcid,
                'title': r.get('title'),
                'details': r.get('details'),
                'approved': r.get('is_approved'),
                'edited': r.get('is_edited'),
            }
            (missing if cat == 'missing_requirement' else risk).append(item)
    return {'deepen_questions': deepen, 'missing': missing, 'risk': risk}


def _deepen_questions_flat(deepen: dict) -> list:
    """
    Flatten grouped deepen questions into an ordered, numbered list for asking one at a time.
    Returns [{index, requirement_context_id, sub_category, query, current_response}].
    """
    if not isinstance(deepen, dict):
        return []
    ordered = ([s for s in _DEEPEN_SUBCAT_ORDER if s in deepen]
               + [s for s in deepen if s not in _DEEPEN_SUBCAT_ORDER])
    flat = []
    i = 0
    for sub in ordered:
        for q in deepen.get(sub, []):
            i += 1
            flat.append({
                'index': i,
                'requirement_context_id': q.get('requirement_context_id'),
                'sub_category': sub,
                'query': q.get('query'),
                'current_response': q.get('response') or '',
            })
    return flat


def _friendly(status: Optional[str]) -> str:
    """Human label for a status (never the raw code)."""
    if not status:
        return 'this step'
    return _FRIENDLY_STATUS.get(status, status.replace('_ERROR', '').replace('_', ' ').lower())


def _working_message() -> str:
    """Friendly 'still working' message (no raw status, no time numbers to obsess over)."""
    return "Still working on this — I'll keep checking and let you know the moment it's ready."


def _engine_error_response(status_value: str, retry_hint: str = "") -> dict:
    """
    Consistent response when the engine lands on an *_ERROR status: stop polling, surface the error.
    Engine phases can take time AND can fail (e.g. if the uploaded data was insufficient/unclear).
    """
    return {
        'status': 'failed',
        'current_status': status_value,
        'error': f"TestPert engine error: {status_value}",
        'error_type': 'TestpertEngineError',
        'message': (f"Something went wrong while preparing the {_friendly(status_value)} — it usually "
                    f"means the uploaded documents weren't enough or were unclear for this step. "
                    + (retry_hint or "Try adding more detail to the knowledge base and running it again.")),
    }


def _normalize_focus_areas(focus_areas: dict) -> dict:
    """
    Normalize to the frontend's {area_key: "LEVEL"} shape (string level per area).

    The web client posts test_focus_areas as {areaName: "EXHAUSTIVE"|"SUFFICIENT"|"MINIMAL"|"NONE"}.
    Area keys are preserved exactly (use the keys returned by get_testplan). The level may be
    given as a string, a 1-element list, or the rich {'focus': ...} object returned by get.
    """
    out = {}
    for area, level in (focus_areas or {}).items():
        if isinstance(level, dict):
            lvl = str(level.get('focus', '')).strip().upper()
        elif isinstance(level, (list, tuple)):
            lvl = str(level[0]).strip().upper() if level else ''
        else:
            lvl = str(level).strip().upper()
        out[str(area)] = lvl
    return out


def _focus_areas_view(test_focus_areas: Any) -> list:
    """
    Edit-ready list of focus areas: [{key, label, level, value_category}].

    `key` is the config key to send back; `label` is the human name (parent_category),
    which is what the user sees in the UI. Use either to reference an area when updating.
    """
    rows = []
    if isinstance(test_focus_areas, dict):
        for key, val in test_focus_areas.items():
            if isinstance(val, dict):
                lvl = val.get('focus')
                rows.append({
                    'key': str(key),
                    'label': val.get('parent_category') or str(key),
                    'level': str(lvl).strip().upper() if lvl not in (None, '') else None,
                    'value_category': val.get('value_category'),
                })
            else:
                lvl = val[0] if isinstance(val, (list, tuple)) and val else val
                rows.append({
                    'key': str(key),
                    'label': str(key),
                    'level': str(lvl).strip().upper() if lvl not in (None, '') else None,
                })
    return rows


def _is_default_focus_placeholder(fa: Any) -> bool:
    """True if `fa` is the generic default placeholder (real engine data has different keys
    and/or rich objects). The placeholder is exactly those 5 keys with list values."""
    if not isinstance(fa, dict) or set(fa.keys()) != _DEFAULT_FOCUS_KEYS:
        return False
    return all(isinstance(v, (list, tuple)) for v in fa.values())


async def _fetch_sprint_focus_areas(api_key: str, team_id: int, project_id: int, sprint_id: int) -> Any:
    """
    Fetch the REAL test_focus_areas (engine output), never the generic default placeholder.

    Primary source is the coverage mind map: it accepts the sprint's teamId and returns the real
    rich focus areas, unlike testplan/get which is bound to the api key's auth team (so it returns
    the default when the key's team != the sprint's team). Falls back to the KB/tab endpoint and
    then testplan/get. Returns None only if no real set is readable.
    """
    # 1. Coverage mind map — reliable, team-aware source for the real focus areas.
    cm = await make_api_request('GET', '/v1/testpert/getSprintCoverageMindMap', api_key, params={
        'appId': project_id, 'teamId': team_id, 'sprintId': sprint_id,
    })
    if isinstance(cm, dict) and cm.get('status') == 'OK':
        fa = (cm.get('sprintCoverageMindMap') or {}).get('test_focus_areas')
        if isinstance(fa, dict) and fa and not _is_default_focus_placeholder(fa):
            return fa

    # 2. KB/tab endpoint — returns the rich coverage-json focus areas during planning.
    kb = await make_api_request('GET', '/v1/testpertKB/sprint/get', api_key, params={
        'appId': project_id, 'teamId': team_id, 'sprintId': sprint_id,
    })
    if isinstance(kb, dict) and kb.get('status') == 'OK':
        fa = (kb.get('testPlanDetails') or {}).get('test_focus_areas')
        if isinstance(fa, dict) and fa and not _is_default_focus_placeholder(fa):
            return fa

    # 3. Fallback: the saved test-plan config (team-bound; may miss across teams).
    tp = await make_api_request('GET', '/v1/testpert/sprint/testplan/get', api_key, params={
        'appId': project_id, 'sprintId': sprint_id,
    })
    if isinstance(tp, dict) and tp.get('status') == 'OK':
        fa = (tp.get('testPlanDetails') or {}).get('test_focus_areas')
        if isinstance(fa, dict) and fa and not _is_default_focus_placeholder(fa):
            return fa

    return None


def _merge_focus_areas(existing: Any, changes: dict) -> dict:
    """
    Merge focus-level changes into the existing test_focus_areas, preserving every other area
    and all per-area metadata (parent_category / value_category / definition).

    `changes` is {ref: "LEVEL"} where ref matches an area by its config key OR its
    parent_category (case-insensitive) — so both 'authentication' and 'Security' hit the same
    area. Only the matched area's `focus` is updated; unmatched refs are added as new flat areas.
    """
    merged = {}
    if isinstance(existing, dict):
        for k, v in existing.items():
            merged[k] = dict(v) if isinstance(v, dict) else v

    # Build ref -> actual-key lookup from config keys and (unique) parent_category labels.
    lookup = {}
    for key, val in merged.items():
        lookup.setdefault(str(key).strip().lower(), key)
        if isinstance(val, dict) and val.get('parent_category'):
            lookup.setdefault(str(val['parent_category']).strip().lower(), key)

    for ref, level in (changes or {}).items():
        actual = lookup.get(str(ref).strip().lower())
        if actual is None:
            merged[str(ref)] = level            # new area not in the plan — add flat
        elif isinstance(merged[actual], dict):
            merged[actual]['focus'] = level      # update level, keep metadata
        else:
            merged[actual] = level
    return merged


def _flatten_features(features: Any) -> list:
    """
    Flatten the plan's features into a readable tree: a list of
    {feature_id, name, focus, is_api_endpoint, is_default, sub_features:[{feature_id, name, requirement_id, is_default}]}.

    Mirrors what the web Features tab renders. Handles both a dict keyed by feature name
    (parent name = the key, '_' -> ' ') and a plain list.
    """
    out = []
    if isinstance(features, dict):
        items = features.items()
    elif isinstance(features, list):
        items = enumerate(features)
    else:
        return out
    for key, f in items:
        if not isinstance(f, dict):
            continue
        name = f.get('name') or (str(key).replace('_', ' ') if isinstance(key, str) else str(key))
        sub_raw = f.get('sub_features')
        sub_iter = sub_raw.values() if isinstance(sub_raw, dict) else (sub_raw if isinstance(sub_raw, list) else [])
        subs = [{
            'feature_id': sf.get('feature_id'),
            'name': sf.get('name'),
            'requirement_id': sf.get('requirement_id'),
            'is_default': sf.get('is_default_feature'),
        } for sf in sub_iter if isinstance(sf, dict)]
        out.append({
            'feature_id': f.get('feature_id'),
            'name': name,
            'focus': f.get('focus'),
            'is_api_endpoint': f.get('is_api_endpoint'),
            'is_default': f.get('is_default_feature'),
            'sub_features': subs,
            'sub_feature_count': len(subs),
        })
    return out


def _build_testplan_edit_view(plan: dict) -> dict:
    """Compact, edit-ready summary of a testPlanDetails payload for showing the user."""
    features = _flatten_features(plan.get('features'))
    view = {
        'focus_areas': _focus_areas_view(plan.get('test_focus_areas')),
        'focus_levels': list(_FOCUS_LEVELS),
        'features': features,
        'test_models': plan.get('test_models') or [],
        'counts': {
            'features': len(features),
            'sub_features': sum(f['sub_feature_count'] for f in features),
            'flows': len(plan['flows']) if isinstance(plan.get('flows'), (list, dict)) else 0,
            'scenarios': len(plan['scenarios']) if isinstance(plan.get('scenarios'), (list, dict)) else 0,
        },
        'testplan_id': plan.get('testplan_id'),
        'sprint_id': plan.get('sprint_id'),
    }
    return view


# --- Generate test cases ---------------------------------------------------
async def _poll_sprint_until(api_key: str, team_id: int, project_id: int, sprint_id: int,
                             wait_for: str, budget_seconds: int) -> dict:
    """Poll getStatus until `wait_for`, an `*_ERROR`, or the budget runs out."""
    deadline = time.monotonic() + budget_seconds
    while True:
        status_resp = await _get_sprint_testpert_status_raw(api_key, team_id, project_id, sprint_id)
        current = _extract_sprint_status(status_resp)
        if current is None:
            return {'outcome': 'read_error', 'raw': status_resp}
        if current == wait_for:
            return {'outcome': 'reached', 'current': current}
        if current.endswith('_ERROR'):
            return {'outcome': 'error', 'current': current}
        if time.monotonic() >= deadline:
            return {'outcome': 'timeout', 'current': current}
        await asyncio.sleep(_KB_POLL_INTERVAL_SECONDS)


# --- Features / sub-features (add & delete, like the web Features tab) ------
def _group_testpert_features(rows: Any) -> tuple:
    """
    Group the flat testpertFeatures rows into a parent -> sub-features tree.

    Returns (features, orphan_sub_features). Parents have is_parent_feature_id == 1;
    sub-features are attached to their parent via parent_feature_id.
    """
    parents = {}
    order = []
    subs = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        if str(r.get('is_parent_feature_id')) == '1':
            fid = r.get('feature_id')
            parents[fid] = {
                'feature_id': fid,
                'name': r.get('feature_name'),
                'is_api_endpoint': r.get('is_api_endpoint'),
                'is_default': r.get('is_default_feature'),
                'status': r.get('status'),
                'sub_features': [],
            }
            order.append(fid)
        else:
            subs.append(r)
    orphans = []
    for s in subs:
        item = {
            'feature_id': s.get('feature_id'),
            'name': s.get('feature_name'),
            'requirement_id': s.get('requirement_id'),
            'status': s.get('status'),
            'is_default': s.get('is_default_feature'),
            'no_of_attempts': int(s.get('no_of_attempts') or 0),
            'is_rerun': str(s.get('is_re_run') or s.get('is_rerun') or '0') == '1',
        }
        pid = s.get('parent_feature_id')
        if pid in parents:
            parents[pid]['sub_features'].append(item)
        else:
            orphans.append({**item, 'parent_feature_id': pid})
    return [parents[fid] for fid in order], orphans


# --- Knowledge base: list & delete uploaded documents ----------------------
def _parse_kb_items(kb_details: Any) -> list:
    """Flatten the testpertKB rows into a friendly list for display/deletion."""
    out = []
    for r in kb_details or []:
        if not isinstance(r, dict):
            continue
        filename = None
        conn = r.get('connection_details')
        if isinstance(conn, str) and conn:
            try:
                filename = (json.loads(conn).get('file_details') or {}).get('original_filename')
            except (ValueError, TypeError):
                pass
        out.append({
            'kb_id': r.get('kb_id'),
            'filename': filename,
            'source': r.get('source'),
            'source_type': r.get('source_type'),
            'stage': r.get('stage'),
        })
    return out


# --- KB upload helpers -------------------------------------------------------

def _write_b64_tmp(b64_data: str, suffix: str) -> str:
    """Decode base64 (strict) and write to a delete=False temp file; return path.

    Uses validate=True so MIME-folded or corrupt base64 raises binascii.Error
    instead of silently producing wrong bytes. Cleans up the temp file if the
    write fails before the path is returned, so the caller never leaks a file.
    Raises: binascii.Error on bad base64, OSError on write failure.
    """
    data = base64.b64decode(b64_data, validate=True)
    tmp = tempfile.NamedTemporaryFile(mode='wb', suffix=suffix, delete=False)
    try:
        tmp.write(data)
    except Exception:
        tmp.close()
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        raise
    tmp.close()
    return tmp.name


def _write_text_tmp(text: str, suffix: str) -> str:
    """Write plain text to a delete=False temp file; return path.

    Cleans up the temp file if the write fails before the path is returned.
    Raises: OSError on write failure.
    """
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False, encoding='utf-8')
    try:
        tmp.write(text)
    except Exception:
        tmp.close()
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        raise
    tmp.close()
    return tmp.name


def _normalise_share_url(url: str) -> str:
    """Convert well-known sharing URLs to direct download URLs.

    Handles Google Drive share links and Dropbox share links.
    All other URLs are returned unchanged.
    """
    # Google Drive: https://drive.google.com/file/d/FILE_ID/view?...
    #           or: https://drive.google.com/open?id=FILE_ID
    parsed = urllib.parse.urlparse(url)
    if 'drive.google.com' in parsed.netloc:
        # /file/d/FILE_ID/... form
        parts = parsed.path.split('/')
        try:
            file_id = parts[parts.index('d') + 1]
            return f'https://drive.google.com/uc?export=download&id={file_id}'
        except (ValueError, IndexError):
            pass
        # ?id=FILE_ID form
        qs = urllib.parse.parse_qs(parsed.query)
        if 'id' in qs:
            return f'https://drive.google.com/uc?export=download&id={qs["id"][0]}'
    # Dropbox: replace dl=0 with dl=1 (or add dl=1)
    if 'dropbox.com' in parsed.netloc:
        qs = urllib.parse.parse_qs(parsed.query)
        qs['dl'] = ['1']
        new_query = urllib.parse.urlencode({k: v[0] for k, v in qs.items()})
        return urllib.parse.urlunparse(parsed._replace(query=new_query))
    return url


def _infer_filename_from_url_path(url: str) -> Optional[str]:
    """Extract a filename from the URL path if it looks like a real file.

    Works for Dropbox-style URLs where the filename is in the path.
    Returns None for Google Drive and other URLs where there is no filename.
    """
    try:
        path = urllib.parse.urlparse(url).path.rstrip('/')
        if not path:
            return None
        basename = urllib.parse.unquote(path.split('/')[-1])
        # Only accept if it has a recognisable extension.
        if '.' in basename and not basename.startswith('.'):
            return basename
    except Exception:
        pass
    return None


def _download_url_tmp(url: str, suffix: str, timeout: int = 30) -> tuple:
    """Download a URL to a delete=False temp file; return (path, inferred_filename_or_None).

    Streams the response in 64 KB chunks to avoid loading the whole file into
    memory. Extracts the filename from the Content-Disposition response header
    when available (works for Google Drive and similar services). Cleans up the
    temp file if the download fails before the path is returned.
    Raises: urllib.error.URLError / urllib.error.HTTPError / OSError on failure.
    """
    req = urllib.request.Request(url, headers={'User-Agent': 'BugasuraMCP/1.0'})
    tmp = tempfile.NamedTemporaryFile(mode='wb', suffix=suffix, delete=False)
    inferred_name: Optional[str] = None
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            cd = resp.headers.get('Content-Disposition', '')
            if cd:
                m = re.search(r'filename[^;=\n]*=[\s"\']*([^;"\']+)[\s"\']*', cd, re.IGNORECASE)
                if m:
                    candidate = urllib.parse.unquote(m.group(1).strip('" \''))
                    if '.' in candidate:
                        inferred_name = candidate
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                tmp.write(chunk)
    except Exception:
        tmp.close()
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        raise
    tmp.close()
    return tmp.name, inferred_name


# ---------------------------------------------------------------------------
# Guidance helpers
# ---------------------------------------------------------------------------

def _test_cases_ready_next_step(sprint_id=None) -> str:
    """Build the post-generation 'what next' prompt for a specific sprint."""
    sid = sprint_id if sprint_id is not None else '...'
    return (
        "Share the sprint_url so the user can review the test cases. "
        "Then ask the user what they'd like to do next — present exactly these three options: "
        "1) Regenerate test cases for a specific sub-feature "
        "2) Assign a test case to an AI agent "
        "3) Create a test run for this sprint. "
        "Based on their choice: "
        f"(1) call bugasura_testpert_get_features(sprint_id={sid}) to list sub-features with IDs, "
        f"then bugasura_testpert_regenerate_testcases(feature_id=<id>, sprint_id={sid}) for each they want to redo; "
        f"(2) call bugasura_list_test_cases(sprint_id={sid}) to show test cases, ask which one, "
        "then bugasura_update_test_case(testcase_id=<id>, sprint_id=..., assign_to_agent=True) — "
        "functional test cases route to the Browser Agent, API test cases to the Testpert Agent automatically; "
        "(3) call bugasura_create_test_run(report=<sprint_id>) — the tool will collect all run "
        "options from the user (name, single vs scheduled, environment, etc.) before creating."
    )


