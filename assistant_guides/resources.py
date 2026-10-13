"""MCP resource registrations (bugasura://...)."""
import json

from config.config import WEB_BASE_URL
from core.app import SERVER_VERSION, mcp


@mcp.resource("bugasura://config/settings", title="Server Configuration", mime_type="application/json")
def get_server_config() -> str:
    """Server configuration"""
    return json.dumps({
        "version": SERVER_VERSION,
        "auth": "OAuth 2.0 sign-in (HTTP transport) or BUGASURA_API_KEY environment variable (STDIO)",
        "workflow": "bugasura_list_teams() → bugasura_list_projects() → work with data"
    }, indent=2)


@mcp.resource("bugasura://docs/severity-levels", title="Severity Levels", mime_type="application/json")
def get_severity_levels() -> str:
    """Severity levels reference"""
    return json.dumps({
        "levels": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "CRITICAL": "System crash, data loss, security issue",
        "HIGH": "Major functionality broken",
        "MEDIUM": "Issue with workaround",
        "LOW": "Minor/cosmetic"
    }, indent=2)


@mcp.resource("bugasura://docs/api-endpoints", title="API Endpoints", mime_type="application/json")
def get_api_endpoints() -> str:
    """API endpoints reference"""
    return json.dumps({
        "teams": [
            "GET /v1/teams/list"
        ],
        "oauth": [
            f"GET {WEB_BASE_URL}oauth/authorize",
            "POST /v1/oauth/token",
            "POST /v1/oauth/introspect",
            "POST /v1/oauth/revoke",
        ],
        "projects": [
            "GET /v1/projects/list",
            "GET /v1/projects/get"
        ],
        "issues": [
            "GET /v1/issues/list",
            "GET /v1/issues/get",
            "POST /v1/issues/add",
            "POST /v1/issues/update",
            "POST /v1/issues/delete",
        ],
        "issues_comments": [
            "GET /v1/issues/comments/list",
            "GET /v1/issues/comments/get",
            "POST /v1/issues/comments/add",
            "POST /v1/issues/comments/update",
            "POST /v1/issues/comments/delete",
        ],
        "sprints": [
            "GET /v1/sprints/list",
            "GET /v1/sprints/get",
            "POST /v1/sprints/add",
            "POST /v1/sprints/update",
            "POST /v1/sprints/delete",
        ],
        "testcases": [
            "GET /v1/testcases/list",
            "GET /v1/testcases/get",
            "POST /v1/testcases/add",
            "POST /v1/testcases/update",
            "POST /v1/testcases/delete",
        ],
        "testcases_comments": [
            "GET /v1/testcasecomments/list",
            "GET /v1/testcasecomments/get",
            "POST /v1/testcasecomments/add",
            "POST /v1/testcasecomments/update",
            "POST /v1/testcasecomments/delete",
        ],
        "requirements": [
            "GET /v1/requirements/list",
            "GET /v1/requirement/get",
            "POST /v1/requirement/add",
            "POST /v1/requirement/update",
            "POST /v1/requirement/delete",
        ],
        "knowledge_base": [
            "GET /v1/knowledgebase/getDocs",
            "GET /v1/knowledgebase/list",
            "POST /v1/knowledgebase/add",
            "POST /v1/knowledgebase/update",
            "POST /v1/knowledgebase/importDocPages",
            "POST /v1/knowledgebase/delete",
            "GET /v1/projectFolders/get?folderType=KNOWLEDGE_BASE",
            "POST /v1/projectFolders/add",
            "POST /v1/projectFolders/update",
            "POST /v1/projectFolders/delete",
        ],
        "testpert": [
            "POST /v1/sprint/create",
            "GET /v1/testpert/sprint/getStatus",
            "POST /v1/testpert/sprint/updateStatus",
            "GET /v1/testpertKB/sprint/get",
            "POST /v1/testpertKB/sprint/add",
            "POST /v1/testpertKB/sprint/delete",
            "POST /v1/testpert/updateSprintKBStatus",
            "GET /v1/testpertrequirementcontexts/get",
            "POST /v1/testpertrequirementcontexts/add",
            "POST /v1/testpertrequirementcontexts/update",
            "POST /v1/testpertrequirementcontexts/delete",
            "GET /v1/testpert/sprint/testplan/get",
            "POST /v1/testpert/sprint/testplan/update",
            "GET /v1/testpert/testpertfeatures/getTestpertFeatures",
            "POST /v1/testpert/testpertfeatures/addTestpertFeatures",
            "POST /v1/testpert/testpertfeatures/updateTestpertFeatures",
            "POST /v1/testpert/testpertfeatures/deleteTestpertFeatures",
            "GET /v1/testpert/getSprintCoverageMindMap",
            "GET /v1/requirements/sprint/link",
        ],
        "knowledge_base_connectors": [
            "POST /v1/coda/getDocs",
            "POST /v1/coda/getPages",
            "POST /v1/coda/getDocDetails",
            "POST /v1/bugTracker/getProjectList",
            "POST /v1/testpert/searchToolsProjectIssues",
            "POST /v1/confluence/getSpaceList",
            "POST /v1/confluence/getPagesBySpace",
        ],
    }, indent=2)


@mcp.resource("bugasura://docs/getting-started", title="Getting Started", mime_type="application/json")
def get_getting_started_guide() -> str:
    """Quick start guide"""
    return json.dumps({
        "1": "Connect Bugasura in your MCP client (OAuth sign-in) — or set BUGASURA_API_KEY for STDIO",
        "2": "Get team_id: bugasura_list_teams()",
        "3": "List projects: bugasura_list_projects(team_id)",
        "4": "Create/manage issues, sprints, test cases"
    }, indent=2)


@mcp.resource("bugasura://docs/error-codes", title="Error Codes", mime_type="application/json")
def get_error_codes() -> str:
    """Error codes returned by tools and the recommended agent response."""
    return json.dumps({
        "status_values": {
            "OK": "Success — payload contains the requested data.",
            "selection_required": "Tool needs additional context (team/project/sprint). Inspect the 'options' field and re-call with the chosen identifier.",
            "failed": "Operation failed. Inspect 'error' and 'error_type' for details.",
            "api_key_required": "Not signed in or the session expired. HTTP: tell the user to reconnect Bugasura in the MCP client. STDIO: set BUGASURA_API_KEY. Never ask for a key in chat."
        },
        "error_types": {
            "AuthenticationError": "401 from upstream. Session expired or revoked — the user must reconnect (HTTP) or fix BUGASURA_API_KEY (STDIO).",
            "HTTPError": "Non-2xx response. Inspect 'status_code' and 'response_body'.",
            "ConnectionError": "Could not reach the Bugasura API. Retry shortly.",
            "Timeout": "Request exceeded API timeout. Retry with backoff.",
            "RequestError": "The request to the Bugasura API failed before a response arrived. Retry with backoff.",
            "InvalidResponse": "The Bugasura API returned a response that could not be read. Retry; report if it persists.",
            "ValidationError": "Input failed validation (IDs, dates, lengths, file sources). Fix params and retry.",
            "InternalError": "Unexpected server-side error. Retry once; report if it persists."
        },
        "http_status_codes": {
            "400": "Bad request — payload shape or required fields missing.",
            "401": "Unauthorized — expired/revoked OAuth token or invalid API key.",
            "403": "Forbidden — user lacks permission on the team/project.",
            "404": "Not found — id does not exist or is not visible to this user.",
            "409": "Conflict — duplicate name or stale update.",
            "429": "Rate limited — see bugasura://docs/rate-limits.",
            "5xx": "Server error — retry with backoff."
        }
    }, indent=2)


@mcp.resource("bugasura://docs/field-reference", title="Field Reference", mime_type="application/json")
def get_field_reference() -> str:
    """Allowed values for enumerated fields used across tools."""
    return json.dumps({
        "severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "issue_status_default": ["New", "In Progress", "Resolved", "Closed", "Reopened"],
        "issue_status_note": "Status values are project-specific and follow the project's workflow. Read the project to discover its actual status set.",
        "priority": ["P0", "P1", "P2", "P3", "P4"],
        "platform": ["ALL", "Android", "iOS", "Desktop", "API", "Multiple"],
        "platform_type": ["ALL", "Apps", "Mobileweb", "Web", "API", "Multiple"],
        "project_status": ["ACTIVE", "ARCHIVE", "ALL"],
        "project_type": ["all", "contributed", "private", "public"],
        "sprint_status": ["SCHEDULED", "IN PROGRESS", "CANCELLED", "COMPLETED"],
        "source": ["PLATFORM", "EXTENSION", "API", "IMPORT"],
        "date_format": "YYYY-MM-DD",
        "id_types": {
            "team_id":    "positive integer",
            "project_id": "positive integer",
            "sprint_id":  "positive integer",
            "issue_id":   "numeric ID OR issue key (e.g. 'ISS09', 'BUG-123') OR exact summary",
            "user":       "user_id (int) OR email OR display name (case-insensitive partial match)"
        }
    }, indent=2)


@mcp.resource("bugasura://docs/pagination", title="Pagination", mime_type="application/json")
def get_pagination_docs() -> str:
    """Pagination contract for list_* tools."""
    return json.dumps({
        "request_params": {
            "start_at":    "Offset of first item to return. Default 0.",
            "max_results": "Page size. Default and max vary per tool; see each tool's max_results description."
        },
        "response_envelope_target": {
            "total":       "int — total items matching the query",
            "count":       "int — items in this response",
            "offset":      "int — echo of start_at",
            "items":       "list — page contents",
            "has_more":    "bool — true if total > offset + count",
            "next_offset": "int|null — start_at value for the next page, or null if exhausted"
        },
        "current_state": "Paginated list_* tools return this envelope. list_teams and the TestPert getters return their full result in one response.",
        "client_guidance": "Always pass start_at + max_results explicitly. Do not assume the upstream cap is your cap."
    }, indent=2)


@mcp.resource("bugasura://docs/rate-limits", title="Rate Limits", mime_type="application/json")
def get_rate_limits() -> str:
    """Documented Bugasura API rate limits and client guidance."""
    return json.dumps({
        "documented_limits": "Bugasura does not publish per-endpoint rate limits in the public API docs as of this writing.",
        "observed_behavior": {
            "429": "Returned when the per-key quota is exceeded.",
            "5xx_burst": "Bursts of write traffic occasionally yield 502/503 — treat as transient."
        },
        "client_guidance": [
            "Backoff with jitter on 429 and 5xx (suggested: 1s, 2s, 4s, 8s, give up).",
            "Avoid client-side fan-out: prefer list_* with appropriate filters over N parallel get_* calls.",
            "Reuse team_id / project_id from earlier results instead of re-resolving names on every call."
        ],
        "reference": "Confirm current limits with Bugasura support for production deployments."
    }, indent=2)
