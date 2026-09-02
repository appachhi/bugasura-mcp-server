"""MCP resource registrations (bugasura://...)."""
import json

from app import mcp
from config import API_BASE


@mcp.resource("bugasura://config/settings")
def get_server_config() -> str:
    """Server configuration"""
    return json.dumps({
        "api_base_url": API_BASE, "version": "2.0.0",
        "auth": "api_key parameter or BUGASURA_API_KEY environment variable",
        "workflow": "bugasura_list_teams() → bugasura_list_projects() → work with data"
    }, indent=2)


@mcp.resource("bugasura://docs/severity-levels")
def get_severity_levels() -> str:
    """Severity levels reference"""
    return json.dumps({
        "levels": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "CRITICAL": "System crash, data loss, security issue",
        "HIGH": "Major functionality broken",
        "MEDIUM": "Issue with workaround",
        "LOW": "Minor/cosmetic"
    }, indent=2)


@mcp.resource("bugasura://docs/api-endpoints")
def get_api_endpoints() -> str:
    """API endpoints reference"""
    return json.dumps({
        "teams": ["GET /v1/teams/list"],
        "projects": ["GET /v1/projects/list", "GET /v1/projects/get"],
        "issues": ["GET /v1/issues/list", "GET /v1/issues/get", "POST /v1/issues/add", "POST /v1/issues/update", "POST /v1/issues/delete"],
        "issues_comments": ["GET /v1/issues/comments/list", "GET /v1/issues/comments/get", "POST /v1/issues/comments/add", "POST /v1/issues/comments/update", "POST /v1/issues/comments/delete"],
        "sprints": ["GET /v1/sprints/list", "GET /v1/sprints/get", "POST /v1/sprints/add", "POST /v1/sprints/update", "POST /v1/sprints/delete"],
        "testcases": ["GET /v1/testcases/list", "GET /v1/testcases/get", "POST /v1/testcases/add", "POST /v1/testcases/update", "POST /v1/testcases/delete"],
        "testcases_comments": ["GET /v1/testcasecomments/list", "GET /v1/testcasecomments/get", "POST /v1/testcasecomments/add", "POST /v1/testcasecomments/update", "POST /v1/testcasecomments/delete"],
        "requirements": ["GET /v1/requirements/list", "GET /v1/requirement/get", "POST /v1/requirement/add", "POST /v1/requirement/update", "POST /v1/requirement/delete"],
        "knowledge_base": ["GET /v1/knowledgebase/getDocs", "GET /v1/knowledgebase/list", "POST /v1/knowledgebase/add",
                           "POST /v1/knowledgebase/update", "POST /v1/knowledgebase/importDocPages", "POST /v1/knowledgebase/delete",
                           "GET /v1/projectFolders/get?folderType=KNOWLEDGE_BASE", "POST /v1/projectFolders/add",
                           "POST /v1/projectFolders/update", "POST /v1/projectFolders/delete"],
        "testpert": ["POST /v1/sprint/create", "GET /v1/testpert/sprint/getStatus", "POST /v1/testpert/sprint/updateStatus",
                     "GET /v1/testpertKB/sprint/get", "POST /v1/testpertKB/sprint/add", "POST /v1/testpertKB/sprint/delete",
                     "POST /v1/testpert/updateSprintKBStatus",
                     "GET /v1/testpertrequirementcontexts/get", "POST /v1/testpertrequirementcontexts/add",
                     "POST /v1/testpertrequirementcontexts/update", "POST /v1/testpertrequirementcontexts/delete",
                     "GET /v1/testpert/sprint/testplan/get", "POST /v1/testpert/sprint/testplan/update",
                     "GET /v1/testpert/testpertfeatures/getTestpertFeatures", "POST /v1/testpert/testpertfeatures/addTestpertFeatures",
                     "POST /v1/testpert/testpertfeatures/updateTestpertFeatures", "POST /v1/testpert/testpertfeatures/deleteTestpertFeatures",
                     "GET /v1/testpert/getSprintCoverageMindMap", "GET /v1/requirements/sprint/link"],
        "knowledge_base_connectors": ["POST /v1/coda/getDocs", "POST /v1/coda/getPages", "POST /v1/coda/getDocDetails",
                                      "POST /v1/bugTracker/getProjectList", "POST /v1/testpert/searchToolsProjectIssues",
                                      "POST /v1/confluence/getSpaceList", "POST /v1/confluence/getPagesBySpace"]
    }, indent=2)


@mcp.resource("bugasura://docs/getting-started")
def get_getting_started_guide() -> str:
    """Quick start guide"""
    return json.dumps({
        "1": "Get API key: Bugasura → User Settings → API Key",
        "2": "Get team_id: list_teams(api_key)",
        "3": "List projects: list_projects(api_key, team_id)",
        "4": "Create/manage issues, sprints, test cases"
    }, indent=2)


@mcp.resource("bugasura://docs/error-codes")
def get_error_codes() -> str:
    """Error codes returned by tools and the recommended agent response."""
    return json.dumps({
        "status_values": {
            "OK": "Success — payload contains the requested data.",
            "selection_required": "Tool needs additional context (team/project/sprint). Inspect the 'options' field and re-call with the chosen identifier.",
            "failed": "Operation failed. Inspect 'error' and 'error_type' for details.",
            "api_key_required": "API key missing or invalid. Prompt the user to provide one and retry."
        },
        "error_types": {
            "AuthenticationError": "401 from upstream. Re-prompt for API key.",
            "HTTPError": "Non-2xx response. Inspect 'status_code' and 'response_body'.",
            "ConnectionError": "Could not reach API_BASE_URL. Check network/config.",
            "Timeout": "Request exceeded API timeout. Retry with backoff.",
            "ValueError": "Input failed validation (IDs, dates, lengths). Fix params and retry.",
            "KeyError": "Resolver could not find a referenced entity (team/project/user). Use list_/find_ tools first."
        },
        "http_status_codes": {
            "400": "Bad request — payload shape or required fields missing.",
            "401": "Unauthorized — invalid/expired API key.",
            "403": "Forbidden — user lacks permission on the team/project.",
            "404": "Not found — id does not exist or is not visible to this user.",
            "409": "Conflict — duplicate name or stale update.",
            "429": "Rate limited — see bugasura://docs/rate-limits.",
            "5xx": "Server error — retry with backoff."
        }
    }, indent=2)


@mcp.resource("bugasura://docs/field-reference")
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


@mcp.resource("bugasura://docs/pagination")
def get_pagination_docs() -> str:
    """Pagination contract for list_* tools."""
    return json.dumps({
        "request_params": {
            "start_at":    "Offset of first item to return. Default 0.",
            "max_results": "Page size. Default 10. Max 100."
        },
        "response_envelope_target": {
            "total":       "int — total items matching the query",
            "count":       "int — items in this response",
            "offset":      "int — echo of start_at",
            "items":       "list — page contents",
            "has_more":    "bool — true if total > offset + count",
            "next_offset": "int|null — start_at value for the next page, or null if exhausted"
        },
        "current_state": "Some list_* tools return upstream payload as-is rather than this envelope. See MCP_BUILDER_NOTES.md #9.",
        "client_guidance": "Always pass start_at + max_results explicitly. Do not assume the upstream cap is your cap."
    }, indent=2)


@mcp.resource("bugasura://docs/rate-limits")
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
            "Cache user/team context within a session — see _fetch_user_context (15+ callers, see DEV_NOTES if present)."
        ],
        "reference": "Confirm current limits with Bugasura support for production deployments."
    }, indent=2)
