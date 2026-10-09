"""Internal resolvers, file-upload utilities, and context helpers used by tools."""
import ipaddress
import json
import mimetypes
import os
import re
import shutil
import socket
import tempfile
import urllib.parse
import urllib.request
from typing import Optional


from auth import fetch_user_context
from client import UPLOAD_TIMEOUT, in_http_request, logger, make_api_request


# WEB_BASE_URL / CDN_BASE_URL now live in config.py; re-exported here because
# tools import them from helpers.
from config import CDN_BASE_URL, SECRET_RESPONSE_KEYS, WEB_BASE_URL  # noqa: F401,E402
from config import ATTACHMENT_MAX_FILE_SIZE_MB  # noqa: E402
from auth import current_user_id  # noqa: E402
from uploads import claim, discard, release, staged_paths  # noqa: E402

# Shared Field descriptions for the attachment parameters of the issue/comment/requirement tools
ATTACH_UPLOAD_ID_DESCRIPTION = (
    "upload_id from bugasura_create_upload_link(purpose='attachment'), once the user has uploaded the "
    "file(s) to its link — the way to attach a file from the user's own computer on the hosted server. "
    "Never read or encode the file yourself.")
ATTACH_FILE_PATHS_DESCRIPTION = (
    "Absolute paths of files to attach on the machine running this server (local STDIO servers only; "
    "rejected on the hosted server). Ask the user for the exact path — never guess it.")


def filter_large_fields(data: dict) -> dict:
    """
    Remove large unnecessary fields from API responses to reduce payload size.

    Fields removed:
    - tools_integration_settings: Large JSON containing integration configs
      (can be 100KB+, not needed by MCP clients)
    - tools_mapped_fields: Integration field mappings (also large)

    This function recursively processes nested structures (lists and dicts).
    """
    if not isinstance(data, dict):
        return data

    # Fields to remove from responses
    fields_to_remove = ['tools_integration_settings', 'tools_mapped_fields']

    # Create a new dict without the large fields
    filtered = {}
    for key, value in data.items():
        if key in fields_to_remove:
            logger.debug(f"Filtered out large field: {key}")
            continue

        # Recursively filter nested dicts
        if isinstance(value, dict):
            filtered[key] = filter_large_fields(value)
        # Recursively filter lists of dicts
        elif isinstance(value, list):
            filtered[key] = [filter_large_fields(item) if isinstance(item, dict) else item for item in value]
        else:
            filtered[key] = value

    return filtered


def redact_secrets(data):
    """Return a copy of data with every credential-named key masked, at any depth (JSON-object strings included)."""
    if isinstance(data, str) and data.lstrip().startswith('{'):
        try:
            return json.dumps(redact_secrets(json.loads(data)))
        except ValueError:
            return data
    if isinstance(data, dict):
        return {k: ('[REDACTED]' if str(k).lower() in SECRET_RESPONSE_KEYS and v not in (None, '')
                    else redact_secrets(v))
                for k, v in data.items()}
    if isinstance(data, list):
        return [redact_secrets(item) for item in data]
    return data


async def select_team_project_context(api_key: str, team_id: Optional[int], project_id: Optional[int], operation_name: str, operation_params: str = "") -> dict:
    """
    Helper function to handle interactive team and project selection.

    Returns either:
    1. A selection_required response if team_id or project_id is missing
    2. A dict with 'team_id' and 'project_id' keys if both are provided

    Args:
        api_key: User's Bugasura API key
        team_id: Team identifier (optional)
        project_id: Project identifier (optional)
        operation_name: Name of the operation (for display in prompts)
        operation_params: Additional parameters to include in instruction examples

    Returns:
        dict: Either selection prompt or validated context with team_id and project_id
    """
    # Step 1: If team_id not provided, fetch and return team options
    if team_id is None:
        context = await fetch_user_context(api_key)

        # Handle unexpected list response
        if isinstance(context, list):
            return {
                'status': 'failed',
                'error': 'Unexpected API response format in team selection',
                'error_type': 'ResponseFormatError',
                'details': 'Expected dict, got list'
            }

        if context.get('status') != 'OK':
            return context

        teams = context.get('teams', [])
        if not teams:
            return {
                'status': 'failed',
                'error': 'No teams found. Please create a team first.'
            }

        return {
            'status': 'selection_required',
            'step': 'team_selection',
            'message': f'Please select a team for {operation_name}:',
            'options': [{
                'team_id': team['team_id'],
                'team_name': team['team_name'],
                'role': team['role'],
                'is_expired': team.get('is_expired')
            } for team in teams],
            'instruction': f'Please call {operation_name} again with team_id parameter. Example: {operation_name}(team_id=<selected_team_id>{operation_params})'
        }

    # Step 2: If project_id not provided, fetch and return project options
    if project_id is None:
        context = await fetch_user_context(api_key)

        # Handle unexpected list response
        if isinstance(context, list):
            return {
                'status': 'failed',
                'error': 'Unexpected API response format in project selection',
                'error_type': 'ResponseFormatError',
                'details': 'Expected dict, got list'
            }

        if context.get('status') != 'OK':
            return context

        # Find the selected team
        selected_team = None
        for team in context.get('teams', []):
            if team['team_id'] == team_id:
                selected_team = team
                break

        if not selected_team:
            return {
                'status': 'failed',
                'error': f'Team with ID {team_id} not found or you do not have access to it.'
            }

        projects = selected_team.get('projects', [])
        if not projects:
            return {
                'status': 'failed',
                'error': f'No projects found in team "{selected_team.get("team_name", "Unknown Team")}". Please create a project first.'
            }

        return {
            'status': 'selection_required',
            'step': 'project_selection',
            'message': f'Please select a project in team "{selected_team.get("team_name", "Unknown Team")}" for {operation_name}:',
            'options': [{
                'project_id': proj['project_id'],
                'project_name': proj['project_name'],
                'platform': proj.get('platform', ''),
                'platform_type': proj.get('platform_type', '')
            } for proj in projects],
            'instruction': f'Please call {operation_name} again with project_id parameter. Example: {operation_name}(team_id={team_id}, project_id=<selected_project_id>{operation_params})'
        }

    # Both team_id and project_id provided - return validated context
    return {
        'team_id': team_id,
        'project_id': project_id
    }


async def search_team_by_name(api_key: str, team_name: str) -> dict:
    """Search the user's teams by name without depending on an MCP tool."""
    context = await fetch_user_context(api_key)
    if not isinstance(context, dict):
        return {
            'status': 'failed',
            'message': 'Unexpected API response format while searching for teams'
        }
    if context.get('status') != 'OK':
        return context

    search_name = team_name.strip().lower()
    matches = [
        team for team in context.get('teams', [])
        if search_name in str(team.get('team_name', '')).lower()
    ]
    return {
        'status': 'OK',
        'matches': matches,
        'count': len(matches)
    }


async def search_projects_by_name(api_key: str, project_name: str) -> dict:
    """Search projects by name (case-insensitive, partial) across all the user's teams."""
    context = await fetch_user_context(api_key)
    if context.get('status') != 'OK':
        return context

    search_term = project_name.strip().lower()
    matches = [{
        'team_id': team.get('team_id'),
        'team_name': team.get('team_name'),
        'project_id': project.get('project_id'),
        'project_name': project.get('project_name'),
        'platform': project.get('platform', ''),
        'platform_type': project.get('platform_type', '')
    } for team in context.get('teams', []) for project in team.get('projects', [])
        if search_term in str(project.get('project_name', '')).lower()]
    return {'status': 'OK', 'matches': matches, 'count': len(matches)}


async def resolve_team_identifier(api_key: str, team_id: Optional[int], team_name: Optional[str]) -> dict:
    """
    Internal helper to resolve team_id from either team_id or team_name.
    This is NOT an MCP tool - it's a helper function that can be called from Python code.

    Args:
        api_key: User's Bugasura API key
        team_id: Team identifier (optional if team_name is provided)
        team_name: Team name to resolve (optional if team_id is provided)

    Returns:
        dict: {
            'status': 'OK',
            'team_id': int,
            'team_name': str
        }
        OR error dict: {
            'status': 'failed',
            'error': str,
            'error_type': str,
            'message': str
        }
    """
    # Both provided - use team_id
    if team_id is not None and team_name is not None:
        logger.info(f"resolve_team_identifier: Both team_id={team_id} and team_name='{team_name}' provided, using team_id")
        return {
            'status': 'OK',
            'team_id': team_id,
            'team_name': team_name  # Pass through, will be validated by API
        }

    # team_id provided - use it directly
    if team_id is not None:
        logger.info(f"resolve_team_identifier: Using provided team_id={team_id}")
        return {
            'status': 'OK',
            'team_id': team_id,
            'team_name': None
        }

    # team_name provided - resolve to team_id
    if team_name is not None and team_name.strip():
        logger.info(f"resolve_team_identifier: Resolving team_name='{team_name}' to team_id")

        # Use search_team_by_name to search
        search_result = await search_team_by_name(api_key=api_key, team_name=team_name)

        if search_result.get('status') != 'OK':
            logger.error(f"resolve_team_identifier: Failed to search for team: {search_result.get('message')}")
            return {
                'status': 'failed',
                'error': 'Team search failed',
                'error_type': 'TeamSearchError',
                'message': f"Could not search for team '{team_name}': {search_result.get('message', 'Unknown error')}"
            }

        matches = search_result.get('matches', [])
        match_count = search_result.get('count', 0)

        if match_count == 0:
            logger.error(f"resolve_team_identifier: No teams found matching '{team_name}'")
            return {
                'status': 'failed',
                'error': 'Team not found',
                'error_type': 'TeamNotFound',
                'message': f"No teams found matching '{team_name}'. Check the team name and try again."
            }

        if match_count > 1:
            logger.warning(f"resolve_team_identifier: Multiple teams ({match_count}) found matching '{team_name}'")
            team_list = [f"{m['team_name']} (ID: {m['team_id']})" for m in matches]
            return {
                'status': 'failed',
                'error': 'Multiple teams found',
                'error_type': 'AmbiguousTeamError',
                'message': f"Multiple teams match '{team_name}'. Please be more specific or use team_id.",
                'matches': matches,
                'suggestion': f"Found: {', '.join(team_list)}"
            }

        # Exactly one match - use it
        resolved_team = matches[0]
        resolved_team_id = resolved_team['team_id']
        resolved_team_name = resolved_team['team_name']
        logger.info(f"resolve_team_identifier: Resolved '{team_name}' to team_id={resolved_team_id} ('{resolved_team_name}')")

        return {
            'status': 'OK',
            'team_id': resolved_team_id,
            'team_name': resolved_team_name
        }

    # Neither provided
    logger.error("resolve_team_identifier: Neither team_id nor team_name provided")
    return {
        'status': 'failed',
        'error': 'Missing team identifier',
        'error_type': 'ValidationError',
        'message': 'Please provide either team_id or team_name'
    }


async def fetch_team_members(api_key: str, team_id: int) -> dict:
    """
    Internal helper to fetch team members.
    This is NOT an MCP tool - it's a helper function that can be called from Python code.

    Args:
        api_key: User's Bugasura API key
        team_id: Team identifier

    Returns:
        dict: API response with team members
    """
    logger.info(f"fetch_team_members: Fetching members for team_id={team_id}")

    # Call API to get team members directly (no validation to avoid recursive calls)
    logger.info(f"fetch_team_members: Calling /v1/teamUsers/get for team_id={team_id}")
    response = await make_api_request('GET', '/v1/teamUsers/get', api_key, params={
        'team_id': str(team_id)
    })

    if isinstance(response, dict) and response.get('status') == 'OK':
        member_count = len(response.get('team_users_details', []))
        logger.info(f"fetch_team_members: Successfully fetched {member_count} team members")
    else:
        logger.error(f"fetch_team_members: Failed to fetch team members. Response: {response}")

    return response


async def find_user_ids_by_names_or_emails(api_key: str, team_id: int, identifiers: str) -> dict:
    """
    Internal helper to convert user names/emails to user IDs.

    Args:
        api_key: API key
        team_id: Team ID
        identifiers: Comma-separated names, emails, or user IDs

    Returns:
        dict with 'status' and either 'user_ids' (comma-separated) or 'error'
    """
    # Get team members using internal helper (not the MCP tool)
    logger.info(f"_find_user_ids: Getting team members for team_id={team_id}")
    members_response = await fetch_team_members(api_key, team_id)

    if isinstance(members_response, list):
        logger.error(f"_find_user_ids: list_team_members returned a list instead of dict")
        return {'status': 'failed', 'error': 'Could not fetch team members - unexpected response format', 'details': str(members_response)}

    if members_response.get('status') != 'OK':
        logger.error(f"_find_user_ids: list_team_members failed. Response: {members_response}")
        return {'status': 'failed', 'error': 'Could not fetch team members', 'details': members_response}

    team_members = members_response.get('team_users_details', [])
    logger.info(f"_find_user_ids: Got {len(team_members)} team members")

    if not team_members:
        logger.error(f"_find_user_ids: No team members found for team_id={team_id}")
        return {'status': 'failed', 'error': f'No team members found for team_id={team_id}'}

    # Parse the identifiers (can be names, emails, or IDs)
    # Filter out empty strings that may result from extra commas or spaces
    identifier_list = [i.strip() for i in identifiers.split(',') if i.strip()]

    if not identifier_list:
        return {'status': 'failed', 'error': 'No valid identifiers provided'}

    # Build O(n) lookup indices once. Previously this function was O(n_identifiers ×
    # n_members), which blew up on large teams (500 members × 100 assignees = 50K
    # comparisons). The name index stores a list of (lowercased_name, member) pairs
    # for substring matching — still linear per identifier in the worst case but
    # with much smaller constants and no repeated .lower() on members.
    id_index = {m['user_id']: m for m in team_members if m.get('user_id') is not None}
    email_index = {}
    name_index = []  # list of (lower_name, member) — preserves first-occurrence order
    for m in team_members:
        email = m.get('email_id')
        if email:
            email_index[email.lower()] = m
        name = m.get('name')
        if name:
            name_index.append((name.lower(), m))

    resolved_ids = []
    not_found = []

    logger.info(f"_find_user_ids: Searching for identifiers: {identifier_list}")

    for identifier in identifier_list:
        logger.debug(f"_find_user_ids: Processing identifier '{identifier}'")
        match = None

        # Try to match as user ID first (if it's numeric)
        if identifier.isdigit():
            match = id_index.get(int(identifier))
            if match:
                logger.info(f"_find_user_ids: Matched '{identifier}' as user ID")

        # Try to match by email (exact match)
        if match is None:
            match = email_index.get(identifier.lower())
            if match:
                logger.info(f"_find_user_ids: Matched '{identifier}' by email to user_id={match['user_id']} ({match['name']})")

        # Try to match by name (partial match, case-insensitive)
        if match is None:
            needle = identifier.lower()
            for lower_name, member in name_index:
                if needle in lower_name:
                    match = member
                    logger.info(f"_find_user_ids: Matched '{identifier}' by name to user_id={match['user_id']} ({match['name']})")
                    break

        if match is not None:
            resolved_ids.append(str(match['user_id']))
        else:
            not_found.append(identifier)
            logger.warning(f"_find_user_ids: Could not find user matching '{identifier}'")

    if not_found:
        return {
            'status': 'failed',
            'error': f'Could not find users: {", ".join(not_found)}',
            'available_members': [{'name': m['name'], 'email': m['email_id'], 'user_id': m['user_id']} for m in team_members]
        }

    return {'status': 'OK', 'user_ids': ','.join(resolved_ids)}


async def resolve_issue_identifier_to_id(api_key: str, team_id: int, project_id: int, issue_id: str, function_name: str = "",
                                         sprint_id: Optional[int] = None) -> dict:
    """
    Internal helper to resolve issue identifier (key or summary) to numeric issue ID.

    Supports:
    - Numeric IDs (returns as-is)
    - Issue keys (e.g., 'NEW3', 'BUG-123') - case-insensitive exact match
    - Issue summaries - exact or partial match

    Args:
        api_key: API key
        team_id: Team ID
        project_id: Project ID
        issue_id: Issue numeric ID or identifier
        function_name: Name of calling function (for logging)
        sprint_id: Only search issues in this sprint (optional)

    Returns:
        dict with 'status' and either 'issue_id' (int) or 'error'
    """
    log_prefix = f"{function_name}: " if function_name else ""

    # If already numeric, return as-is
    if str(issue_id).isdigit():
        return {'status': 'OK', 'issue_id': int(issue_id)}

    issue_identifier = str(issue_id)
    logger.info(f"{log_prefix}Resolving issue identifier '{issue_identifier}'")

    # Fetch issues in pages. Previously this fetched a single 1000-issue page; we
    # now paginate so projects with >1000 issues are searchable, and we short-circuit
    # as soon as we find an exact key match (the common case — users typically
    # reference 'ISS09'-style keys). Cap total scan at PAGE_SIZE * MAX_PAGES
    # (50 × 100 = 5000) to bound latency; projects larger than that need a
    # server-side search endpoint.
    PAGE_SIZE = 100
    MAX_PAGES = 50

    def _issue_key_of(issue: dict) -> str:
        return (issue.get('issue_id') or issue.get('issue_key')
                or issue.get('bug_id') or issue.get('testresults_key') or '')

    identifier_upper = issue_identifier.upper()
    identifier_lower = issue_identifier.lower()
    collected: list = []  # retained for summary fallback below

    for page in range(MAX_PAGES):
        offset = page * PAGE_SIZE
        params = {
            'team_id': str(team_id),
            'project_id': str(project_id),
            'start_at': offset,
            'max_results': PAGE_SIZE,
        }
        if sprint_id:
            params['sprint_id'] = str(sprint_id)
        issues_response = await make_api_request('GET', '/v1/issues/list', api_key, params=params)

        if issues_response.get('status') != 'OK':
            logger.error(f"{log_prefix}Failed to fetch issues: {issues_response.get('message')}")
            return {
                'status': 'failed',
                'error': 'Failed to fetch issues',
                'message': issues_response.get('message', 'Could not retrieve issues list')
            }

        page_issues = issues_response.get('issues', issues_response.get('issue_list', []))
        if not page_issues:
            break

        # Fast path: exact issue key match — early-exit.
        for issue in page_issues:
            if _issue_key_of(issue).upper() == identifier_upper:
                resolved = issue.get('testresults_id') or issue.get('issue_key')
                logger.info(f"{log_prefix}Found issue '{issue_identifier}' with ID {resolved} on page {page}")
                return {'status': 'OK', 'issue_id': resolved}

        collected.extend(page_issues)
        if len(page_issues) < PAGE_SIZE:
            break

    if not collected:
        logger.warning(f"{log_prefix}No issues found in project {project_id}")
        return {
            'status': 'failed',
            'error': 'No issues found',
            'message': f"No issues found in project {project_id}"
        }

    logger.info(f"{log_prefix}Exhausted key lookup across {len(collected)} issues; falling back to summary match")
    issues = collected

    # Try exact match by summary/reason
    matching_issues = [i for i in issues
                      if (i.get('reason', '') or i.get('summary', '')).lower() == identifier_lower]

    if not matching_issues:
        # Try partial match by summary
        matching_issues = [i for i in issues
                          if identifier_lower in (i.get('reason', '') or i.get('summary', '')).lower()]

    if not matching_issues:
        logger.warning(f"{log_prefix}No match found for '{issue_identifier}'")
        # Log available issue keys for debugging
        available_keys = []
        for issue in issues[:5]:  # Show first 5
            key = (issue.get('issue_id') or issue.get('issue_key') or
                   issue.get('bug_id') or issue.get('testresults_key') or 'NO_KEY')
            available_keys.append(f"{key} (ID: {issue.get('testresults_id')})")

        logger.info(f"{log_prefix}Available issue keys (first 5): {', '.join(available_keys)}")

        return {
            'status': 'failed',
            'error': 'Issue not found',
            'message': f"No issue found with key or summary '{issue_identifier}' in project {project_id}",
            'hint': f"Try one of: {', '.join(available_keys[:3])}" if available_keys else "No issues available"
        }

    if len(matching_issues) > 1:
        issue_list = '\n'.join([
            f"  - ID: {i.get('testresults_id')}, Key: {i.get('issue_id', 'N/A')}, Summary: {i.get('reason', i.get('summary', 'N/A'))}"
            for i in matching_issues[:10]
        ])
        return {
            'status': 'failed',
            'error': 'Multiple issues found',
            'message': f"Multiple issues match '{issue_identifier}'. Please use the numeric ID or unique issue key instead:\n{issue_list}"
        }

    issue_id = matching_issues[0].get('testresults_id') or matching_issues[0].get('issue_key')
    logger.info(f"{log_prefix}Found issue '{issue_identifier}' with ID {issue_id}")
    return {'status': 'OK', 'issue_id': issue_id}


# Schemes the file-fetch helpers below may open. urllib's default opener also handles
# file://, ftp:// and data:, so an unguarded urlopen() would turn a caller-supplied
# `source_url` into an arbitrary local-file read — the bytes are uploaded to Bugasura,
# and the extension check upstream only ever sees the *display* filename, not the URL.
_FETCHABLE_URL_SCHEMES = ('http', 'https')


def _require_fetchable_url(url: str) -> None:
    """Raise ValueError unless `url` is an http(s) URL with a host.

    Every helper that opens a caller-supplied URL calls this first. Callers already
    wrap these helpers in `except Exception` and surface the message, so a ValueError
    here reaches the user as a normal actionable failure.
    """
    try:
        parsed = urllib.parse.urlparse(url or '')
    except Exception:
        raise ValueError(f"'{url}' is not a valid URL.")
    scheme = (parsed.scheme or '').lower()
    if scheme not in _FETCHABLE_URL_SCHEMES:
        raise ValueError(
            f"Only http:// and https:// links can be fetched, but this one uses "
            f"'{scheme or 'no'}' scheme. Ask the user for a shareable https link "
            f"(Google Drive, Dropbox, or any public download URL). Local paths belong "
            f"in file_paths, not source_url."
        )
    if not parsed.netloc or not parsed.hostname:
        raise ValueError(f"'{url}' has no host — it is not a fetchable link.")
    # Over HTTP the server sits inside our network; never let a caller reach it (SSRF).
    if in_http_request():
        _reject_internal_host(parsed.hostname, parsed.port or (443 if scheme == 'https' else 80))


def _reject_internal_host(host: str, port: int) -> None:
    """Raise ValueError when `host` resolves to a loopback, private, link-local or reserved address."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError(f"Could not resolve the host '{host}'. Check the link and try again.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split('%', 1)[0])
        if getattr(ip, 'ipv4_mapped', None):
            ip = ip.ipv4_mapped
        if not ip.is_global or ip.is_multicast:
            raise ValueError(
                f"'{host}' points to a private or internal address, which this server will not "
                f"fetch. Ask the user for a public https link (Google Drive, Dropbox, or any "
                f"public download URL)."
            )


class _CheckedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Apply the same URL checks to every redirect hop."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _require_fetchable_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# Only http(s) handlers plus the checked redirect handler; no file://, ftp:// or data:.
_URL_OPENER = urllib.request.OpenerDirector()
for _handler in (urllib.request.ProxyHandler(), urllib.request.HTTPHandler(),
                 urllib.request.HTTPSHandler(), _CheckedRedirectHandler(),
                 urllib.request.HTTPErrorProcessor(), urllib.request.HTTPDefaultErrorHandler()):
    _URL_OPENER.add_handler(_handler)


def normalise_share_url(url: str) -> str:
    """Convert well-known sharing URLs to direct download URLs.

    Handles Google Drive share links and Dropbox share links.
    All other URLs are returned unchanged.
    """
    # Google Drive: https://drive.google.com/file/d/FILE_ID/view?...
    #           or: https://drive.google.com/open?id=FILE_ID
    # confirm=t skips Drive's virus-scan page for files over ~100 MB
    drive_download = 'https://drive.usercontent.google.com/download?id={}&export=download&confirm=t'
    parsed = urllib.parse.urlparse(url)
    if 'drive.google.com' in parsed.netloc:
        # /file/d/FILE_ID/... form
        parts = parsed.path.split('/')
        try:
            file_id = parts[parts.index('d') + 1]
            return drive_download.format(file_id)
        except (ValueError, IndexError):
            pass
        # ?id=FILE_ID form
        qs = urllib.parse.parse_qs(parsed.query)
        if 'id' in qs:
            return drive_download.format(qs['id'][0])
    # Dropbox: replace dl=0 with dl=1 (or add dl=1)
    if 'dropbox.com' in parsed.netloc:
        qs = urllib.parse.parse_qs(parsed.query)
        qs['dl'] = ['1']
        new_query = urllib.parse.urlencode({k: v[0] for k, v in qs.items()})
        return urllib.parse.urlunparse(parsed._replace(query=new_query))
    return url


def infer_filename_from_url_path(url: str) -> Optional[str]:
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


def download_url_tmp(url: str, suffix: str, timeout: int = 30,
                      max_bytes: Optional[int] = None) -> tuple:
    """Download a URL to a delete=False temp file; return (path, inferred_filename_or_None).

    Streams the response in 64 KB chunks to avoid loading the whole file into
    memory. Extracts the filename from the Content-Disposition response header
    when available (works for Google Drive and similar services). Cleans up the
    temp file if the download fails before the path is returned.

    `max_bytes` aborts the transfer as soon as the response passes the cap, so an
    oversized link is rejected without filling the temp directory first — the
    callers' own size checks can only run once the whole file is already on disk.
    Only http(s) URLs are accepted; see _require_fetchable_url.
    Raises: ValueError on a rejected URL or an oversized response;
            urllib.error.URLError / urllib.error.HTTPError / OSError on failure.
    """
    _require_fetchable_url(url)
    req = urllib.request.Request(url, headers={'User-Agent': 'BugasuraMCP/1.0'})
    tmp = tempfile.NamedTemporaryFile(mode='wb', suffix=suffix, delete=False)
    inferred_name: Optional[str] = None
    try:
        with _URL_OPENER.open(req, timeout=timeout) as resp:
            cd = resp.headers.get('Content-Disposition', '')
            if cd:
                m = re.search(r'filename[^;=\n]*=[\s"\']*([^;"\']+)[\s"\']*', cd, re.IGNORECASE)
                if m:
                    candidate = urllib.parse.unquote(m.group(1).strip('" \''))
                    if '.' in candidate:
                        inferred_name = candidate
            # A web page (sign-in, preview, quota error) where a file was expected must not be saved as the file.
            # Bugasura's own CDN is exempt: it labels stored files by sniffing them, so a .txt can be text/html
            if (resp.headers.get_content_type() == 'text/html' and not _on_bugasura_cdn(url)
                    and not suffix.lower().endswith(('.html', '.htm'))
                    and not (inferred_name or '').lower().endswith(('.html', '.htm'))):
                raise ValueError("the link returned a web page instead of the file — it may be private, "
                                 "need a sign-in, or not be a direct download link")
            written = 0
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                written += len(chunk)
                if max_bytes is not None and written > max_bytes:
                    limit = (f"{max_bytes / (1024 * 1024):.0f}MB" if max_bytes >= 1024 * 1024
                             else f"{max_bytes / 1024:.0f}KB")
                    raise ValueError(
                        f"The file at this link is larger than {limit}, so the download was "
                        f"stopped. Ask the user for a smaller file."
                    )
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


def fetch_url_bytes(url: str, max_bytes: int, timeout: int = 30) -> tuple:
    """Read a URL into memory; return (content, exceeded_limit).

    Stops reading once max_bytes has been passed and reports it through the
    second element, so an oversized file is detected without ever buffering
    the whole thing. `content` is truncated in that case and must not be
    treated as the complete file.
    Only http(s) URLs are accepted; see _require_fetchable_url.
    Raises: ValueError on a rejected URL;
            urllib.error.URLError / urllib.error.HTTPError / OSError on failure.
    """
    _require_fetchable_url(url)
    req = urllib.request.Request(url, headers={'User-Agent': 'BugasuraMCP/1.0'})
    with _URL_OPENER.open(req, timeout=timeout) as resp:
        # One byte past the cap is enough to tell "at the limit" from "over it".
        content = resp.read(max_bytes + 1)
    if len(content) > max_bytes:
        return content[:max_bytes], True
    return content, False


def _on_bugasura_cdn(url: str) -> bool:
    """True when `url` points at the CDN that serves files stored in Bugasura."""
    cdn_host = urllib.parse.urlparse(CDN_BASE_URL).netloc.lower() if CDN_BASE_URL else ''
    return bool(cdn_host) and urllib.parse.urlparse(url).netloc.lower() == cdn_host


def download_url_to_path(url: str, dest_path: str, timeout: int = 60,
                          max_bytes: Optional[int] = None) -> int:
    """Download a URL onto the local filesystem at dest_path; return the byte size.

    Streams through download_url_tmp() so the transfer never buffers the whole
    file in memory, then moves the temp file into place — shutil.move rather than
    os.replace, since the temp directory is often on a different filesystem. The
    destination is only written once the download has fully succeeded, and the temp
    file is removed if the move itself fails.

    The http(s)-only guard and the optional `max_bytes` cap are inherited from
    download_url_tmp, so nothing lands on disk from a rejected or oversized URL.
    Raises: ValueError on a rejected URL or an oversized response;
            urllib.error.URLError / urllib.error.HTTPError / OSError on failure.
    """
    suffix = os.path.splitext(dest_path)[1] or '.tmp'
    tmp_path, _ = download_url_tmp(url, suffix, timeout, max_bytes)
    try:
        shutil.move(tmp_path, dest_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return os.path.getsize(dest_path)


def resolve_save_destination(save_to_path: str, filename: str) -> tuple[str, Optional[str]]:
    """Turn a caller's save_to_path into the file path to write.

    A folder is an existing directory, a path ending in a separator, or a path that does
    not exist yet and has no file extension — the file goes inside it under `filename`.
    Anything else is the full file path, written as given. Nothing is created here: the
    second value is the missing folder the caller creates once its own checks pass.
    Raises: ValueError when save_to_path is not absolute.
    """
    raw = os.path.expanduser(save_to_path.strip())
    if not os.path.isabs(raw):
        raise ValueError(f"'{save_to_path}' is not an absolute path")
    if os.path.isdir(raw):
        return os.path.join(raw, filename), None
    if raw.endswith(('/', os.sep)) or (not os.path.exists(raw) and not os.path.splitext(raw)[1]):
        return os.path.join(raw, filename), raw
    return raw, None


def create_folder(folder: str) -> Optional[str]:
    """Create `folder` (parents included); return the topmost folder created, for remove_created_folder."""
    top, parent = None, os.path.abspath(folder)
    while parent and not os.path.exists(parent):
        top, parent = parent, os.path.dirname(parent)
    os.makedirs(folder, exist_ok=True)
    return top


def remove_created_folder(folder: str, top: Optional[str]) -> None:
    """Remove the empty folders create_folder made, from `folder` up to `top`."""
    if not top:
        return
    current = os.path.abspath(folder)
    while True:
        try:
            os.rmdir(current)
        except OSError:
            return
        if current == top:
            return
        current = os.path.dirname(current)


def local_path_rejected(param: str) -> Optional[dict]:
    """A `failed` payload when `param` (a server-side file path) is used over HTTP, else None.

    Over streamable HTTP the "local" filesystem is the shared server's, not the user's, so
    file paths would let any signed-in caller read or write files on that box.
    """
    if not in_http_request():
        return None
    return {
        'status': 'failed',
        'error': f'{param} is not available on this hosted Bugasura MCP server.',
        'error_type': 'ValidationError',
        'message': (f"{param} refers to the server's own filesystem, which a hosted server does not "
                    "expose. Create an upload link with bugasura_create_upload_link for the user's "
                    "file and pass its upload_id, or, where the tool takes one, a shareable https "
                    "link (Google Drive, Dropbox, or any public download URL) as source_url."),
    }


def close_upload_files(files: list) -> None:
    """Close the file handles in multipart fields built for an upload."""
    for _field, (_name, file_handle, _content_type) in files:
        file_handle.close()


# Comment kind -> (comments endpoint prefix, item id param) for /v1/{testcase,requirement}comments/*
_PROJECT_COMMENT_KINDS = {
    'testcase': ('/v1/testcasecomments', 'testCaseId'),
    'requirement': ('/v1/requirementcomments', 'requirementId'),
}


def attachment_names_csv(names: Optional[str]) -> Optional[str]:
    """A comma-separated filename list without the spaces the API would treat as part of a name."""
    if names is None:
        return None
    return ','.join(name.strip() for name in names.split(',') if name.strip())


async def project_comment_attachment_names(api_key: str, kind: str, team_id: int, project_id: int,
                                           item_id: int, comment_id: int,
                                           report_id: Optional[int] = None) -> Optional[str]:
    """
    A test case / requirement comment's attachment filenames as the update endpoint's CSV.

    Their update endpoint treats a missing attachment list as "keep none" and deletes the files,
    so an update that was not given one must resend this. None when the comment is unreadable.
    A test case comment posted in a sprint needs its report_id: without one the API only looks
    at comments made outside any sprint.
    """
    endpoint, id_param = _PROJECT_COMMENT_KINDS[kind]
    params = {'teamId': team_id, 'team_id': team_id, 'appId': project_id, 'app_id': project_id,
              id_param: item_id, 'commentId': comment_id}
    if report_id is not None:
        params.update(reportId=report_id, report_id=report_id)
    response = await make_api_request('GET', f'{endpoint}/get', api_key, params=params)
    if response.get('status') != 'OK':
        return None
    details = response.get('commentDetails')
    rows = details if isinstance(details, list) else [details] if isinstance(details, dict) else []
    row = next((r for r in rows if str(r.get('comment_id')) == str(comment_id)), None)
    if row is None:
        return None
    return attachment_names_csv(row.get('comment_attachments') or '')


async def send_with_attachments(method: str, endpoint: str, api_key: str, opened: dict,
                                upload_id: Optional[str], **kwargs) -> dict:
    """
    Make the API call with the files from `open_attachments` (streamed), then close them.

    On success the response gains `attached_files` and the upload link's staged files are
    deleted; on failure they are kept so the call can be retried with the same upload_id.
    """
    files = opened.get('files') or []
    if files:
        kwargs.update(files=files, timeout=UPLOAD_TIMEOUT)
    if files and upload_id and (busy := claim(upload_id)):
        close_upload_files(files)
        return busy
    succeeded = False
    try:
        response = await make_api_request(method, endpoint, api_key, **kwargs)
        succeeded = files and isinstance(response, dict) and response.get('status') == 'OK'
    finally:
        close_upload_files(files)
        if files and upload_id:
            discard(upload_id) if succeeded else release(upload_id)
    if succeeded:
        _report_skipped_attachments(response, opened['filenames'])
    return response


def _report_skipped_attachments(response: dict, filenames: list) -> None:
    """Set `attached_files`, leaving out files the API reported skipping (size or count limits).

    The API still answers OK when it skips files: issues list the reasons in `errorMessage`,
    requirements append them to `message`.
    """
    errors = response.get('errorMessage') or []
    errors = [str(e) for e in (errors if isinstance(errors, list) else [errors]) if e]
    message = str(response.get('message') or '')
    if 'error while uploading' in message.lower():
        errors.append(message)
    skipped = [name for name in filenames if any(name in error for error in errors)]
    response['attached_files'] = [name for name in filenames if name not in skipped]
    if errors:
        response['not_attached'] = skipped
        response['attachment_errors'] = errors
        response['warning'] = ("Bugasura did not store every file: " + "; ".join(errors) + ". Tell the user which "
                               "files were not attached; the plan's attachment size limit may be lower than the "
                               "MCP's. The upload link is used up, so a new one is needed to try those files again.")


def open_attachments(file_paths: Optional[list], upload_id: Optional[str]) -> dict:
    """
    Open the files to attach: an upload link's staged files, or local paths (STDIO only).

    Each file becomes its own multipart field (file0, file1, …), the shape every attachment
    endpoint accepts; the handles are streamed by httpx. Neither source given -> no files.
    The caller closes them with `close_upload_files` and discards `upload_id` on success.

    Returns:
        dict: {'status': 'OK', 'files': [(field, (filename, file_handle, content_type))],
               'filenames': [str]} or a failure envelope.
    """
    if file_paths and upload_id:
        return {'status': 'failed', 'error': 'Multiple file sources provided', 'error_type': 'ValidationError',
                'message': 'Provide either upload_id or file_paths, not both.'}
    if file_paths and (rejected := local_path_rejected('file_paths')):
        return rejected
    paths = list(file_paths or [])
    if upload_id:
        staged = staged_paths(upload_id, current_user_id(), 'attachment')
        if staged.get('status') != 'OK':
            return staged
        paths = staged['paths']

    files, filenames = [], []
    succeeded = False
    try:
        for index, path in enumerate(paths):
            name = os.path.basename(path)
            if not os.path.isfile(path):
                if upload_id:
                    return {'status': 'failed', 'error': 'Uploaded file unavailable', 'error_type': 'ValidationError',
                            'message': ("The uploaded file is no longer available. Create a new link with "
                                        "bugasura_create_upload_link(purpose='attachment') and ask the user to "
                                        "upload it again.")}
                return {'status': 'failed', 'error': f'File not found: {path}', 'error_type': 'ValidationError',
                        'message': f"Could not find a readable file at '{path}'. Ask the user for the exact absolute path."}
            if not os.path.splitext(name)[1]:
                return {'status': 'failed', 'error': 'Missing file extension', 'error_type': 'ValidationError',
                        'message': f"'{name}' has no file extension; Bugasura needs one to store an attachment."}
            size = os.path.getsize(path)
            if size > ATTACHMENT_MAX_FILE_SIZE_MB * 1024 * 1024:
                return {'status': 'failed', 'error': 'File too large', 'error_type': 'ValidationError',
                        'message': (f"'{name}' is {size / (1024 * 1024):.1f}MB. Attachments are limited to "
                                    f"{ATTACHMENT_MAX_FILE_SIZE_MB}MB each.")}
            content_type = mimetypes.guess_type(name)[0] or 'application/octet-stream'
            files.append((f"file{index}", (name, open(path, 'rb'), content_type)))
            filenames.append(name)
        succeeded = True
        return {'status': 'OK', 'files': files, 'filenames': filenames}
    except OSError as e:
        logger.error(f"open_attachments: could not open '{path}': {e}")
        return {'status': 'failed', 'error': 'Could not read file', 'error_type': 'IOError',
                'message': f"Could not read '{os.path.basename(path)}'."}
    finally:
        if not succeeded:
            close_upload_files(files)
