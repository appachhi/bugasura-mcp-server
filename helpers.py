"""Internal resolvers, file-upload utilities, and context helpers used by tools."""
import os
import re
import shutil
import tempfile
import urllib.parse
import urllib.request
from typing import Any, Optional
from urllib.parse import urlparse

import requests  # needed for except clauses referencing requests.RequestException

from auth import _get_api_key, _fetch_user_context, validate_api_key
from client import logger, make_api_request


# API host -> customer-facing web app base URL.
# Set WEB_BASE_URL in .env to override for deployments not listed here.
_KNOWN_WEB_BASES = {
    "api.bugasura.io":       "https://my.bugasura.io/",
    "api.stage.bugasura.io": "https://stage.bugasura.io/",
    "api.appachhi.net":      "http://appachhi.net/",
    "localhost":             "http://localhost/Appachhi/chhiscore/",
    "127.0.0.1":             "http://127.0.0.1/Appachhi/chhiscore/",
}


def _derive_web_base(api_base: str) -> str:
    """Return the customer-facing web app base URL derived from an API base URL."""
    try:
        p = urlparse(api_base)
        host = p.netloc.split('@')[-1].split(':')[0]
        if host in _KNOWN_WEB_BASES:
            return _KNOWN_WEB_BASES[host]
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}/"
    except Exception:
        pass
    return ""

# API host -> CDN base that serves stored files (config.application.cdnUrl upstream).
# Uploaded files are public objects under this base, so `CDN_BASE_URL + <file path>` is a
# working download link. Set CDN_BASE_URL in .env for deployments not listed here — the CDN
# is a separate CloudFront/S3 host, so unlike the web base it can never be guessed from the
# API host. localhost -> stage CloudFront is intentional: the backend's own LOCAL config
# resolves cdnUrl to that same distribution, so a local API still serves files from it.
_KNOWN_CDN_BASES = {
    "api.bugasura.io":       "https://dp891r6qeu0kb.cloudfront.net/",
    "api.stage.bugasura.io": "https://dfpr5nkt5jhxf.cloudfront.net/",
    "api.appachhi.net":      "https://dfpr5nkt5jhxf.cloudfront.net/",
    "localhost":             "https://dfpr5nkt5jhxf.cloudfront.net/",
    "127.0.0.1":             "https://dfpr5nkt5jhxf.cloudfront.net/",
}


def _derive_cdn_base(api_base: str) -> str:
    """Return the CDN base URL for a known API host, or '' when it is not known."""
    try:
        host = urlparse(api_base).netloc.split('@')[-1].split(':')[0]
        return _KNOWN_CDN_BASES.get(host, "")
    except Exception:
        return ""


_api_base = os.getenv("API_BASE_URL", "http://localhost/api.appachhi.com")
WEB_BASE_URL = os.getenv("WEB_BASE_URL", "").strip() or _derive_web_base(_api_base)
if WEB_BASE_URL and not WEB_BASE_URL.endswith("/"):
    WEB_BASE_URL += "/"

CDN_BASE_URL = os.getenv("CDN_BASE_URL", "").strip() or _derive_cdn_base(_api_base)
if CDN_BASE_URL and not CDN_BASE_URL.endswith("/"):
    CDN_BASE_URL += "/"


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
        context = await _fetch_user_context(api_key)

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
                'role': team['role']
            } for team in teams],
            'instruction': f'Please call {operation_name} again with team_id parameter. Example: {operation_name}(api_key="{api_key[:4]}...", team_id=<selected_team_id>{operation_params})'
        }

    # Step 2: If project_id not provided, fetch and return project options
    if project_id is None:
        context = await _fetch_user_context(api_key)

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
            'instruction': f'Please call {operation_name} again with project_id parameter. Example: {operation_name}(api_key="{api_key[:4]}...", team_id={team_id}, project_id=<selected_project_id>{operation_params})'
        }

    # Both team_id and project_id provided - return validated context
    return {
        'team_id': team_id,
        'project_id': project_id
    }


async def _resolve_team_identifier(api_key: str, team_id: Optional[int], team_name: Optional[str]) -> dict:
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
        logger.info(f"_resolve_team_identifier: Both team_id={team_id} and team_name='{team_name}' provided, using team_id")
        return {
            'status': 'OK',
            'team_id': team_id,
            'team_name': team_name  # Pass through, will be validated by API
        }

    # team_id provided - use it directly
    if team_id is not None:
        logger.info(f"_resolve_team_identifier: Using provided team_id={team_id}")
        return {
            'status': 'OK',
            'team_id': team_id,
            'team_name': None
        }

    # team_name provided - resolve to team_id
    if team_name is not None and team_name.strip():
        logger.info(f"_resolve_team_identifier: Resolving team_name='{team_name}' to team_id")

        # Use find_team_by_name to search
        search_result = await find_team_by_name(api_key=api_key, team_name=team_name)

        if search_result.get('status') != 'OK':
            logger.error(f"_resolve_team_identifier: Failed to search for team: {search_result.get('message')}")
            return {
                'status': 'failed',
                'error': 'Team search failed',
                'error_type': 'TeamSearchError',
                'message': f"Could not search for team '{team_name}': {search_result.get('message', 'Unknown error')}"
            }

        matches = search_result.get('matches', [])
        match_count = search_result.get('count', 0)

        if match_count == 0:
            logger.error(f"_resolve_team_identifier: No teams found matching '{team_name}'")
            return {
                'status': 'failed',
                'error': 'Team not found',
                'error_type': 'TeamNotFound',
                'message': f"No teams found matching '{team_name}'. Check the team name and try again."
            }

        if match_count > 1:
            logger.warning(f"_resolve_team_identifier: Multiple teams ({match_count}) found matching '{team_name}'")
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
        logger.info(f"_resolve_team_identifier: Resolved '{team_name}' to team_id={resolved_team_id} ('{resolved_team_name}')")

        return {
            'status': 'OK',
            'team_id': resolved_team_id,
            'team_name': resolved_team_name
        }

    # Neither provided
    logger.error("_resolve_team_identifier: Neither team_id nor team_name provided")
    return {
        'status': 'failed',
        'error': 'Missing team identifier',
        'error_type': 'ValidationError',
        'message': 'Please provide either team_id or team_name'
    }


async def _fetch_team_members(api_key: str, team_id: int) -> dict:
    """
    Internal helper to fetch team members.
    This is NOT an MCP tool - it's a helper function that can be called from Python code.

    Args:
        api_key: User's Bugasura API key
        team_id: Team identifier

    Returns:
        dict: API response with team members
    """
    logger.info(f"_fetch_team_members: Fetching members for team_id={team_id}")

    # Call API to get team members directly (no validation to avoid recursive calls)
    logger.info(f"_fetch_team_members: Calling /v1/teamUsers/get for team_id={team_id}")
    response = await make_api_request('GET', '/v1/teamUsers/get', api_key, params={
        'team_id': str(team_id)
    })

    if isinstance(response, dict) and response.get('status') == 'OK':
        member_count = len(response.get('team_users_details', []))
        logger.info(f"_fetch_team_members: Successfully fetched {member_count} team members")
    else:
        logger.error(f"_fetch_team_members: Failed to fetch team members. Response: {response}")

    return response


async def _find_user_ids_by_names_or_emails(api_key: str, team_id: int, identifiers: str) -> dict:
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
    members_response = await _fetch_team_members(api_key, team_id)

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


async def _resolve_issue_identifier_to_id(api_key: str, team_id: int, project_id: int, issue_id: str, function_name: str = "") -> dict:
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
        issues_response = await make_api_request('GET', '/v1/issues/list', api_key, params={
            'team_id': str(team_id),
            'project_id': str(project_id),
            'start_at': offset,
            'max_results': PAGE_SIZE,
        })

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
    if not parsed.netloc:
        raise ValueError(f"'{url}' has no host — it is not a fetchable link.")


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


def _download_url_tmp(url: str, suffix: str, timeout: int = 30,
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
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            cd = resp.headers.get('Content-Disposition', '')
            if cd:
                m = re.search(r'filename[^;=\n]*=[\s"\']*([^;"\']+)[\s"\']*', cd, re.IGNORECASE)
                if m:
                    candidate = urllib.parse.unquote(m.group(1).strip('" \''))
                    if '.' in candidate:
                        inferred_name = candidate
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


def _fetch_url_bytes(url: str, max_bytes: int, timeout: int = 30) -> tuple:
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
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        # One byte past the cap is enough to tell "at the limit" from "over it".
        content = resp.read(max_bytes + 1)
    if len(content) > max_bytes:
        return content[:max_bytes], True
    return content, False


def _download_url_to_path(url: str, dest_path: str, timeout: int = 60,
                          max_bytes: Optional[int] = None) -> int:
    """Download a URL onto the local filesystem at dest_path; return the byte size.

    Streams through _download_url_tmp() so the transfer never buffers the whole
    file in memory, then moves the temp file into place — shutil.move rather than
    os.replace, since the temp directory is often on a different filesystem. The
    destination is only written once the download has fully succeeded, and the temp
    file is removed if the move itself fails.

    The http(s)-only guard and the optional `max_bytes` cap are inherited from
    _download_url_tmp, so nothing lands on disk from a rejected or oversized URL.
    Raises: ValueError on a rejected URL or an oversized response;
            urllib.error.URLError / urllib.error.HTTPError / OSError on failure.
    """
    suffix = os.path.splitext(dest_path)[1] or '.tmp'
    tmp_path, _ = _download_url_tmp(url, suffix, timeout, max_bytes)
    try:
        shutil.move(tmp_path, dest_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return os.path.getsize(dest_path)
