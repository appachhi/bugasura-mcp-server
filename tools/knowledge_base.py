"""Bugasura MCP tools: project knowledge base.

The knowledge base is a project-level document library organised in folders
(`projectFolders.folder_type = 'KNOWLEDGE_BASE'`). It is separate from the
per-sprint TestPert knowledge base in `tools/testpert.py`: documents added here
belong to the project, are visible on the web app's Knowledge Base page, and are
picked up by the engine's KB processing sweep so they become searchable project
context.

Documents live in `/v1/knowledgebase/*` and their folders in `/v1/projectFolders/*`
with `folderType=KNOWLEDGE_BASE`; the tools here cover both. Uploads mirror the web
app's "Import from file" flow — POST /v1/knowledgebase/add with `kbType=upload_file`
and one multipart field per file. `folderId` is required upstream, so every upload
resolves (or creates) a folder first; see `_resolve_kb_folder`.

Folders and documents are addressed by name wherever possible (`_find_kb_folder`,
`_find_kb_document`), since that is how users refer to them; both fall back to ids
and report the available options when a name is unknown or ambiguous.

Alongside uploaded files the knowledge base holds *page documents* — the web app's
"Create Document" flow (`kbType=custom_doc`), a Notion-style document whose body is a
tree of pages. Their pages live in `connection_details.pageDetails` as a flat list of
`{page_id, page_name, parent_id, uploaded_file_path, ...}` entries, and every page
action goes through POST /v1/knowledgebase/update with a `customFileDetails` action
envelope (`add_page`, `edit_page_name`, `delete_page`, `page_reposition`, ...); see
`_kb_doc_page_action`. A page's markdown body is stored as its own S3 file: the API only
ever writes it, so reading a page back means fetching that file from the CDN the way the
web app's editor does — see `_read_kb_page_content`. Editing a page is therefore always
read-modify-write, since the write action replaces the whole body.

This module owns the knowledge base's own structure — its folders, its documents, and the
pages inside a page document — and, alongside it, every way content gets *in*: all six
entries in the Knowledge Base page's "+" menu, plus the document editor's own Import menu.

The six are two kinds. A **file upload** and a **website crawl** need nothing but the
content itself: the file is posted as multipart form data (`kbType=upload_file`), the site
as a URL to crawl (`kbType=url`). The four **connector imports** — Coda ("Superhuman
Import"), Jira, Confluence and Figma — pull from a third-party tool, so each ships with
listing tools that let a caller show the user what is importable before committing.

Every connector import is the same two-step shape the web app's modals use:

1. Ask the tool what is there — Coda docs/pages, Jira projects/issues, Confluence
   spaces/pages, a Figma frame's name and export link. Bugasura proxies all of these
   except Figma, which is queried directly (`_fetch_figma_frame`), exactly as the web
   app's own controller does.
2. POST the selection to /v1/knowledgebase/add with the connector's `kbType` and a
   `toolsConnectionDetails` payload. The API stores the selection, leaves the row at
   stage CONNECTED and queues a worker — the actual fetching happens in the background,
   so no tool here waits on it.

Credentials are never stored by these tools: the user supplies them per call, the same
way each modal asks for them, and they are forwarded to Bugasura which forwards them to
the tool. They are never logged.

Jira and Confluence can also import *into an existing page document* rather than creating
a new one — the web app reuses the same modal for both, and so do the tools here through
their optional `document_identifier`. That path posts to /v1/knowledgebase/importDocPages
instead, which merges the new selection into the document's `connection_details` and
queues the same worker. `bugasura_import_file_to_knowledge_base_document` is the third
member of that in-document family: the KB document editor's Markdown / CSV / Excel import.

Figma is the one import with replace semantics: the API treats the submitted frame list as
the complete set of Figma entries for the project and DELETES every stored Figma entry
missing from it. `bugasura_import_figma_to_knowledge_base` therefore reads the existing
entries first and carries them forward unless the caller explicitly asks to replace them.
"""
from typing import Any, Dict, List, Literal, Optional

from pydantic import Field

from output_types import ToolResponse
from app import mcp
from auth import _get_api_key, validate_api_key
from client import _get_http_client, _paginated, _respond, logger, make_api_request
from helpers import (
    _download_url_to_path, _download_url_tmp, _fetch_url_bytes,
    _infer_filename_from_url_path, _normalise_share_url,
    select_team_project_context, CDN_BASE_URL, WEB_BASE_URL,
)

import asyncio
import httpx
import json
import mimetypes
import os
import urllib.parse


# Folder type that scopes a project's knowledge base folders (projectFolders.folder_type).
_KB_FOLDER_TYPE = 'KNOWLEDGE_BASE'
# Folder created when the project has no knowledge base folder yet and the user named
# none — mirrors the default-folder behaviour of bugasura_create_requirement.
_KB_DEFAULT_FOLDER_NAME = 'Knowledge Base'
# Characters the folder endpoints reject (validator pattern '^[^<>\\/\\\\]*$'). Checked here
# so a bad name comes back as a clear ValidationError instead of an upstream regex message.
_KB_FOLDER_NAME_INVALID_CHARS = '<>/\\'
# How many options a "which one did you mean?" failure lists back to the caller.
_KB_MAX_CHOICES = 25

# Document types whose body is a tree of pages in connection_details.pageDetails. custom_doc is
# the one users author here; coda/url/jira/confluence docs are synced from a connected tool but
# are stored — and edited — in the very same shape.
_KB_PAGE_DOC_TYPES = ('custom_doc', 'coda', 'url', 'jira', 'confluence')
# Type created by bugasura_create_knowledge_base_document (the web app's "Create Document").
_KB_CUSTOM_DOC_TYPE = 'custom_doc'
# Names the API falls back to when the caller provides none — matched to spot a still-unnamed doc.
_KB_DEFAULT_DOC_NAME = 'Untitled Doc'
_KB_DEFAULT_PAGE_NAME = 'Untitled Page'
# Cap on the markdown a page read returns. A page over this is REFUSED rather than truncated:
# writing a page replaces its whole body, so handing back a partial one invites an edit that
# silently deletes the rest.
_KB_MAX_PAGE_CONTENT_BYTES = 200 * 1024
# Blank line inserted between the old and new body on an append/prepend, so the two halves stay
# separate markdown blocks instead of running together into one paragraph.
_KB_PAGE_CONTENT_JOINER = '\n\n'

# Extensions the Knowledge Base accepts on an upload (matches the web app's file picker).
_KB_DOC_EXTS = {'txt', 'pdf', 'doc', 'docx', 'md'}
# Per-file cap enforced upstream by config.application.maxTestpertFileSize (MB).
_KB_MAX_FILE_SIZE_MB = 100
# Multipart field prefix. The web app posts choose_file[]; the API iterates $_FILES
# and ignores the field names, so one indexed field per file is what reaches it.
_KB_UPLOAD_FIELD_PREFIX = 'choose_file'
# Pages a website import will crawl. The API clamps max_limit to this and defaults to it.
_KB_MAX_WEBSITE_PAGES = 1000
# Marker the API reads as "import everything in this project/space" (it compares the
# selection list against exactly this one-element form).
_KB_IMPORT_ALL = ['all']
# Issues/pages listed per call by the discovery tools. The upstream endpoints cap far
# higher; this keeps a listing readable in a tool response.
_KB_CONNECTOR_PAGE_SIZE = 50
# Most Figma frame URLs one import may carry — the web app's own cap.
_KB_FIGMA_MAX_URLS = 50
# Source/source type the web app files a Figma import under. They are sent explicitly
# rather than left to the API's folder-name fallback, because they also scope the
# replace-the-whole-set behaviour described in the module docstring.
_KB_FIGMA_SOURCE = 'FIGMA'
_KB_FIGMA_SOURCE_TYPE = 'DESIGN'
# Figma path segments that precede the file key (https://www.figma.com/design/<key>/...).
_KB_FIGMA_URL_KINDS = ('design', 'file', 'proto', 'board', 'slides')
_KB_FIGMA_API_BASE = 'https://api.figma.com/v1'
# Extension -> the API's importType for the KB document editor's Import menu.
_KB_DOC_IMPORT_TYPES = {'md': 'md_file', 'csv': 'csv_file', 'xlsx': 'excel_file', 'xls': 'excel_file'}
# Per-file cap the importDocPages endpoint enforces (MB).
_KB_DOC_IMPORT_MAX_FILE_SIZE_MB = 10
# Stages that mean a page import is already running on a document; the API refuses a
# second one, so the tools report it before spending a request.
_KB_DOC_IMPORTING_STAGES = ('IMPORT_PAGES', 'IMPORTING_PAGES')


@mcp.tool(
    name="bugasura_create_knowledge_base_folder",
    description=(
        "Create a folder in a Bugasura project's Knowledge Base. Pass parent_folder_name (or "
        "parent_folder_id) to nest the new folder inside an existing knowledge base folder; omit both "
        "to create it at root level. When a folder with the same name already exists at that level the "
        "existing folder is returned instead of failing, so this is safe to call twice. "
        "This creates the folder only — use bugasura_upload_knowledge_base_document to put documents in it."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def create_knowledge_base_folder(
    folder_name: str = Field(description="Name for the new knowledge base folder"),
    parent_folder_name: Optional[str] = Field(default=None, description="Existing knowledge base folder to nest the new folder inside. Matched case-insensitively anywhere in the folder tree. Omit for a root-level folder."),
    parent_folder_id: Optional[int] = Field(default=None, description="Parent folder identifier. Use only when the user picked a specific folder from a list — parent_folder_name is the normal way to target a parent.", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Create a knowledge base folder, optionally nested under an existing one.

    Posts to /v1/projectFolders/add with `folderType=KNOWLEDGE_BASE`, mirroring the
    web app's "New folder" action on the Knowledge Base page. The parent, when given,
    is validated against the project's own knowledge base folders so a requirements or
    test-repo folder can never become the parent.

    Args:
        folder_name: Name for the new folder (required)
        parent_folder_name: Existing knowledge base folder to nest under (optional)
        parent_folder_id: Explicit parent identifier (takes precedence over parent_folder_name)
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'folder_id': int,
            'folder_name': str,
            'parent_folder_id': int | '',
            'parent_folder_name': str | None,
            'created': bool,             # False when an existing folder was reused
            'knowledge_base_url': str,   # web app link, when the web base is known
            'message': str
        }
        OR a selection prompt / failure envelope.

    Examples:
        # Root-level folder
        create_knowledge_base_folder(folder_name="Product Specs", team_id=12, project_id=34)

        # Nested under an existing knowledge base folder
        create_knowledge_base_folder(folder_name="Testcase", parent_folder_name="Requirements")
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(
        api_key, team_id, project_id, 'bugasura_create_knowledge_base_folder',
        f', folder_name="{folder_name}"'
    )
    if context.get('status') == 'selection_required':
        return context
    if context.get('status') == 'failed':
        return context

    team_id = context['team_id']
    project_id = context['project_id']

    if not folder_name or not folder_name.strip():
        return {
            'status': 'failed',
            'error': 'Folder name is required',
            'error_type': 'ValidationError',
            'message': 'Please provide a name for the knowledge base folder.'
        }
    folder_name = folder_name.strip()

    team_id = await _resolve_project_team_id(api_key, team_id, project_id,
                                             'create_knowledge_base_folder')

    # Resolve the parent, when one was asked for. The lookup never creates — the user
    # named a folder they believe exists, so an unknown name is an error worth reporting.
    resolved_parent_id = 0
    resolved_parent_name = None
    if parent_folder_id is not None or (parent_folder_name and parent_folder_name.strip()):
        parent = await _find_kb_folder(api_key, team_id, project_id, parent_folder_id,
                                       parent_folder_name, role='parent folder')
        if parent.get('status') != 'OK':
            return _with_hint(parent, "Ask the user which folder to nest under, or omit the parent "
                                      "for a root-level folder.")
        resolved_parent_id = parent['folder_id']
        resolved_parent_name = parent['folder_name']

    logger.info(f"create_knowledge_base_folder: Creating '{folder_name}' in project_id={project_id} under "
                f"parent={resolved_parent_name or 'root'}")

    result = await _create_kb_folder(api_key, team_id, project_id, folder_name, resolved_parent_id)
    if result.get('status') != 'OK':
        return result

    response = {
        'status': 'OK',
        'folder_id': result['folder_id'],
        'folder_name': result['folder_name'],
        'parent_folder_id': resolved_parent_id or '',
        'parent_folder_name': resolved_parent_name,
        'created': result.get('created', False),
    }

    where = f"inside '{resolved_parent_name}'" if resolved_parent_name else "at root level"
    response['message'] = (
        f"Created the knowledge base folder '{result['folder_name']}' {where}."
        if result.get('created')
        else f"A knowledge base folder named '{result['folder_name']}' already exists {where}; reusing it."
    )

    if WEB_BASE_URL:
        knowledge_base_url = f"{WEB_BASE_URL}knowledgeBase/{project_id}"
        response['knowledge_base_url'] = knowledge_base_url
        response['message'] += f" You can view the knowledge base here: {knowledge_base_url}"

    logger.info(f"create_knowledge_base_folder: folder_id={response['folder_id']} "
                f"(created={response['created']})")
    return response


@mcp.tool(
    name="bugasura_rename_knowledge_base_folder",
    description=(
        "Rename a folder in a Bugasura project's Knowledge Base. Identify the folder by its "
        "current name (matched case-insensitively anywhere in the folder tree) or by its id. "
        "The folder keeps its place in the tree and everything inside it — this changes the "
        "name only; use bugasura_list_knowledge_base_folders first when you are not sure "
        "which folder the user means. Renaming a folder to a name another folder already has "
        "at the same level is refused, and a name containing < > / or \\ is rejected."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def rename_knowledge_base_folder(
    new_name: str = Field(description="New name for the folder. Up to 250 characters; cannot contain < > / or \\."),
    folder_name: Optional[str] = Field(default=None, description="Knowledge base folder to rename, by its current name. Matched case-insensitively anywhere in the folder tree."),
    folder_id: Optional[int] = Field(default=None, description="Knowledge base folder identifier. Use only when the user picked a specific folder from a list — folder_name is the normal way to target a folder.", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Rename a knowledge base folder.

    Posts to /v1/projectFolders/update with `updateType=NAME_UPDATE` and
    `folderType=KNOWLEDGE_BASE`, mirroring the web app's inline folder rename. The endpoint
    checks the folder still sits under the parent it is told about, so the folder's current
    `parent_folder_id` is read from the tree and sent back unchanged — the folder is renamed
    in place, never moved.

    A rename to the name the folder already has is a no-op and is answered without a write.
    A clash with a sibling folder's name is caught here so the failure names the folder in
    the way, matching the check the API makes.

    Args:
        new_name: New folder name (required)
        folder_name / folder_id: Folder to rename (one of them is required)
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'folder_id': int,
            'folder_name': str,          # the new name
            'previous_folder_name': str,
            'parent_folder_id': int | '',
            'parent_folder_name': str | None,
            'renamed': bool,             # False when the folder already had that name
            'knowledge_base_url': str,   # web app link, when the web base is known
            'message': str
        }
        OR a selection prompt / failure envelope.

    Examples:
        # Rename by the folder's current name
        rename_knowledge_base_folder(folder_name="Product Specs", new_name="Product Requirements")

        # Rename the folder the user picked from a list
        rename_knowledge_base_folder(folder_id=412, new_name="Archive", team_id=12, project_id=34)
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(
        api_key, team_id, project_id, 'bugasura_rename_knowledge_base_folder',
        f', folder_name="{folder_name}", new_name="{new_name}"' if folder_name
        else f', new_name="{new_name}"'
    )
    if context.get('status') == 'selection_required':
        return context
    if context.get('status') == 'failed':
        return context

    team_id = context['team_id']
    project_id = context['project_id']

    if not new_name or not new_name.strip():
        return {
            'status': 'failed',
            'error': 'New folder name is required',
            'error_type': 'ValidationError',
            'message': 'Ask the user what the folder should be called, then pass it as new_name.'
        }
    new_name = new_name.strip()

    invalid_chars = sorted({c for c in new_name if c in _KB_FOLDER_NAME_INVALID_CHARS})
    if invalid_chars:
        return {
            'status': 'failed',
            'error': 'Invalid folder name',
            'error_type': 'ValidationError',
            'message': (f"A folder name cannot contain {' '.join(invalid_chars)}. Ask the user for a "
                        f"name without < > / or \\.")
        }

    team_id = await _resolve_project_team_id(api_key, team_id, project_id,
                                             'rename_knowledge_base_folder')

    folder = await _find_kb_folder(api_key, team_id, project_id, folder_id, folder_name)
    if folder.get('status') != 'OK':
        return _with_hint(folder, "List the folders with bugasura_list_knowledge_base_folders.")

    folders = folder['folders']
    # The API validates the folder against the parent it is given, so send back the one the
    # folder already has ('' for a root-level folder).
    current = next((f for f in folders if str(f['folder_id']) == str(folder['folder_id'])), {})
    parent_folder_id = str(current.get('parent_folder_id') or '')
    parent_folder_name = next((f['folder_name'] for f in folders
                               if str(f['folder_id']) == parent_folder_id), None)

    where = f"inside '{parent_folder_name}'" if parent_folder_name else "at root level"

    if folder['folder_name'] == new_name:
        logger.info(f"rename_knowledge_base_folder: folder_id={folder['folder_id']} is already "
                    f"named '{new_name}', nothing to do")
        unchanged = {
            'status': 'OK',
            'folder_id': folder['folder_id'],
            'folder_name': folder['folder_name'],
            'previous_folder_name': folder['folder_name'],
            'parent_folder_id': current.get('parent_folder_id') or '',
            'parent_folder_name': parent_folder_name,
            'renamed': False,
            'message': f"The knowledge base folder is already called '{new_name}'; nothing changed."
        }
        if WEB_BASE_URL:
            unchanged['knowledge_base_url'] = f"{WEB_BASE_URL}knowledgeBase/{project_id}"
        return unchanged

    # The API refuses two folders with the same name under the same parent — catch it here so
    # the failure can name the folder in the way. Compared exactly, as the API compares.
    clash = next((f for f in folders
                  if str(f['folder_id']) != str(folder['folder_id'])
                  and str(f['parent_folder_id'] or '') == parent_folder_id
                  and f['folder_name'] == new_name), None)
    if clash is not None:
        logger.warning(f"rename_knowledge_base_folder: A folder named '{new_name}' already exists "
                       f"{where} (folder_id={clash['folder_id']})")
        return {
            'status': 'failed',
            'error': 'Knowledge base folder name already exists',
            'error_type': 'DuplicateFolderName',
            'message': (f"Another knowledge base folder {where} is already called '{new_name}'. "
                        f"Ask the user for a different name, or move the documents into that "
                        f"folder instead of renaming this one."),
            'folder_id': folder['folder_id'],
            'folder_name': folder['folder_name'],
            'existing_folder_id': clash['folder_id']
        }

    logger.info(f"rename_knowledge_base_folder: Renaming folder_id={folder['folder_id']} "
                f"('{folder['folder_name']}') to '{new_name}' in project_id={project_id}")

    response = await make_api_request('POST', '/v1/projectFolders/update', api_key, data={
        'appId': str(project_id),
        'teamId': str(team_id),
        'folderId': str(folder['folder_id']),
        'folderName': new_name,
        'parentFolderId': parent_folder_id,
        'updateType': 'NAME_UPDATE',
        'folderType': _KB_FOLDER_TYPE,
    })

    if response.get('status') != 'OK':
        logger.error(f"rename_knowledge_base_folder: Rename failed for "
                     f"folder_id={folder['folder_id']}: {response.get('message')}")
        return response

    # The API sanitises the name before storing it, so report the name it actually kept.
    folder_details = response.get('folderDetails')
    response['folder_id'] = folder['folder_id']
    response['folder_name'] = (folder_details.get('folder_name', new_name)
                               if isinstance(folder_details, dict) else new_name)
    response['previous_folder_name'] = folder['folder_name']
    response['parent_folder_id'] = current.get('parent_folder_id') or ''
    response['parent_folder_name'] = parent_folder_name
    response['renamed'] = True
    response['message'] = (f"Renamed the knowledge base folder '{folder['folder_name']}' to "
                           f"'{response['folder_name']}' ({where}).")

    if WEB_BASE_URL:
        knowledge_base_url = f"{WEB_BASE_URL}knowledgeBase/{project_id}"
        response['knowledge_base_url'] = knowledge_base_url
        response['message'] += f" You can view the knowledge base here: {knowledge_base_url}"

    logger.info(f"rename_knowledge_base_folder: Renamed folder_id={folder['folder_id']}")
    return response


@mcp.tool(
    name="bugasura_list_knowledge_base_folders",
    description=(
        "List the folders in a Bugasura project's Knowledge Base, with the document count in each. "
        "Use this to show the user which folders exist before uploading a document, deleting a "
        "folder, or nesting a new one. Returns every folder in the project as a flat list; "
        "`parent_folder_id` tells you how they nest ('' means root level)."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def list_knowledge_base_folders(
    parent_folder_id: Optional[int] = Field(default=None, description="Filter to the direct children of this folder. Pass 0 for root-level folders only. Omit to get every knowledge base folder in the project.", ge=0),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    List a project's knowledge base folders.

    Reads /v1/projectFolders/get with `folderType=KNOWLEDGE_BASE` and flattens the
    folder tree, so sub-folders are listed alongside root folders with their
    `parent_folder_id`.

    Args:
        parent_folder_id: 0 for root folders, a folder id for its children, omit for all
        team_id / project_id: Resolved interactively if omitted
        response_format: 'json' or 'markdown'
        api_key: User's Bugasura API key

    Returns:
        dict: Standard pagination envelope whose items are
        {'folder_id', 'folder_name', 'parent_folder_id', 'kb_count'}, plus
        'folders', 'project_id', 'team_id', 'knowledge_base_url' and 'message'.
        OR a selection prompt / failure envelope.

    Examples:
        # Every knowledge base folder in the project
        list_knowledge_base_folders(team_id=12, project_id=34)

        # Root-level folders only
        list_knowledge_base_folders(parent_folder_id=0)
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return _respond(validation, response_format)

    context = await select_team_project_context(api_key, team_id, project_id,
                                                'bugasura_list_knowledge_base_folders')
    if context.get('status') == 'selection_required':
        return _respond(context, response_format)
    if context.get('status') == 'failed':
        return _respond(context, response_format)

    team_id = context['team_id']
    project_id = context['project_id']
    team_id = await _resolve_project_team_id(api_key, team_id, project_id,
                                             'list_knowledge_base_folders')

    folders_response = await _fetch_kb_folders(api_key, team_id, project_id)
    if folders_response.get('status') != 'OK':
        return _respond(folders_response, response_format)

    folders = folders_response['folders']

    if parent_folder_id is not None:
        # Root folders carry an empty parent; everything else carries its parent's id.
        wanted_parent = '' if parent_folder_id == 0 else str(parent_folder_id)
        folders = [f for f in folders if str(f['parent_folder_id'] or '') == wanted_parent]
        scope = ("root-level knowledge base folders" if parent_folder_id == 0
                 else f"sub-folders of folder {parent_folder_id}")
    else:
        scope = "knowledge base folders"

    message = f"Retrieved {len(folders)} {scope}."
    if not folders:
        message = (f"This project has no {scope} yet. Create one with "
                   f"bugasura_create_knowledge_base_folder, or upload a document and the folder "
                   f"is created for you.")

    extras = {'folders': folders, 'project_id': project_id, 'team_id': team_id, 'message': message}
    if WEB_BASE_URL:
        extras['knowledge_base_url'] = f"{WEB_BASE_URL}knowledgeBase/{project_id}"

    logger.info(f"list_knowledge_base_folders: Returning {len(folders)} folder(s) for "
                f"project_id={project_id}")
    return _respond(_paginated(folders, total=len(folders), offset=0, **extras), response_format)


@mcp.tool(
    name="bugasura_list_knowledge_base_documents",
    description=(
        "List the documents in a Bugasura project's Knowledge Base. Pass folder_name (or folder_id) "
        "to list one folder and its sub-folders; omit both to list every document in the project. "
        "Set starred_only=True for the user's starred documents. Use this to show the user what is "
        "in the knowledge base, and to get the document id needed to delete or star one."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def list_knowledge_base_documents(
    folder_name: Optional[str] = Field(default=None, description="Knowledge base folder to list. Matched case-insensitively anywhere in the folder tree. Omit to list every document in the project."),
    folder_id: Optional[int] = Field(default=None, description="Knowledge base folder identifier. Use only when the user picked a specific folder from a list — folder_name is the normal way to target a folder.", ge=1),
    starred_only: bool = Field(default=False, description="List only the documents that have been starred (default: False)"),
    start_at: int = Field(default=0, description="Pagination offset (default: 0)", ge=0),
    max_results: int = Field(default=25, description="Number of documents to return (default: 25)", ge=1, le=100),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    List the documents in a project's knowledge base.

    Reads /v1/knowledgebase/getDocs, which returns the documents of the selected folder
    *and its sub-folders* (or of every knowledge base folder when none is selected).
    The upstream endpoint returns the full set, so pagination is applied here.

    Args:
        folder_name / folder_id: Folder to list (optional — omit for the whole project)
        starred_only: Restrict to starred documents
        start_at / max_results: Pagination window
        team_id / project_id: Resolved interactively if omitted
        response_format: 'json' or 'markdown'
        api_key: User's Bugasura API key

    Returns:
        dict: Standard pagination envelope whose items are
        {'kb_id', 'doc_name', 'folder_id', 'folder_name', 'source', 'source_type', 'type',
        'stage', 'file_size', 'is_starred', 'created_by', 'created_date', 'last_modified'},
        plus 'documents', 'folder_name', 'knowledge_base_url' and 'message'.
        OR a selection prompt / failure envelope.

    Examples:
        # Everything in the project's knowledge base
        list_knowledge_base_documents(team_id=12, project_id=34)

        # One folder
        list_knowledge_base_documents(folder_name="Product Specs")

        # Starred documents only
        list_knowledge_base_documents(starred_only=True)
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return _respond(validation, response_format)

    context = await select_team_project_context(api_key, team_id, project_id,
                                                'bugasura_list_knowledge_base_documents')
    if context.get('status') == 'selection_required':
        return _respond(context, response_format)
    if context.get('status') == 'failed':
        return _respond(context, response_format)

    team_id = context['team_id']
    project_id = context['project_id']
    team_id = await _resolve_project_team_id(api_key, team_id, project_id,
                                             'list_knowledge_base_documents')

    # Resolve the folder scope, when one was asked for. The lookup never creates a folder.
    scope_folder_id = None
    scope_folder_name = None
    if folder_id is not None or (folder_name and folder_name.strip()):
        folder = await _find_kb_folder(api_key, team_id, project_id, folder_id, folder_name)
        if folder.get('status') != 'OK':
            return _respond(_with_hint(folder, "List the folders with "
                                               "bugasura_list_knowledge_base_folders."), response_format)
        scope_folder_id = folder['folder_id']
        scope_folder_name = folder['folder_name']

    documents_response = await _fetch_kb_documents(api_key, team_id, project_id,
                                                   scope_folder_id, starred_only)
    if documents_response.get('status') != 'OK':
        return _respond(documents_response, response_format)

    documents = documents_response['documents']
    page = documents[start_at:start_at + max_results]

    where = f"the '{scope_folder_name}' folder" if scope_folder_name else "the knowledge base"
    what = "starred document(s)" if starred_only else "document(s)"
    message = f"{len(documents)} {what} in {where}."
    if not documents:
        message = (f"No starred documents in {where}." if starred_only
                   else f"No documents in {where} yet. Add one with "
                        f"bugasura_upload_knowledge_base_document.")

    extras = {
        'documents': page,
        'folder_id': scope_folder_id,
        'folder_name': scope_folder_name,
        'starred_only': starred_only,
        'project_id': project_id,
        'team_id': team_id,
        'message': message,
    }
    if WEB_BASE_URL:
        extras['knowledge_base_url'] = f"{WEB_BASE_URL}knowledgeBase/{project_id}"

    logger.info(f"list_knowledge_base_documents: Returning {len(page)} of {len(documents)} "
                f"document(s) for project_id={project_id}")
    return _respond(_paginated(page, total=len(documents), offset=start_at, **extras), response_format)


@mcp.tool(
    name="bugasura_download_knowledge_base_document",
    description=(
        "Get an uploaded Knowledge Base document as a file the user can open — a PDF, Word "
        "document, text or markdown file. Returns download_url, a direct link to the file "
        "that opens in a browser with no login; give that link to the user when they just "
        "want the document. "
        "Additionally pass save_to_path (an absolute path or directory on the machine "
        "running this server) to have the server write the file to disk as well — useful in "
        "the terminal, where that machine is the user's own; pointless when the server runs "
        "elsewhere, so ask before assuming. "
        "Only documents that were UPLOADED have a file. Documents written in Bugasura are "
        "page documents with no file of their own — read those with "
        "bugasura_list_knowledge_base_pages; there is no PDF export anywhere in Bugasura, so "
        "a page document cannot be turned into one."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def download_knowledge_base_document(
    document_identifier: str = Field(description="Document to download: its file name (e.g. 'PRD.pdf', matched exactly then partially) or its numeric id from bugasura_list_knowledge_base_documents"),
    save_to_path: Optional[str] = Field(default=None, description="Absolute path on the MCP server's local filesystem to write the file to — a directory (the document's own file name is used) or a full file path. Omit to just get the download link. Only meaningful when the server runs on the user's own machine."),
    overwrite: bool = Field(default=False, description="Set True to replace the file at save_to_path when one is already there. Leave False to have the tool refuse rather than overwrite it (default: False)."),
    folder_name: Optional[str] = Field(default=None, description="Folder to search in when the same file name exists in several folders. Omit to search the whole project."),
    folder_id: Optional[int] = Field(default=None, description="Folder identifier to search in. Use only when the user picked a specific folder from a list.", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Get a download link for an uploaded knowledge base document, and optionally save it.

    Bugasura has no download endpoint: an uploaded file's bytes live only on the CDN, and
    /v1/knowledgebase/getDocs returns its CDN-relative path as `kbFilePath`. Those objects
    are public — the web app reads them with a plain GET and hands Office documents to
    view.officeapps.live.com — so the path plus the deployment's CDN base is a working,
    unauthenticated download link. That link is the primary answer; `save_to_path` is the
    extra step for terminal use, where the server and the user share a filesystem.

    The CDN base is a separate CloudFront/S3 host that the API never returns, so it comes
    from the known-deployment map (or CDN_BASE_URL) in helpers. Without it the file cannot
    be linked or fetched, and the tool falls back to the web app document link.

    Args:
        document_identifier: File name or numeric id of the document
        save_to_path: Local directory or file path to write the file to (optional)
        overwrite: Allow replacing an existing file at save_to_path
        folder_name / folder_id: Narrow the search when names repeat across folders
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'kb_id': int,
            'doc_name': str,
            'folder_name': str,
            'type': str,                 # 'pdf', 'docx', 'md', ...
            'file_size': str,
            'download_url': str,         # direct, no login needed
            'saved_to': str | None,      # local path, when save_to_path was used
            'saved_bytes': int | None,
            'document_url': str,         # the document on the Knowledge Base page
            'message': str,
            'next_step': str
        }
        OR a selection prompt / failure envelope.

    Examples:
        # Just the link
        download_knowledge_base_document(document_identifier="PRD.pdf")

        # Save it next to the user's work as well
        download_knowledge_base_document(document_identifier="PRD.pdf",
                                         save_to_path="/home/me/specs/")
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(
        api_key, team_id, project_id, 'bugasura_download_knowledge_base_document',
        f', document_identifier="{document_identifier}"'
    )
    if context.get('status') == 'selection_required':
        return context
    if context.get('status') == 'failed':
        return context

    team_id = context['team_id']
    project_id = context['project_id']
    team_id = await _resolve_project_team_id(api_key, team_id, project_id,
                                             'download_knowledge_base_document')

    scope_folder_id = None
    if folder_id is not None or (folder_name and folder_name.strip()):
        folder = await _find_kb_folder(api_key, team_id, project_id, folder_id, folder_name)
        if folder.get('status') != 'OK':
            return _with_hint(folder, "List the folders with bugasura_list_knowledge_base_folders.")
        scope_folder_id = folder['folder_id']

    found = await _find_kb_document(api_key, team_id, project_id, document_identifier,
                                    scope_folder_id, include_connection_details=True)
    if found.get('status') != 'OK':
        return found
    document = found['document']

    doc_type = (document.get('type') or '').lower()
    file_path = (document.get('file_path') or '').strip()
    document_url = _kb_document_url(project_id, document['kb_id'])

    # No stored file: say what this document actually is and where its content lives,
    # rather than leaving the caller to guess why there is nothing to download.
    if not file_path:
        website_url = (document.get('connection_details') or {}).get('website_url', '')
        if doc_type in _KB_PAGE_DOC_TYPES:
            reason = (f"'{document['doc_name']}' is a page document written in Bugasura, not an "
                      f"uploaded file — there is nothing to download. Read its pages with "
                      f"bugasura_list_knowledge_base_pages, or open it in the web app. Bugasura "
                      f"has no PDF export, so it cannot be handed over as a PDF.")
        elif website_url:
            reason = (f"'{document['doc_name']}' is a website Bugasura scraped, not a file. The "
                      f"source page is {website_url}.")
        else:
            reason = (f"'{document['doc_name']}' has no file stored against it, so there is "
                      f"nothing to download.")

        logger.info(f"download_knowledge_base_document: kb_id={document['kb_id']} "
                    f"(type='{doc_type}') has no stored file")
        response = {
            'status': 'failed',
            'error': 'Document has no downloadable file',
            'error_type': 'NoDownloadableFile',
            'message': reason,
            'kb_id': document['kb_id'],
            'doc_name': document['doc_name'],
            'type': doc_type,
        }
        if website_url:
            response['source_url'] = website_url
        if document_url:
            response['document_url'] = document_url
            response['message'] += f" You can open it here: {document_url}"
        return response

    download_url = _kb_file_url(file_path)
    if not download_url:
        logger.error("download_knowledge_base_document: CDN base is not configured, cannot build "
                     f"a download link for kb_id={document['kb_id']}")
        response = {
            'status': 'failed',
            'error': 'Download link unavailable',
            'error_type': 'DownloadUrlUnavailable',
            'message': ("This server does not know where this Bugasura deployment stores its "
                        "files, so it cannot build a download link. Set CDN_BASE_URL in the MCP "
                        "server's .env to the deployment's CDN base URL. In the meantime the user "
                        "can download the document from the Knowledge Base page."),
            'kb_id': document['kb_id'],
            'doc_name': document['doc_name'],
            'file_path': file_path,
        }
        if document_url:
            response['document_url'] = document_url
            response['message'] += f" Open it here: {document_url}"
        return response

    response = {
        'status': 'OK',
        'kb_id': document['kb_id'],
        'doc_name': document['doc_name'],
        'folder_name': document['folder_name'],
        'type': doc_type,
        'file_size': document.get('file_size', ''),
        'download_url': download_url,
        'saved_to': None,
        'saved_bytes': None,
    }
    if document_url:
        response['document_url'] = document_url

    if save_to_path and save_to_path.strip():
        destination = os.path.expanduser(save_to_path.strip())
        # A directory means "put it here under its own name"; anything else is the file path.
        # The document's own name is the one the user knows it by; fall back to the stored
        # file name, and borrow the stored extension when the name has none.
        if os.path.isdir(destination):
            filename = os.path.basename(document['doc_name'] or '') or os.path.basename(file_path)
            if not os.path.splitext(filename)[1]:
                filename += os.path.splitext(file_path)[1]
            destination = os.path.join(destination, filename)

        parent_dir = os.path.dirname(destination) or '.'
        if not os.path.isdir(parent_dir):
            return {
                'status': 'failed',
                'error': f'Directory not found: {parent_dir}',
                'error_type': 'ValidationError',
                'message': (f"Cannot save to '{destination}' — the folder '{parent_dir}' does not "
                            f"exist. Ask the user for a folder that does, or hand them the "
                            f"download link instead: {download_url}"),
                'download_url': download_url,
                'kb_id': document['kb_id'],
                'doc_name': document['doc_name'],
            }

        if os.path.exists(destination) and not overwrite:
            logger.warning(f"download_knowledge_base_document: '{destination}' already exists; "
                           f"refusing without overwrite=True")
            return {
                'status': 'failed',
                'error': 'File already exists',
                'error_type': 'FileExists',
                'message': (f"There is already a file at '{destination}'. Tell the user, and call "
                            f"this tool again with overwrite=True to replace it or with a "
                            f"different save_to_path. The download link works either way: "
                            f"{download_url}"),
                'download_url': download_url,
                'save_to_path': destination,
                'kb_id': document['kb_id'],
                'doc_name': document['doc_name'],
            }

        logger.info(f"download_knowledge_base_document: Saving kb_id={document['kb_id']} "
                    f"('{document['doc_name']}') to '{destination}'")
        try:
            response['saved_bytes'] = await asyncio.to_thread(
                _download_url_to_path, download_url, destination)
            response['saved_to'] = destination
        except Exception as e:
            logger.error(f"download_knowledge_base_document: Download failed for "
                         f"kb_id={document['kb_id']} from '{download_url}': {e}")
            return {
                'status': 'failed',
                'error': 'Could not download the document',
                'error_type': 'IOError',
                'message': (f"The download link could not be fetched: {e}. Hand the user the link "
                            f"so they can download it in their browser: {download_url}"),
                'download_url': download_url,
                'kb_id': document['kb_id'],
                'doc_name': document['doc_name'],
            }

    if response['saved_to']:
        response['message'] = (f"Saved '{document['doc_name']}' to {response['saved_to']} "
                               f"({response['saved_bytes']} bytes). It can also be downloaded "
                               f"from {download_url}")
        response['next_step'] = ("Tell the user where the file was saved. Share download_url too "
                                 "if they would rather open it in their browser.")
    else:
        response['message'] = (f"'{document['doc_name']}' can be downloaded from {download_url} — "
                               f"the link opens the file directly, no login needed.")
        response['next_step'] = ("Give the user download_url. If they wanted the file on this "
                                 "machine instead, ask where to put it and call this tool again "
                                 "with save_to_path.")

    logger.info(f"download_knowledge_base_document: Resolved kb_id={document['kb_id']} "
                f"(saved={bool(response['saved_to'])})")
    return response


@mcp.tool(
    name="bugasura_star_knowledge_base_document",
    description=(
        "Star or unstar a document in a Bugasura project's Knowledge Base. Starring is the user's "
        "own shortlist — starred documents show up in the Knowledge Base page's Starred view and "
        "in bugasura_list_knowledge_base_documents(starred_only=True). Identify the document by its "
        "file name (e.g. 'PRD.pdf') or its id; pass starred=False to remove the star."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def star_knowledge_base_document(
    document_identifier: str = Field(description="Document to star: its file name (e.g. 'PRD.pdf', matched exactly then partially) or its numeric id from bugasura_list_knowledge_base_documents"),
    starred: bool = Field(default=True, description="True to star the document, False to remove the star (default: True)"),
    folder_name: Optional[str] = Field(default=None, description="Folder to search in when the same file name exists in several folders. Omit to search the whole project."),
    folder_id: Optional[int] = Field(default=None, description="Folder identifier to search in. Use only when the user picked a specific folder from a list.", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Star or unstar a knowledge base document.

    Posts to /v1/knowledgebase/update with only `isStarred` set, which the API treats as
    a star-only update: the document's content and its last-modified date are untouched.

    Args:
        document_identifier: File name or numeric id of the document
        starred: True to star, False to unstar
        folder_name / folder_id: Narrow the search when names repeat across folders
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'kb_id': int,
            'doc_name': str,
            'folder_name': str,
            'is_starred': bool,
            'knowledge_base_url': str,
            'message': str
        }
        OR a selection prompt / failure envelope.

    Examples:
        # Star a document by name
        star_knowledge_base_document(document_identifier="PRD.pdf")

        # Unstar it again
        star_knowledge_base_document(document_identifier="PRD.pdf", starred=False)
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(
        api_key, team_id, project_id, 'bugasura_star_knowledge_base_document',
        f', document_identifier="{document_identifier}"'
    )
    if context.get('status') == 'selection_required':
        return context
    if context.get('status') == 'failed':
        return context

    team_id = context['team_id']
    project_id = context['project_id']
    team_id = await _resolve_project_team_id(api_key, team_id, project_id,
                                             'star_knowledge_base_document')

    scope_folder_id = None
    if folder_id is not None or (folder_name and folder_name.strip()):
        folder = await _find_kb_folder(api_key, team_id, project_id, folder_id, folder_name)
        if folder.get('status') != 'OK':
            return _with_hint(folder, "List the folders with bugasura_list_knowledge_base_folders.")
        scope_folder_id = folder['folder_id']

    found = await _find_kb_document(api_key, team_id, project_id, document_identifier, scope_folder_id)
    if found.get('status') != 'OK':
        return found
    document = found['document']

    logger.info(f"star_knowledge_base_document: Setting is_starred={int(starred)} on "
                f"kb_id={document['kb_id']} in project_id={project_id}")

    response = await make_api_request('POST', '/v1/knowledgebase/update', api_key, data={
        'appId': str(project_id),
        'teamId': str(team_id),
        'kbId': str(document['kb_id']),
        'isStarred': '1' if starred else '0',
    })

    if response.get('status') != 'OK':
        logger.error(f"star_knowledge_base_document: Update failed for kb_id={document['kb_id']}: "
                     f"{response.get('message')}")
        return response

    # Drop the raw document row the API echoes back (is_starred '0'/'1', connection_details, paths).
    response.pop('knowledgeBaseDetails', None)

    response['kb_id'] = document['kb_id']
    response['doc_name'] = document['doc_name']
    response['folder_name'] = document['folder_name']
    response['is_starred'] = starred
    response['message'] = (f"Starred '{document['doc_name']}'." if starred
                           else f"Removed the star from '{document['doc_name']}'.")
    response['next_step'] = ("Just confirm the document is starred (or no longer starred) in words — "
                             "don't show the ids or the is_starred flag.")

    if WEB_BASE_URL:
        response['knowledge_base_url'] = f"{WEB_BASE_URL}knowledgeBase/{project_id}"

    return response


@mcp.tool(
    name="bugasura_delete_knowledge_base_document",
    description=(
        "Delete a document from a Bugasura project's Knowledge Base, permanently. Identify the "
        "document by its file name (e.g. 'PRD.pdf') or its id. The file and everything the AI "
        "learned from it are removed, so confirm with the user which document they mean — "
        "bugasura_list_knowledge_base_documents shows the exact names — before calling this. "
        "Requires team or project admin rights."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": True}
)
async def delete_knowledge_base_document(
    document_identifier: str = Field(description="Document to delete: its file name (e.g. 'PRD.pdf', matched exactly then partially) or its numeric id from bugasura_list_knowledge_base_documents"),
    folder_name: Optional[str] = Field(default=None, description="Folder to search in when the same file name exists in several folders. Omit to search the whole project."),
    folder_id: Optional[int] = Field(default=None, description="Folder identifier to search in. Use only when the user picked a specific folder from a list.", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Delete a document from a project's knowledge base.

    Posts to /v1/knowledgebase/delete. The API removes the row, the stored file and the
    AI vector-store copy, so this cannot be undone. Only team admins and project admins
    may delete, and the API refuses while a TestPert training run is using the knowledge
    base — both come back as the upstream error message.

    Args:
        document_identifier: File name or numeric id of the document
        folder_name / folder_id: Narrow the search when names repeat across folders
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'kb_id': int,
            'doc_name': str,
            'folder_name': str,
            'message': str
        }
        OR a selection prompt / failure envelope.

    Examples:
        # Delete by file name
        delete_knowledge_base_document(document_identifier="old-spec.pdf")

        # Delete by id, scoped to one folder
        delete_knowledge_base_document(document_identifier="3772", folder_name="Product Specs")
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(
        api_key, team_id, project_id, 'bugasura_delete_knowledge_base_document',
        f', document_identifier="{document_identifier}"'
    )
    if context.get('status') == 'selection_required':
        return context
    if context.get('status') == 'failed':
        return context

    team_id = context['team_id']
    project_id = context['project_id']
    team_id = await _resolve_project_team_id(api_key, team_id, project_id,
                                             'delete_knowledge_base_document')

    scope_folder_id = None
    if folder_id is not None or (folder_name and folder_name.strip()):
        folder = await _find_kb_folder(api_key, team_id, project_id, folder_id, folder_name)
        if folder.get('status') != 'OK':
            return _with_hint(folder, "List the folders with bugasura_list_knowledge_base_folders.")
        scope_folder_id = folder['folder_id']

    found = await _find_kb_document(api_key, team_id, project_id, document_identifier, scope_folder_id)
    if found.get('status') != 'OK':
        return found
    document = found['document']

    logger.info(f"delete_knowledge_base_document: Deleting kb_id={document['kb_id']} "
                f"('{document['doc_name']}') from project_id={project_id}")

    response = await make_api_request('POST', '/v1/knowledgebase/delete', api_key, data={
        'appId': str(project_id),
        'teamId': str(team_id),
        'kbId': str(document['kb_id']),
    })

    if response.get('status') != 'OK':
        logger.error(f"delete_knowledge_base_document: Delete failed for kb_id={document['kb_id']}: "
                     f"{response.get('message')}")
        return response

    response['kb_id'] = document['kb_id']
    response['doc_name'] = document['doc_name']
    response['folder_name'] = document['folder_name']
    response['message'] = (f"Deleted '{document['doc_name']}' from the "
                           f"'{document['folder_name']}' folder in the knowledge base.")

    logger.info(f"delete_knowledge_base_document: Deleted kb_id={document['kb_id']}")
    return response


@mcp.tool(
    name="bugasura_delete_knowledge_base_folder",
    description=(
        "Delete a folder from a Bugasura project's Knowledge Base. The folder and its sub-folders "
        "are removed from the knowledge base tree, and the documents inside them stop being "
        "listed — the API trashes the folder rather than erasing it, so it can be restored. A "
        "folder that still holds documents is NOT deleted unless delete_documents=True — tell "
        "the user how many documents are inside and get their confirmation first. Requires team "
        "or project admin rights."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": True}
)
async def delete_knowledge_base_folder(
    folder_name: Optional[str] = Field(default=None, description="Knowledge base folder to delete. Matched case-insensitively anywhere in the folder tree."),
    folder_id: Optional[int] = Field(default=None, description="Knowledge base folder identifier. Use only when the user picked a specific folder from a list — folder_name is the normal way to target a folder.", ge=1),
    delete_documents: bool = Field(default=False, description="Set True to delete a folder that still holds documents — the documents stop being listed with it. Leave False to have the tool refuse and report what is inside (default: False)."),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Delete a knowledge base folder.

    Posts to /v1/projectFolders/delete with `folderType=KNOWLEDGE_BASE`, mirroring the web
    app's folder delete: the folder is removed from the knowledge base tree along with its
    sub-folders, and any documents inside it stop being listed.

    This is a soft delete. The API only hard-deletes when `isPermanentDelete=1` is posted,
    which this tool does not send: the folder row is flagged `is_deleted=1` and renamed to
    "<name>-deleted-on-<timestamp>", its sub-folders are unlinked from the tree, and the
    documents keep their rows, S3 files and vector-store entries. `isDeleteResults` only
    takes effect on the permanent path, so it is inert here. A folder deleted by mistake
    can be restored from the project's trash.

    The document count is checked here first, so a folder with documents is only deleted
    when the caller explicitly passes delete_documents=True. That count comes from getDocs
    over the folder *and its sub-folders*, so it covers everything that would be unlisted.

    Args:
        folder_name / folder_id: Folder to delete (one of them is required)
        delete_documents: Allow deleting a folder that still holds documents
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'folder_id': int,
            'folder_name': str,
            'unlisted_document_count': int,
            'message': str
        }
        OR a selection prompt / failure envelope.

    Examples:
        # Delete an empty folder
        delete_knowledge_base_folder(folder_name="Old Specs")

        # Delete a folder together with the documents inside it
        delete_knowledge_base_folder(folder_name="Old Specs", delete_documents=True)
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(
        api_key, team_id, project_id, 'bugasura_delete_knowledge_base_folder',
        f', folder_name="{folder_name}"' if folder_name else ''
    )
    if context.get('status') == 'selection_required':
        return context
    if context.get('status') == 'failed':
        return context

    team_id = context['team_id']
    project_id = context['project_id']
    team_id = await _resolve_project_team_id(api_key, team_id, project_id,
                                             'delete_knowledge_base_folder')

    folder = await _find_kb_folder(api_key, team_id, project_id, folder_id, folder_name)
    if folder.get('status') != 'OK':
        return _with_hint(folder, "List the folders with bugasura_list_knowledge_base_folders.")

    # Count what would go with the folder — getDocs covers the folder and its sub-folders.
    documents_response = await _fetch_kb_documents(api_key, team_id, project_id, folder['folder_id'])
    if documents_response.get('status') != 'OK':
        return documents_response
    documents = documents_response['documents']

    if documents and not delete_documents:
        logger.warning(f"delete_knowledge_base_folder: Folder {folder['folder_id']} holds "
                       f"{len(documents)} document(s); refusing without delete_documents=True")
        return {
            'status': 'failed',
            'error': 'Knowledge base folder is not empty',
            'error_type': 'FolderNotEmpty',
            'message': (f"The folder '{folder['folder_name']}' and its sub-folders hold "
                        f"{len(documents)} document(s). Tell the user which documents would stop "
                        f"being listed with it and, once they confirm, call this tool again with "
                        f"delete_documents=True. To keep the documents listed, move them out "
                        f"first or leave the folder in place."),
            'folder_id': folder['folder_id'],
            'folder_name': folder['folder_name'],
            'document_count': len(documents),
            'documents': _document_choices(documents)
        }

    logger.info(f"delete_knowledge_base_folder: Deleting folder_id={folder['folder_id']} "
                f"('{folder['folder_name']}') with {len(documents)} document(s) from "
                f"project_id={project_id}")

    response = await make_api_request('POST', '/v1/projectFolders/delete', api_key, data={
        'appId': str(project_id),
        'teamId': str(team_id),
        'folderId': str(folder['folder_id']),
        'folderType': _KB_FOLDER_TYPE,
        'isDeleteResults': 1 if delete_documents else 0,
    })

    if response.get('status') != 'OK':
        logger.error(f"delete_knowledge_base_folder: Delete failed for "
                     f"folder_id={folder['folder_id']}: {response.get('message')}")
        return response

    response['folder_id'] = folder['folder_id']
    response['folder_name'] = folder['folder_name']
    response['unlisted_document_count'] = len(documents)
    # The API soft-deletes: the folder is flagged and renamed rather than removed, and its
    # documents are only unlisted, not purged. Say so instead of promising a hard delete.
    response['message'] = (f"Deleted the knowledge base folder '{folder['folder_name']}'. It is "
                           f"moved to trash rather than erased.")
    if documents:
        response['message'] += (f" The {len(documents)} document(s) it held go with it and are no "
                                f"longer listed in the knowledge base.")
    response['message'] += " If this was a mistake, the folder can be restored from the trash."

    if WEB_BASE_URL:
        response['knowledge_base_url'] = f"{WEB_BASE_URL}knowledgeBase/{project_id}"

    logger.info(f"delete_knowledge_base_folder: Deleted folder_id={folder['folder_id']}")
    return response

@mcp.tool(
    name="bugasura_create_knowledge_base_document",
    description=(
        "Create a page document in a Bugasura project's Knowledge Base — the web app's "
        "'Create Document' flow. Unlike an uploaded file, a page document is written in "
        "Bugasura: its body is a tree of pages the user can add to, rename and reorder. "
        "The document starts with one empty page; add more with "
        "bugasura_create_knowledge_base_page and write their markdown with "
        "bugasura_update_knowledge_base_page_content. "
        "Folders work as they do for uploads: pass folder_name to file the document there — "
        "it is created when the project has no folder by that name — or omit it to use the "
        "project's first knowledge base folder. "
        "To add an existing file (.pdf/.docx/.md/...) instead, use "
        "bugasura_upload_knowledge_base_document."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def create_knowledge_base_document(
    doc_name: str = Field(description="Name for the new document, e.g. 'Onboarding Spec'. Trimmed to 250 characters; '<' and '>' are stripped upstream."),
    first_page_name: Optional[str] = Field(default=None, description="Name of the page the document starts with. Defaults to 'Untitled Page'."),
    folder_name: Optional[str] = Field(default=None, description="Knowledge base folder to create the document in. Matched case-insensitively; created at root level when no folder has that name. Omit to use the project's first knowledge base folder."),
    folder_id: Optional[int] = Field(default=None, description="Knowledge base folder identifier. Use only when the user picked a specific folder from a list — folder_name is the normal way to target a folder.", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Create an empty page document in a project's knowledge base.

    Posts to /v1/knowledgebase/add with `kbType=custom_doc` and a `customFileDetails`
    payload of `{doc_name, page_name}`, mirroring the web app's "Create Document" action.
    The API creates the row with a single empty page and marks it PROCESSED straight away —
    a page document has nothing to download or scrape. Page bodies are written afterwards,
    through the update endpoint.

    Args:
        doc_name: Name for the document (required)
        first_page_name: Name of the initial page (defaults to 'Untitled Page')
        folder_name: Folder to create the document in (created when it does not exist)
        folder_id: Explicit folder identifier (takes precedence over folder_name)
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'kb_id': int,
            'doc_name': str,
            'folder_id': int,
            'folder_name': str,
            'folder_created': bool,
            'first_page_id': str,
            'first_page_name': str,
            'document_url': str,     # web app link that opens the document
            'message': str,
            'next_step': str
        }
        OR a selection prompt / failure envelope.

    Examples:
        # In a named folder (created if it does not exist)
        create_knowledge_base_document(doc_name="Onboarding Spec", folder_name="Product Specs")

        # With a named first page
        create_knowledge_base_document(doc_name="API Guide", first_page_name="Overview")
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(
        api_key, team_id, project_id, 'bugasura_create_knowledge_base_document',
        f', doc_name="{doc_name}"'
    )
    if context.get('status') == 'selection_required':
        return context
    if context.get('status') == 'failed':
        return context

    team_id = context['team_id']
    project_id = context['project_id']

    if not doc_name or not doc_name.strip():
        return {
            'status': 'failed',
            'error': 'Document name is required',
            'error_type': 'ValidationError',
            'message': 'Ask the user what the document should be called, then pass it as doc_name.'
        }
    doc_name = doc_name.strip()
    page_name = (first_page_name or '').strip() or _KB_DEFAULT_PAGE_NAME

    team_id = await _resolve_project_team_id(api_key, team_id, project_id,
                                             'create_knowledge_base_document')

    # folderId is required upstream, so resolve (or create) the folder before the document.
    folder = await _resolve_kb_folder(api_key, team_id, project_id, folder_id, folder_name)
    if folder.get('status') != 'OK':
        return folder

    logger.info(f"create_knowledge_base_document: Creating '{doc_name}' in "
                f"folder_id={folder['folder_id']} ('{folder['folder_name']}'), project_id={project_id}")

    response = await make_api_request('POST', '/v1/knowledgebase/add', api_key, data={
        'appId': str(project_id),
        'teamId': str(team_id),
        'folderId': str(folder['folder_id']),
        'kbType': _KB_CUSTOM_DOC_TYPE,
        'customFileDetails': json.dumps({'doc_name': doc_name, 'page_name': page_name}),
    })

    if response.get('status') != 'OK':
        logger.error(f"create_knowledge_base_document: Create failed for '{doc_name}': "
                     f"{response.get('message')}")
        return response

    doc_details = response.get('kbDocDetails') or {}
    connection_details = doc_details.get('connection_details') or {}
    pages = connection_details.get('pageDetails') or []
    first_page = pages[0] if pages else {}

    # kbDocDetails carries the created row; kbIds is the generic fallback every add returns.
    response['kb_id'] = doc_details.get('kb_id') or next(iter(response.get('kbIds') or []), None)
    response['doc_name'] = connection_details.get('doc_name', doc_name)
    response['folder_id'] = folder['folder_id']
    response['folder_name'] = folder['folder_name']
    response['folder_created'] = folder.get('created', False)
    response['first_page_id'] = first_page.get('page_id', '')
    response['first_page_name'] = first_page.get('page_name', page_name)

    folder_phrase = (f"a new folder '{folder['folder_name']}'" if folder.get('created')
                     else f"the '{folder['folder_name']}' folder")
    response['message'] = (f"Created the document '{response['doc_name']}' in {folder_phrase}, "
                           f"with one page called '{response['first_page_name']}'.")

    document_url = _kb_document_url(project_id, response['kb_id']) if response['kb_id'] else None
    if document_url:
        response['document_url'] = document_url
        response['message'] += f" You can open it here: {document_url}"

    response['next_step'] = (
        "The document is empty. Write the first page's body with "
        "bugasura_update_knowledge_base_page_content, and add more pages with "
        "bugasura_create_knowledge_base_page. Ask the user what should go in it."
    )

    logger.info(f"create_knowledge_base_document: Created kb_id={response['kb_id']}")
    return response


@mcp.tool(
    name="bugasura_rename_knowledge_base_document",
    description=(
        "Rename a page document in a Bugasura project's Knowledge Base. Works on documents "
        "created with bugasura_create_knowledge_base_document and on documents synced from "
        "Coda, Jira, Confluence or a URL — an uploaded file keeps its file name and cannot "
        "be renamed. Identify the document by its current name or its id. "
        "Documents created without a name are called 'Untitled Doc' and are worth renaming."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def rename_knowledge_base_document(
    document_identifier: str = Field(description="Document to rename: its current name (matched exactly then partially) or its numeric id from bugasura_list_knowledge_base_documents"),
    new_name: str = Field(description="New name for the document. Trimmed to 250 characters; '<' and '>' are stripped upstream."),
    folder_name: Optional[str] = Field(default=None, description="Folder to search in when the same document name exists in several folders. Omit to search the whole project."),
    folder_id: Optional[int] = Field(default=None, description="Folder identifier to search in. Use only when the user picked a specific folder from a list.", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Rename a knowledge base page document.

    Posts the `edit_doc_name` action to /v1/knowledgebase/update. The name is stored in the
    document's `connection_details.doc_name`, which is what the Knowledge Base page and
    bugasura_list_knowledge_base_documents show for a page document.

    Args:
        document_identifier: Name or numeric id of the document
        new_name: New document name (required)
        folder_name / folder_id: Narrow the search when names repeat across folders
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'kb_id': int,
            'doc_name': str,             # the new name
            'previous_doc_name': str,
            'folder_name': str,
            'document_url': str,
            'message': str
        }
        OR a selection prompt / failure envelope.

    Examples:
        # Give a freshly created document a real name
        rename_knowledge_base_document(document_identifier="Untitled Doc", new_name="Onboarding Spec")
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(
        api_key, team_id, project_id, 'bugasura_rename_knowledge_base_document',
        f', document_identifier="{document_identifier}", new_name="{new_name}"'
    )
    if context.get('status') == 'selection_required':
        return context
    if context.get('status') == 'failed':
        return context

    team_id = context['team_id']
    project_id = context['project_id']

    if not new_name or not new_name.strip():
        return {
            'status': 'failed',
            'error': 'New document name is required',
            'error_type': 'ValidationError',
            'message': 'Ask the user what the document should be called, then pass it as new_name.'
        }
    new_name = new_name.strip()

    team_id = await _resolve_project_team_id(api_key, team_id, project_id,
                                             'rename_knowledge_base_document')

    doc = await _resolve_page_document(api_key, team_id, project_id, document_identifier,
                                       folder_id, folder_name)
    if doc.get('status') != 'OK':
        return doc
    document = doc['document']

    logger.info(f"rename_knowledge_base_document: Renaming kb_id={document['kb_id']} "
                f"('{doc['doc_name']}') to '{new_name}' in project_id={project_id}")

    response = await _kb_doc_page_action(api_key, team_id, project_id, document['kb_id'],
                                         doc['doc_type'], 'edit_doc_name', doc_name=new_name)

    if response.get('status') != 'OK':
        logger.error(f"rename_knowledge_base_document: Rename failed for kb_id={document['kb_id']}: "
                     f"{response.get('message')}")
        return response

    # Report the stored name — the API sanitises it, so it can differ from new_name and a
    # later name-based lookup would otherwise miss.
    stored_name = _doc_name_from_update_response(response, document['kb_id']) or new_name
    response['kb_id'] = document['kb_id']
    response['doc_name'] = stored_name
    response['previous_doc_name'] = doc['doc_name']
    response['folder_name'] = document['folder_name']
    response['message'] = f"Renamed the document '{doc['doc_name']}' to '{stored_name}'."

    document_url = _kb_document_url(project_id, document['kb_id'])
    if document_url:
        response['document_url'] = document_url

    return response


@mcp.tool(
    name="bugasura_list_knowledge_base_pages",
    description=(
        "List the pages of a Bugasura Knowledge Base page document. Use this to show the "
        "user a document's structure and to get the page id needed to rename, move, "
        "duplicate or delete a page. Pages come back in their stored order with "
        "`parent_page_id`, `page_path` and `depth` describing how they nest, and "
        "`has_content` telling you which pages have a body written. "
        "This returns the structure only — read a page's markdown with "
        "bugasura_get_knowledge_base_page_content."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def list_knowledge_base_pages(
    document_identifier: str = Field(description="Document whose pages to list: its name (matched exactly then partially) or its numeric id from bugasura_list_knowledge_base_documents"),
    folder_name: Optional[str] = Field(default=None, description="Folder to search in when the same document name exists in several folders. Omit to search the whole project."),
    folder_id: Optional[int] = Field(default=None, description="Folder identifier to search in. Use only when the user picked a specific folder from a list.", ge=1),
    start_at: int = Field(default=0, description="Pagination offset (default: 0)", ge=0),
    max_results: int = Field(default=50, description="Number of pages to return (default: 50)", ge=1, le=100),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    List the pages of a knowledge base page document.

    The pages are read from the document's `connection_details.pageDetails`, which
    /v1/knowledgebase/getDocs already returns decoded — no extra call is needed. The stored
    list is flat and in display order; `parent_page_id` is what makes it a tree.

    Args:
        document_identifier: Name or numeric id of the document
        folder_name / folder_id: Narrow the search when names repeat across folders
        start_at / max_results: Pagination window
        team_id / project_id: Resolved interactively if omitted
        response_format: 'json' or 'markdown'
        api_key: User's Bugasura API key

    Returns:
        dict: Standard pagination envelope whose items are
        {'page_id', 'page_name', 'parent_page_id', 'parent_page_name', 'page_path',
        'depth', 'has_content', 'created_on', 'modified_on'}, plus 'pages', 'kb_id',
        'doc_name', 'document_url' and 'message'.
        OR a selection prompt / failure envelope.

    Examples:
        # Every page of a document
        list_knowledge_base_pages(document_identifier="Onboarding Spec")

        # By document id, scoped to one folder
        list_knowledge_base_pages(document_identifier="3772", folder_name="Product Specs")
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return _respond(validation, response_format)

    context = await select_team_project_context(
        api_key, team_id, project_id, 'bugasura_list_knowledge_base_pages',
        f', document_identifier="{document_identifier}"'
    )
    if context.get('status') == 'selection_required':
        return _respond(context, response_format)
    if context.get('status') == 'failed':
        return _respond(context, response_format)

    team_id = context['team_id']
    project_id = context['project_id']
    team_id = await _resolve_project_team_id(api_key, team_id, project_id,
                                             'list_knowledge_base_pages')

    doc = await _resolve_page_document(api_key, team_id, project_id, document_identifier,
                                       folder_id, folder_name)
    if doc.get('status') != 'OK':
        return _respond(doc, response_format)

    document = doc['document']
    pages = _normalise_kb_pages(doc['pages'])
    page = pages[start_at:start_at + max_results]

    message = f"{len(pages)} page(s) in the document '{doc['doc_name']}'."
    if not pages:
        message = (f"The document '{doc['doc_name']}' has no pages. Add one with "
                   f"bugasura_create_knowledge_base_page.")
    # A doc still carrying the API's fallback name was created without one being given.
    if doc['doc_name'] == _KB_DEFAULT_DOC_NAME:
        message += (" This document has never been named — offer to rename it with "
                    "bugasura_rename_knowledge_base_document.")

    extras = {
        'pages': page,
        'kb_id': document['kb_id'],
        'doc_name': doc['doc_name'],
        'doc_type': doc['doc_type'],
        'folder_name': document['folder_name'],
        'project_id': project_id,
        'team_id': team_id,
        'message': message,
    }
    document_url = _kb_document_url(project_id, document['kb_id'])
    if document_url:
        extras['document_url'] = document_url

    logger.info(f"list_knowledge_base_pages: Returning {len(page)} of {len(pages)} page(s) for "
                f"kb_id={document['kb_id']}")
    return _respond(_paginated(page, total=len(pages), offset=start_at, **extras), response_format)


@mcp.tool(
    name="bugasura_create_knowledge_base_page",
    description=(
        "Add a page to a Bugasura Knowledge Base page document. By default the page is added "
        "at the end of the document, at root level. Pass parent_page to nest it under an "
        "existing page, or after_page to place it directly after one as a sibling — not both. "
        "Pass content to write the page's markdown body in the same call; leave it out to "
        "create an empty page and fill it in later with "
        "bugasura_update_knowledge_base_page_content. "
        "Identify the document by name or id, and the parent/sibling page by page name or "
        "page id from bugasura_list_knowledge_base_pages."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def create_knowledge_base_page(
    document_identifier: str = Field(description="Document to add the page to: its name (matched exactly then partially) or its numeric id from bugasura_list_knowledge_base_documents"),
    page_name: Optional[str] = Field(default=None, description="Name for the new page. Defaults to 'Untitled Page'. Trimmed to 250 characters; '<' and '>' are stripped upstream."),
    content: Optional[str] = Field(default=None, description="Markdown body for the new page. Omit to create an empty page. Written in a second step, so the page still exists if the body fails to save."),
    parent_page: Optional[str] = Field(default=None, description="Existing page to nest the new page under, by page name or page id. Omit for a root-level page. Cannot be combined with after_page."),
    after_page: Optional[str] = Field(default=None, description="Existing page to place the new page right after, as its sibling, by page name or page id. Cannot be combined with parent_page."),
    folder_name: Optional[str] = Field(default=None, description="Folder to search in when the same document name exists in several folders. Omit to search the whole project."),
    folder_id: Optional[int] = Field(default=None, description="Folder identifier to search in. Use only when the user picked a specific folder from a list.", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Add a page to a knowledge base page document.

    Posts one of the `add_page` / `add_subpage` / `add_sibling_page` actions to
    /v1/knowledgebase/update, picked from whether the caller gave a parent or a sibling.
    The API generates the page id and hands the new page back in `pageDetails`.

    `content` is applied as a follow-up `edit_page_content` action, because the add actions
    ignore a body — the same two-step the web app's editor does. A failure there leaves the
    page in place and comes back as `content_saved: False`, so retrying means writing the
    content, not creating the page again.

    Args:
        document_identifier: Name or numeric id of the document
        page_name: Name for the new page (defaults to 'Untitled Page')
        content: Markdown body to write into the new page
        parent_page: Page to nest under (add_subpage)
        after_page: Page to place the new page after (add_sibling_page)
        folder_name / folder_id: Narrow the search when names repeat across folders
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'kb_id': int,
            'doc_name': str,
            'page_id': str,
            'page_name': str,
            'page_path': str,
            'parent_page_id': str,
            'parent_page_name': str,
            'content_saved': bool,       # False when the body could not be written
            'document_url': str,
            'message': str
        }
        OR a selection prompt / failure envelope.

    Examples:
        # A root-level page at the end of the document
        create_knowledge_base_page(document_identifier="Onboarding Spec", page_name="Rollout")

        # A sub page with its body written in the same call
        create_knowledge_base_page(document_identifier="Onboarding Spec", page_name="Step 1",
                                   parent_page="Rollout", content="# Step 1\\n\\nInvite the user.")
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(
        api_key, team_id, project_id, 'bugasura_create_knowledge_base_page',
        f', document_identifier="{document_identifier}"'
    )
    if context.get('status') == 'selection_required':
        return context
    if context.get('status') == 'failed':
        return context

    team_id = context['team_id']
    project_id = context['project_id']

    if (parent_page and parent_page.strip()) and (after_page and after_page.strip()):
        return {
            'status': 'failed',
            'error': 'Both parent_page and after_page provided',
            'error_type': 'ValidationError',
            'message': ('A page is either nested under a parent or placed after a sibling, not both. '
                        'Pass parent_page to nest it, after_page to place it, or neither for a '
                        'root-level page at the end of the document.')
        }

    page_name = (page_name or '').strip() or _KB_DEFAULT_PAGE_NAME

    team_id = await _resolve_project_team_id(api_key, team_id, project_id,
                                             'create_knowledge_base_page')

    doc = await _resolve_page_document(api_key, team_id, project_id, document_identifier,
                                       folder_id, folder_name)
    if doc.get('status') != 'OK':
        return doc
    document = doc['document']

    # Pick the action from where the caller wants the page: under a parent, after a
    # sibling, or — with neither given — at the end of the document at root level.
    action = 'add_page'
    anchor_page_id: Any = False
    if parent_page and parent_page.strip():
        found = _find_kb_page(doc['pages'], parent_page, role='parent page')
        if found.get('status') != 'OK':
            return found
        action = 'add_subpage'
        anchor_page_id = found['page'].get('page_id')
    elif after_page and after_page.strip():
        found = _find_kb_page(doc['pages'], after_page, role='sibling page')
        if found.get('status') != 'OK':
            return found
        action = 'add_sibling_page'
        anchor_page_id = found['page'].get('page_id')

    logger.info(f"create_knowledge_base_page: Adding '{page_name}' to kb_id={document['kb_id']} "
                f"with action='{action}', anchor_page_id={anchor_page_id}")

    response = await _kb_doc_page_action(
        api_key, team_id, project_id, document['kb_id'], doc['doc_type'], action,
        page_details=[{'page_id': anchor_page_id, 'page_name': page_name, 'page_content': False}]
    )

    if response.get('status') != 'OK':
        logger.error(f"create_knowledge_base_page: Add failed for kb_id={document['kb_id']}: "
                     f"{response.get('message')}")
        return response

    new_page = response.get('pageDetails') or {}
    page_id = new_page.get('page_id', '')
    pages = _pages_from_update_response(response, document['kb_id']) or doc['pages']
    pages_by_id = {str(p.get('page_id')): p for p in pages}
    normalised = _normalise_kb_page(pages_by_id.get(str(page_id), new_page), pages_by_id)

    # The add actions ignore a body, so the content is a second action on the new page.
    content_saved = None
    content_error = ''
    if content is not None and content.strip() != '' and page_id:
        content_response = await _kb_doc_page_action(
            api_key, team_id, project_id, document['kb_id'], doc['doc_type'], 'edit_page_content',
            page_details=[{'page_id': page_id, 'page_name': False, 'page_content': content}]
        )
        content_saved = content_response.get('status') == 'OK'
        if not content_saved:
            content_error = content_response.get('message', 'Unknown error')
            logger.error(f"create_knowledge_base_page: Content write failed for page_id={page_id} "
                         f"on kb_id={document['kb_id']}: {content_error}")

    response['kb_id'] = document['kb_id']
    response['doc_name'] = doc['doc_name']
    response['page_id'] = page_id
    response['page_name'] = normalised['page_name']
    response['page_path'] = normalised['page_path']
    response['parent_page_id'] = normalised['parent_page_id']
    response['parent_page_name'] = normalised['parent_page_name']
    response['content_saved'] = bool(content_saved)

    where = (f"under '{normalised['parent_page_name']}'" if normalised['parent_page_name']
             else "at root level")
    response['message'] = (f"Added the page '{normalised['page_name']}' {where} in "
                           f"'{doc['doc_name']}'.")
    if content_saved:
        response['message'] += " Its content has been saved."
    elif content_saved is False:
        response['message'] += (f" The page's content could NOT be saved: {content_error} "
                                f"The page itself exists — write its body with "
                                f"bugasura_update_knowledge_base_page_content rather than "
                                f"adding the page again.")

    document_url = _kb_document_url(project_id, document['kb_id'])
    if document_url:
        response['document_url'] = document_url

    logger.info(f"create_knowledge_base_page: Added page_id={page_id} to kb_id={document['kb_id']}")
    return response


@mcp.tool(
    name="bugasura_rename_knowledge_base_page",
    description=(
        "Rename a page in a Bugasura Knowledge Base page document. Identify the document by "
        "name or id, and the page by its current page name or its page id from "
        "bugasura_list_knowledge_base_pages. This changes the page's title only — its "
        "content, its position and its sub pages are untouched."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def rename_knowledge_base_page(
    document_identifier: str = Field(description="Document holding the page: its name (matched exactly then partially) or its numeric id from bugasura_list_knowledge_base_documents"),
    page_identifier: str = Field(description="Page to rename: its current page name (matched exactly then partially) or its page id (e.g. 'page_20250104120500')"),
    new_name: str = Field(description="New name for the page. Trimmed to 250 characters; '<' and '>' are stripped upstream."),
    folder_name: Optional[str] = Field(default=None, description="Folder to search in when the same document name exists in several folders. Omit to search the whole project."),
    folder_id: Optional[int] = Field(default=None, description="Folder identifier to search in. Use only when the user picked a specific folder from a list.", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Rename a page of a knowledge base page document.

    Posts the `edit_page_name` action to /v1/knowledgebase/update, which updates the page's
    name in `connection_details.pageDetails` and stamps the modified-by details.

    Args:
        document_identifier: Name or numeric id of the document
        page_identifier: Page name or page id of the page to rename
        new_name: New page name (required)
        folder_name / folder_id: Narrow the search when names repeat across folders
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'kb_id': int,
            'doc_name': str,
            'page_id': str,
            'page_name': str,            # the new name
            'previous_page_name': str,
            'page_path': str,
            'document_url': str,
            'message': str
        }
        OR a selection prompt / failure envelope.

    Examples:
        # Rename by page name
        rename_knowledge_base_page(document_identifier="Onboarding Spec",
                                   page_identifier="Untitled Page", new_name="Overview")
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(
        api_key, team_id, project_id, 'bugasura_rename_knowledge_base_page',
        f', document_identifier="{document_identifier}", page_identifier="{page_identifier}"'
    )
    if context.get('status') == 'selection_required':
        return context
    if context.get('status') == 'failed':
        return context

    team_id = context['team_id']
    project_id = context['project_id']

    if not new_name or not new_name.strip():
        return {
            'status': 'failed',
            'error': 'New page name is required',
            'error_type': 'ValidationError',
            'message': 'Ask the user what the page should be called, then pass it as new_name.'
        }
    new_name = new_name.strip()

    team_id = await _resolve_project_team_id(api_key, team_id, project_id,
                                             'rename_knowledge_base_page')

    doc = await _resolve_page_document(api_key, team_id, project_id, document_identifier,
                                       folder_id, folder_name)
    if doc.get('status') != 'OK':
        return doc
    document = doc['document']

    found = _find_kb_page(doc['pages'], page_identifier)
    if found.get('status') != 'OK':
        return found
    page = found['page']

    logger.info(f"rename_knowledge_base_page: Renaming page_id={page.get('page_id')} "
                f"('{page.get('page_name')}') to '{new_name}' on kb_id={document['kb_id']}")

    response = await _kb_doc_page_action(
        api_key, team_id, project_id, document['kb_id'], doc['doc_type'], 'edit_page_name',
        page_details=[{'page_id': page.get('page_id'), 'page_name': new_name, 'page_content': False}]
    )

    if response.get('status') != 'OK':
        logger.error(f"rename_knowledge_base_page: Rename failed for page_id={page.get('page_id')}: "
                     f"{response.get('message')}")
        return response

    pages = _pages_from_update_response(response, document['kb_id']) or doc['pages']
    pages_by_id = {str(p.get('page_id')): p for p in pages}
    normalised = _normalise_kb_page(pages_by_id.get(str(page.get('page_id')), page), pages_by_id)

    response['kb_id'] = document['kb_id']
    response['doc_name'] = doc['doc_name']
    response['page_id'] = page.get('page_id')
    response['page_name'] = new_name
    response['previous_page_name'] = page.get('page_name', '')
    response['page_path'] = normalised['page_path']
    response['message'] = (f"Renamed the page '{page.get('page_name')}' to '{new_name}' in "
                           f"'{doc['doc_name']}'.")

    document_url = _kb_document_url(project_id, document['kb_id'])
    if document_url:
        response['document_url'] = document_url

    return response


@mcp.tool(
    name="bugasura_get_knowledge_base_page_content",
    description=(
        "Read the current markdown body of a page in a Bugasura Knowledge Base page document. "
        "ALWAYS call this before changing a page the user wants edited rather than rewritten "
        "— bugasura_update_knowledge_base_page_content replaces the whole body, so you need "
        "the existing text in front of you to change part of it without losing the rest. "
        "A page that has never been written comes back with empty content, which is normal. "
        "Identify the document by name or id, and the page by page name or page id from "
        "bugasura_list_knowledge_base_pages."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def get_knowledge_base_page_content(
    document_identifier: str = Field(description="Document holding the page: its name (matched exactly then partially) or its numeric id from bugasura_list_knowledge_base_documents"),
    page_identifier: str = Field(description="Page to read: its page name (matched exactly then partially) or its page id (e.g. 'page_20250104120500')"),
    folder_name: Optional[str] = Field(default=None, description="Folder to search in when the same document name exists in several folders. Omit to search the whole project."),
    folder_id: Optional[int] = Field(default=None, description="Folder identifier to search in. Use only when the user picked a specific folder from a list.", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Read a knowledge base document page's markdown body.

    The API has no endpoint that returns a page's content: the markdown is written to the
    page's own file on the CDN and the path is kept on the page as `uploaded_file_path`. The
    web app's editor loads that file directly, and so does this tool — see
    `_read_kb_page_content`.

    This is the read half of an edit. The write action replaces a page's whole body, so an
    edit is read here, changed, then written back with
    bugasura_update_knowledge_base_page_content(mode='replace').

    Args:
        document_identifier: Name or numeric id of the document
        page_identifier: Page name or page id of the page to read
        folder_name / folder_id: Narrow the search when names repeat across folders
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'kb_id': int,
            'doc_name': str,
            'page_id': str,
            'page_name': str,
            'page_path': str,
            'content': str,              # '' when the page has never been written
            'content_length': int,
            'has_content': bool,
            'document_url': str,
            'message': str,
            'next_step': str
        }
        OR a selection prompt / failure envelope.

    Examples:
        # Read a page before editing it
        get_knowledge_base_page_content(document_identifier="Onboarding Spec",
                                        page_identifier="Overview")
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(
        api_key, team_id, project_id, 'bugasura_get_knowledge_base_page_content',
        f', document_identifier="{document_identifier}", page_identifier="{page_identifier}"'
    )
    if context.get('status') == 'selection_required':
        return context
    if context.get('status') == 'failed':
        return context

    team_id = context['team_id']
    project_id = context['project_id']
    team_id = await _resolve_project_team_id(api_key, team_id, project_id,
                                             'get_knowledge_base_page_content')

    doc = await _resolve_page_document(api_key, team_id, project_id, document_identifier,
                                       folder_id, folder_name)
    if doc.get('status') != 'OK':
        return doc
    document = doc['document']

    found = _find_kb_page(doc['pages'], page_identifier)
    if found.get('status') != 'OK':
        return found
    page = found['page']

    logger.info(f"get_knowledge_base_page_content: Reading page_id={page.get('page_id')} "
                f"on kb_id={document['kb_id']}")

    read = await asyncio.to_thread(_read_kb_page_content, page)
    if read.get('status') != 'OK':
        read['kb_id'] = document['kb_id']
        read['doc_name'] = doc['doc_name']
        read['page_id'] = page.get('page_id')
        read['page_name'] = page.get('page_name', '')
        return read

    pages_by_id = {str(p.get('page_id')): p for p in doc['pages']}
    normalised = _normalise_kb_page(page, pages_by_id)
    content = read['content']

    response = {
        'status': 'OK',
        'kb_id': document['kb_id'],
        'doc_name': doc['doc_name'],
        'page_id': page.get('page_id'),
        'page_name': normalised['page_name'],
        'page_path': normalised['page_path'],
        'content': content,
        'content_length': len(content),
        'has_content': content != '',
    }

    if content:
        response['message'] = (f"Read {len(content)} character(s) from the page "
                               f"'{normalised['page_name']}' in '{doc['doc_name']}'.")
        response['next_step'] = (
            "To change part of this page, edit the content you just read and write the FULL "
            "result back with bugasura_update_knowledge_base_page_content(mode='replace') — "
            "the write replaces the whole body. To only add to the end, skip the rewrite and "
            "call it with mode='append' instead."
        )
    else:
        response['message'] = (f"The page '{normalised['page_name']}' in '{doc['doc_name']}' is "
                               f"empty — nothing has been written to it yet.")
        response['next_step'] = ("Ask the user what should go on this page, then write it with "
                                 "bugasura_update_knowledge_base_page_content.")

    document_url = _kb_document_url(project_id, document['kb_id'])
    if document_url:
        response['document_url'] = document_url

    return response


@mcp.tool(
    name="bugasura_update_knowledge_base_page_content",
    description=(
        "Write the markdown body of a page in a Bugasura Knowledge Base page document. "
        "mode='replace' (the default) REPLACES the whole body and the previous content "
        "cannot be recovered — so to change part of a page, read it first with "
        "bugasura_get_knowledge_base_page_content, edit that text, and pass the full result "
        "here. Never write a partial body in replace mode. "
        "mode='append' and mode='prepend' add to the page instead: they read the current "
        "body themselves and keep it, so pass only the new text — this is the safe way to "
        "add a section without rewriting anything. "
        "Passing an empty string in replace mode clears the page. Bugasura re-indexes the "
        "page after every write, so its new content becomes searchable project context."
    ),
    # Not idempotent: append/prepend concatenate, so a retried call adds the text twice.
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def update_knowledge_base_page_content(
    document_identifier: str = Field(description="Document holding the page: its name (matched exactly then partially) or its numeric id from bugasura_list_knowledge_base_documents"),
    page_identifier: str = Field(description="Page to write: its page name (matched exactly then partially) or its page id (e.g. 'page_20250104120500')"),
    content: str = Field(description="In replace mode: the page's COMPLETE new markdown body (an empty string clears the page). In append/prepend mode: only the new text to add — the existing body is kept."),
    mode: Literal["replace", "append", "prepend"] = Field(default="replace", description="'replace' overwrites the whole body (default); 'append' adds the text to the end of the current body; 'prepend' adds it to the start. Append/prepend read the current body first and separate the two halves with a blank line."),
    folder_name: Optional[str] = Field(default=None, description="Folder to search in when the same document name exists in several folders. Omit to search the whole project."),
    folder_id: Optional[int] = Field(default=None, description="Folder identifier to search in. Use only when the user picked a specific folder from a list.", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Write, extend or clear the markdown body of a knowledge base document page.

    Posts the `edit_page_content` action to /v1/knowledgebase/update. The API stores the
    markdown as the page's own file, swaps the old copy out of the project's AI vector store
    and uploads the new one, so the page's content stays searchable. An empty body deletes
    the stored file instead.

    That action only ever replaces, so `append` / `prepend` are done here as a
    read-modify-write: the current body is read off the CDN, joined with the new text by a
    blank line, and sent as the full replacement. The read must succeed for those modes —
    if it fails the write is abandoned rather than silently replacing the page, which is
    what a blind append would amount to.

    Args:
        document_identifier: Name or numeric id of the document
        page_identifier: Page name or page id of the page to write
        content: Full new body in replace mode, or the text to add in append/prepend mode
        mode: 'replace' (default), 'append' or 'prepend'
        folder_name / folder_id: Narrow the search when names repeat across folders
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'kb_id': int,
            'doc_name': str,
            'page_id': str,
            'page_name': str,
            'page_path': str,
            'mode': str,
            'content_length': int,          # length of the body the page now holds
            'previous_content_length': int, # only for append / prepend
            'document_url': str,
            'message': str
        }
        OR a selection prompt / failure envelope.

    Examples:
        # Replace a page's body (read it first if you are changing part of it)
        update_knowledge_base_page_content(document_identifier="Onboarding Spec",
                                           page_identifier="Overview",
                                           content="# Overview\\n\\nHow onboarding works.")

        # Add a section without touching what is already there
        update_knowledge_base_page_content(document_identifier="Onboarding Spec",
                                           page_identifier="Overview", mode="append",
                                           content="## Rollout\\n\\nShipping in March.")

        # Clear a page
        update_knowledge_base_page_content(document_identifier="Onboarding Spec",
                                           page_identifier="Overview", content="")
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(
        api_key, team_id, project_id, 'bugasura_update_knowledge_base_page_content',
        f', document_identifier="{document_identifier}", page_identifier="{page_identifier}"'
    )
    if context.get('status') == 'selection_required':
        return context
    if context.get('status') == 'failed':
        return context

    team_id = context['team_id']
    project_id = context['project_id']

    if content is None:
        return {
            'status': 'failed',
            'error': 'content is required',
            'error_type': 'ValidationError',
            'message': ("Provide the page's complete new markdown body as content, or an empty "
                        "string to clear the page.")
        }

    # Adding nothing is not an edit — and it would still cost the page a re-index.
    if mode != 'replace' and content.strip() == '':
        return {
            'status': 'failed',
            'error': f'Nothing to {mode}',
            'error_type': 'ValidationError',
            'message': (f"content is empty, so there is nothing to {mode} to the page. Pass the "
                        f"text to add, or use mode='replace' with an empty string to clear the "
                        f"page.")
        }

    team_id = await _resolve_project_team_id(api_key, team_id, project_id,
                                             'update_knowledge_base_page_content')

    doc = await _resolve_page_document(api_key, team_id, project_id, document_identifier,
                                       folder_id, folder_name)
    if doc.get('status') != 'OK':
        return doc
    document = doc['document']

    found = _find_kb_page(doc['pages'], page_identifier)
    if found.get('status') != 'OK':
        return found
    page = found['page']

    # append / prepend keep what is already on the page, so the current body has to be read
    # before the write. A failed read aborts: writing anyway would replace the page.
    new_content = content
    previous_length = None
    if mode != 'replace':
        read = await asyncio.to_thread(_read_kb_page_content, page)
        if read.get('status') != 'OK':
            logger.error(f"update_knowledge_base_page_content: Cannot {mode} to "
                         f"page_id={page.get('page_id')} — its current content could not be read")
            read['message'] = (f"Cannot {mode} to this page: {read.get('message', '')} "
                               f"Nothing was written.").strip()
            read['kb_id'] = document['kb_id']
            read['doc_name'] = doc['doc_name']
            read['page_id'] = page.get('page_id')
            read['page_name'] = page.get('page_name', '')
            return read

        existing = read['content']
        previous_length = len(existing)
        if existing.strip() == '':
            new_content = content
        elif mode == 'append':
            new_content = existing.rstrip('\n') + _KB_PAGE_CONTENT_JOINER + content
        else:
            new_content = content.rstrip('\n') + _KB_PAGE_CONTENT_JOINER + existing

    logger.info(f"update_knowledge_base_page_content: mode='{mode}', writing "
                f"{len(new_content)} character(s) to page_id={page.get('page_id')} on "
                f"kb_id={document['kb_id']}")

    response = await _kb_doc_page_action(
        api_key, team_id, project_id, document['kb_id'], doc['doc_type'], 'edit_page_content',
        page_details=[{'page_id': page.get('page_id'), 'page_name': False,
                       'page_content': new_content}]
    )

    if response.get('status') != 'OK':
        logger.error(f"update_knowledge_base_page_content: Write failed for "
                     f"page_id={page.get('page_id')}: {response.get('message')}")
        return response

    pages = _pages_from_update_response(response, document['kb_id']) or doc['pages']
    pages_by_id = {str(p.get('page_id')): p for p in pages}
    normalised = _normalise_kb_page(pages_by_id.get(str(page.get('page_id')), page), pages_by_id)

    response['kb_id'] = document['kb_id']
    response['doc_name'] = doc['doc_name']
    response['page_id'] = page.get('page_id')
    response['page_name'] = normalised['page_name']
    response['page_path'] = normalised['page_path']
    response['mode'] = mode
    response['content_length'] = len(new_content)
    if previous_length is not None:
        response['previous_content_length'] = previous_length

    where = f"the page '{normalised['page_name']}' in '{doc['doc_name']}'"
    if mode == 'append':
        response['message'] = (f"Added {len(content)} character(s) to the end of {where}, keeping "
                               f"the {previous_length} character(s) already there.")
    elif mode == 'prepend':
        response['message'] = (f"Added {len(content)} character(s) to the start of {where}, keeping "
                               f"the {previous_length} character(s) already there.")
    elif new_content.strip() == '':
        response['message'] = f"Cleared the content of {where}."
    else:
        response['message'] = f"Replaced the content of {where}."

    document_url = _kb_document_url(project_id, document['kb_id'])
    if document_url:
        response['document_url'] = document_url

    return response


@mcp.tool(
    name="bugasura_duplicate_knowledge_base_page",
    description=(
        "Duplicate a page in a Bugasura Knowledge Base page document. The copy is placed "
        "right after the original as its sibling, named '<page name> (Copy)', and carries "
        "the original's content. Its sub pages are copied too unless "
        "include_sub_pages=False. Identify the document by name or id, and the page by its "
        "page name or page id from bugasura_list_knowledge_base_pages."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def duplicate_knowledge_base_page(
    document_identifier: str = Field(description="Document holding the page: its name (matched exactly then partially) or its numeric id from bugasura_list_knowledge_base_documents"),
    page_identifier: str = Field(description="Page to duplicate: its page name (matched exactly then partially) or its page id (e.g. 'page_20250104120500')"),
    include_sub_pages: bool = Field(default=True, description="Copy the page's sub pages along with it (default: True). Set False to copy just the page itself."),
    folder_name: Optional[str] = Field(default=None, description="Folder to search in when the same document name exists in several folders. Omit to search the whole project."),
    folder_id: Optional[int] = Field(default=None, description="Folder identifier to search in. Use only when the user picked a specific folder from a list.", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Duplicate a page of a knowledge base page document.

    Posts the `duplicate_page` action to /v1/knowledgebase/update. The API deep-copies the
    page under fresh page ids, copies each page's stored markdown into its own new file and
    re-indexes it, then inserts the copy right after the original.

    Args:
        document_identifier: Name or numeric id of the document
        page_identifier: Page name or page id of the page to duplicate
        include_sub_pages: Copy the sub pages too (default True)
        folder_name / folder_id: Narrow the search when names repeat across folders
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'kb_id': int,
            'doc_name': str,
            'page_id': str,              # id of the copy
            'page_name': str,            # '<original> (Copy)'
            'page_path': str,
            'source_page_id': str,
            'source_page_name': str,
            'copied_sub_page_count': int,
            'document_url': str,
            'message': str
        }
        OR a selection prompt / failure envelope.

    Examples:
        # Copy a page with everything under it
        duplicate_knowledge_base_page(document_identifier="Onboarding Spec",
                                      page_identifier="Rollout")

        # Copy just the page
        duplicate_knowledge_base_page(document_identifier="Onboarding Spec",
                                      page_identifier="Rollout", include_sub_pages=False)
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(
        api_key, team_id, project_id, 'bugasura_duplicate_knowledge_base_page',
        f', document_identifier="{document_identifier}", page_identifier="{page_identifier}"'
    )
    if context.get('status') == 'selection_required':
        return context
    if context.get('status') == 'failed':
        return context

    team_id = context['team_id']
    project_id = context['project_id']
    team_id = await _resolve_project_team_id(api_key, team_id, project_id,
                                             'duplicate_knowledge_base_page')

    doc = await _resolve_page_document(api_key, team_id, project_id, document_identifier,
                                       folder_id, folder_name)
    if doc.get('status') != 'OK':
        return doc
    document = doc['document']

    found = _find_kb_page(doc['pages'], page_identifier)
    if found.get('status') != 'OK':
        return found
    page = found['page']
    sub_page_count = len(_kb_descendant_page_ids(doc['pages'], page.get('page_id')))

    logger.info(f"duplicate_knowledge_base_page: Duplicating page_id={page.get('page_id')} on "
                f"kb_id={document['kb_id']} with include_sub_pages={include_sub_pages}")

    response = await _kb_doc_page_action(
        api_key, team_id, project_id, document['kb_id'], doc['doc_type'], 'duplicate_page',
        page_details=[{'page_id': page.get('page_id'), 'page_name': False, 'page_content': False,
                       'include_sub_pages': 1 if include_sub_pages else 0}]
    )

    if response.get('status') != 'OK':
        logger.error(f"duplicate_knowledge_base_page: Duplicate failed for "
                     f"page_id={page.get('page_id')}: {response.get('message')}")
        return response

    new_page = response.get('pageDetails') or {}
    pages = _pages_from_update_response(response, document['kb_id']) or doc['pages']
    pages_by_id = {str(p.get('page_id')): p for p in pages}
    normalised = _normalise_kb_page(pages_by_id.get(str(new_page.get('page_id')), new_page),
                                    pages_by_id)
    copied_sub_pages = sub_page_count if include_sub_pages else 0

    response['kb_id'] = document['kb_id']
    response['doc_name'] = doc['doc_name']
    response['page_id'] = new_page.get('page_id', '')
    response['page_name'] = normalised['page_name']
    response['page_path'] = normalised['page_path']
    response['source_page_id'] = page.get('page_id')
    response['source_page_name'] = page.get('page_name', '')
    response['copied_sub_page_count'] = copied_sub_pages
    response['message'] = (f"Duplicated the page '{page.get('page_name')}' as "
                           f"'{normalised['page_name']}' in '{doc['doc_name']}'.")
    if copied_sub_pages:
        response['message'] += f" Its {copied_sub_pages} sub page(s) were copied too."
    elif sub_page_count:
        response['message'] += (f" Its {sub_page_count} sub page(s) were left behind, as "
                                f"include_sub_pages was False.")

    document_url = _kb_document_url(project_id, document['kb_id'])
    if document_url:
        response['document_url'] = document_url

    logger.info(f"duplicate_knowledge_base_page: Created page_id={response['page_id']} on "
                f"kb_id={document['kb_id']}")
    return response


@mcp.tool(
    name="bugasura_move_knowledge_base_page",
    description=(
        "Move a page to a different place in a Bugasura Knowledge Base page document. Pass "
        "parent_page to nest it under another page, after_page to place it directly after a "
        "page as its sibling, or to_root=True to pull it out to the top level of the "
        "document — exactly one of the three. The page's sub pages travel with it, and its "
        "content is untouched. Identify the pages by page name or page id from "
        "bugasura_list_knowledge_base_pages."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def move_knowledge_base_page(
    document_identifier: str = Field(description="Document holding the page: its name (matched exactly then partially) or its numeric id from bugasura_list_knowledge_base_documents"),
    page_identifier: str = Field(description="Page to move: its page name (matched exactly then partially) or its page id (e.g. 'page_20250104120500')"),
    parent_page: Optional[str] = Field(default=None, description="Page to nest the moved page under, by page name or page id. Cannot be combined with after_page or to_root."),
    after_page: Optional[str] = Field(default=None, description="Page to place the moved page right after, as its sibling, by page name or page id. Cannot be combined with parent_page or to_root."),
    to_root: bool = Field(default=False, description="Move the page to the top level of the document, at the end. Cannot be combined with parent_page or after_page (default: False)."),
    folder_name: Optional[str] = Field(default=None, description="Folder to search in when the same document name exists in several folders. Omit to search the whole project."),
    folder_id: Optional[int] = Field(default=None, description="Folder identifier to search in. Use only when the user picked a specific folder from a list.", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Re-parent or reorder a page of a knowledge base page document.

    Posts the `page_reposition` action to /v1/knowledgebase/update. That action replaces the
    document's whole page structure, and the API rejects a structure that is not exactly the
    same set of pages, so the new flat `{page_id, parent_id}` list is rebuilt here from the
    stored one: the moved page is spliced out and reinserted at its new spot with its new
    parent. Only the moved page is re-parented — its own sub pages keep pointing at it and
    therefore travel with it, the same way the web app's drag-and-drop behaves.

    Args:
        document_identifier: Name or numeric id of the document
        page_identifier: Page name or page id of the page to move
        parent_page: Page to nest the moved page under
        after_page: Page to place the moved page after, as a sibling
        to_root: Move the page to the top level, at the end of the document
        folder_name / folder_id: Narrow the search when names repeat across folders
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'kb_id': int,
            'doc_name': str,
            'page_id': str,
            'page_name': str,
            'page_path': str,
            'parent_page_id': str,
            'parent_page_name': str,
            'moved_sub_page_count': int,
            'document_url': str,
            'message': str
        }
        OR a selection prompt / failure envelope.

    Examples:
        # Nest a page under another
        move_knowledge_base_page(document_identifier="Onboarding Spec",
                                 page_identifier="Step 1", parent_page="Rollout")

        # Reorder it next to a sibling
        move_knowledge_base_page(document_identifier="Onboarding Spec",
                                 page_identifier="Step 1", after_page="Step 2")

        # Pull it back out to the top level
        move_knowledge_base_page(document_identifier="Onboarding Spec",
                                 page_identifier="Step 1", to_root=True)
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(
        api_key, team_id, project_id, 'bugasura_move_knowledge_base_page',
        f', document_identifier="{document_identifier}", page_identifier="{page_identifier}"'
    )
    if context.get('status') == 'selection_required':
        return context
    if context.get('status') == 'failed':
        return context

    team_id = context['team_id']
    project_id = context['project_id']

    destinations = [bool(parent_page and parent_page.strip()),
                    bool(after_page and after_page.strip()),
                    bool(to_root)]
    if sum(destinations) != 1:
        return {
            'status': 'failed',
            'error': 'Exactly one destination is required',
            'error_type': 'ValidationError',
            'message': ('Say where the page should go: parent_page to nest it under a page, '
                        'after_page to place it after a page as its sibling, or to_root=True to '
                        'move it to the top level. Pass exactly one of the three.')
        }

    team_id = await _resolve_project_team_id(api_key, team_id, project_id,
                                             'move_knowledge_base_page')

    doc = await _resolve_page_document(api_key, team_id, project_id, document_identifier,
                                       folder_id, folder_name)
    if doc.get('status') != 'OK':
        return doc
    document = doc['document']
    pages = doc['pages']

    found = _find_kb_page(pages, page_identifier)
    if found.get('status') != 'OK':
        return found
    page = found['page']
    page_id = str(page.get('page_id'))
    descendant_ids = _kb_descendant_page_ids(pages, page_id)

    # Resolve the destination. `anchor_page_id` is the page the moved one is placed after;
    # None means "append at the end of the document".
    new_parent_id = ''
    anchor_page_id = None
    destination_page = None
    if parent_page and parent_page.strip():
        destination = _find_kb_page(pages, parent_page, role='parent page')
        if destination.get('status') != 'OK':
            return destination
        destination_page = destination['page']
        new_parent_id = str(destination_page.get('page_id'))
        # A page placed directly after its new parent reads as that parent's first sub page.
        anchor_page_id = new_parent_id
    elif after_page and after_page.strip():
        destination = _find_kb_page(pages, after_page, role='sibling page')
        if destination.get('status') != 'OK':
            return destination
        destination_page = destination['page']
        new_parent_id = str(destination_page.get('parent_id') or '')
        anchor_page_id = str(destination_page.get('page_id'))

    # A page cannot end up inside its own subtree — that would orphan the branch.
    if destination_page is not None:
        destination_id = str(destination_page.get('page_id'))
        if destination_id == page_id or destination_id in descendant_ids:
            logger.warning(f"move_knowledge_base_page: Refusing to move page_id={page_id} into its "
                           f"own subtree (destination page_id={destination_id})")
            return {
                'status': 'failed',
                'error': 'Cannot move a page into its own subtree',
                'error_type': 'ValidationError',
                'message': (f"'{page.get('page_name')}' cannot be moved under itself or under one of "
                            f"its own sub pages. Pick a page outside its branch, or use to_root=True."),
                'page_id': page_id,
                'page_name': page.get('page_name', ''),
                'sub_pages': _page_choices([p for p in pages
                                            if str(p.get('page_id')) in descendant_ids])
            }

    # Rebuild the flat {page_id, parent_id} structure page_reposition expects: the same set
    # of pages, with the moved one spliced out and reinserted under its new parent.
    remaining = [p for p in pages if str(p.get('page_id')) != page_id]
    structure = [{'page_id': p.get('page_id'), 'parent_id': p.get('parent_id') or ''}
                 for p in remaining]
    moved_entry = {'page_id': page.get('page_id'), 'parent_id': new_parent_id}

    if anchor_page_id is None:
        structure.append(moved_entry)
    else:
        anchor_index = next((index for index, entry in enumerate(structure)
                             if str(entry['page_id']) == anchor_page_id), len(structure) - 1)
        structure.insert(anchor_index + 1, moved_entry)

    logger.info(f"move_knowledge_base_page: Moving page_id={page_id} to parent_id="
                f"'{new_parent_id or 'root'}' on kb_id={document['kb_id']}")

    response = await _kb_doc_page_action(
        api_key, team_id, project_id, document['kb_id'], doc['doc_type'], 'page_reposition',
        page_details=structure
    )

    if response.get('status') != 'OK':
        logger.error(f"move_knowledge_base_page: Move failed for page_id={page_id}: "
                     f"{response.get('message')}")
        return response

    updated_pages = _pages_from_update_response(response, document['kb_id']) or pages
    pages_by_id = {str(p.get('page_id')): p for p in updated_pages}
    normalised = _normalise_kb_page(pages_by_id.get(page_id, page), pages_by_id)

    response['kb_id'] = document['kb_id']
    response['doc_name'] = doc['doc_name']
    response['page_id'] = page.get('page_id')
    response['page_name'] = normalised['page_name']
    response['page_path'] = normalised['page_path']
    response['parent_page_id'] = normalised['parent_page_id']
    response['parent_page_name'] = normalised['parent_page_name']
    response['moved_sub_page_count'] = len(descendant_ids)

    where = (f"under '{normalised['parent_page_name']}'" if normalised['parent_page_name']
             else "to the top level of the document")
    response['message'] = f"Moved the page '{normalised['page_name']}' {where}."
    if descendant_ids:
        response['message'] += f" Its {len(descendant_ids)} sub page(s) moved with it."

    document_url = _kb_document_url(project_id, document['kb_id'])
    if document_url:
        response['document_url'] = document_url

    return response


@mcp.tool(
    name="bugasura_delete_knowledge_base_page",
    description=(
        "Delete a page from a Bugasura Knowledge Base page document, permanently. The "
        "page's content and everything the AI learned from it are removed, and a page that "
        "has sub pages takes them ALL with it — such a page is NOT deleted unless "
        "delete_sub_pages=True, so tell the user which sub pages would go and get their "
        "confirmation first. Identify the document by name or id, and the page by its page "
        "name or page id from bugasura_list_knowledge_base_pages."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": True}
)
async def delete_knowledge_base_page(
    document_identifier: str = Field(description="Document holding the page: its name (matched exactly then partially) or its numeric id from bugasura_list_knowledge_base_documents"),
    page_identifier: str = Field(description="Page to delete: its page name (matched exactly then partially) or its page id (e.g. 'page_20250104120500')"),
    delete_sub_pages: bool = Field(default=False, description="Set True to delete a page that has sub pages — they are deleted with it. Leave False to have the tool refuse and report what is underneath (default: False)."),
    folder_name: Optional[str] = Field(default=None, description="Folder to search in when the same document name exists in several folders. Omit to search the whole project."),
    folder_id: Optional[int] = Field(default=None, description="Folder identifier to search in. Use only when the user picked a specific folder from a list.", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Delete a page, and its sub pages, from a knowledge base page document.

    Posts the `delete_page` action to /v1/knowledgebase/update. The API walks the page's
    `parent_id` chains, removes the page and every descendant, and deletes each one's stored
    markdown file and AI vector-store copy — this cannot be undone.

    The descendants are counted here first, so a page with sub pages is only deleted when
    the caller explicitly passes delete_sub_pages=True.

    Args:
        document_identifier: Name or numeric id of the document
        page_identifier: Page name or page id of the page to delete
        delete_sub_pages: Allow deleting a page that has sub pages
        folder_name / folder_id: Narrow the search when names repeat across folders
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'kb_id': int,
            'doc_name': str,
            'page_id': str,
            'page_name': str,
            'deleted_sub_page_count': int,
            'remaining_page_count': int,
            'document_url': str,
            'message': str
        }
        OR a selection prompt / failure envelope.

    Examples:
        # Delete a page with nothing under it
        delete_knowledge_base_page(document_identifier="Onboarding Spec",
                                   page_identifier="Scratch notes")

        # Delete a page together with its sub pages
        delete_knowledge_base_page(document_identifier="Onboarding Spec",
                                   page_identifier="Rollout", delete_sub_pages=True)
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(
        api_key, team_id, project_id, 'bugasura_delete_knowledge_base_page',
        f', document_identifier="{document_identifier}", page_identifier="{page_identifier}"'
    )
    if context.get('status') == 'selection_required':
        return context
    if context.get('status') == 'failed':
        return context

    team_id = context['team_id']
    project_id = context['project_id']
    team_id = await _resolve_project_team_id(api_key, team_id, project_id,
                                             'delete_knowledge_base_page')

    doc = await _resolve_page_document(api_key, team_id, project_id, document_identifier,
                                       folder_id, folder_name)
    if doc.get('status') != 'OK':
        return doc
    document = doc['document']
    pages = doc['pages']

    found = _find_kb_page(pages, page_identifier)
    if found.get('status') != 'OK':
        return found
    page = found['page']
    descendant_ids = _kb_descendant_page_ids(pages, page.get('page_id'))

    if descendant_ids and not delete_sub_pages:
        logger.warning(f"delete_knowledge_base_page: Page {page.get('page_id')} has "
                       f"{len(descendant_ids)} sub page(s); refusing without delete_sub_pages=True")
        return {
            'status': 'failed',
            'error': 'Page has sub pages',
            'error_type': 'PageNotEmpty',
            'message': (f"The page '{page.get('page_name')}' has {len(descendant_ids)} sub page(s), "
                        f"which would be deleted with it. Tell the user which pages would go and, "
                        f"once they confirm, call this tool again with delete_sub_pages=True. To keep "
                        f"them, move them elsewhere first with bugasura_move_knowledge_base_page."),
            'kb_id': document['kb_id'],
            'page_id': page.get('page_id'),
            'page_name': page.get('page_name', ''),
            'sub_page_count': len(descendant_ids),
            'sub_pages': _page_choices([p for p in pages
                                        if str(p.get('page_id')) in descendant_ids])
        }

    logger.info(f"delete_knowledge_base_page: Deleting page_id={page.get('page_id')} "
                f"('{page.get('page_name')}') with {len(descendant_ids)} sub page(s) from "
                f"kb_id={document['kb_id']}")

    response = await _kb_doc_page_action(
        api_key, team_id, project_id, document['kb_id'], doc['doc_type'], 'delete_page',
        page_details=[{'page_id': page.get('page_id'), 'page_name': False, 'page_content': False}]
    )

    if response.get('status') != 'OK':
        logger.error(f"delete_knowledge_base_page: Delete failed for page_id={page.get('page_id')}: "
                     f"{response.get('message')}")
        return response

    # The page and its descendants are exactly what the API removed, so the remaining count
    # is known here — no need to rely on the response carrying the updated document row.
    remaining_page_count = max(len(pages) - 1 - len(descendant_ids), 0)

    response['kb_id'] = document['kb_id']
    response['doc_name'] = doc['doc_name']
    response['page_id'] = page.get('page_id')
    response['page_name'] = page.get('page_name', '')
    response['deleted_sub_page_count'] = len(descendant_ids)
    response['remaining_page_count'] = remaining_page_count
    response['message'] = (f"Deleted the page '{page.get('page_name')}' from "
                           f"'{doc['doc_name']}'.")
    if descendant_ids:
        response['message'] += f" Its {len(descendant_ids)} sub page(s) were deleted with it."
    if not remaining_page_count:
        response['message'] += (" The document now has no pages — add one with "
                                "bugasura_create_knowledge_base_page, or delete the document with "
                                "bugasura_delete_knowledge_base_document.")

    document_url = _kb_document_url(project_id, document['kb_id'])
    if document_url:
        response['document_url'] = document_url

    logger.info(f"delete_knowledge_base_page: Deleted page_id={page.get('page_id')} from "
                f"kb_id={document['kb_id']}")
    return response


@mcp.tool(
    name="bugasura_upload_knowledge_base_document",
    description=(
        "Upload a document (.txt/.pdf/.doc/.docx/.md) to a Bugasura project's Knowledge Base. "
        "Folders are handled automatically: pass folder_name to file the document in that folder — "
        "it is created when the project does not have one by that name yet; omit folder_name and the "
        "project's first knowledge base folder is used, or a 'Knowledge Base' folder is created when "
        "the project has none. "
        "TWO WAYS TO PROVIDE THE FILE — pick ONE per call: "
        "(1) file_paths — absolute paths on the machine running this server (terminal/CLI use); ask the "
        "user for the exact path, never guess or construct it. "
        "(2) source_url — the Google Drive / Dropbox / public download link the user shared; the server "
        "fetches the file itself. "
        "Never read, encode, or convert the file yourself. "
        "This is the project-wide knowledge base — to add documents to a TestPert sprint's own knowledge "
        "base use bugasura_testpert_upload_kb instead."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def upload_knowledge_base_document(
    file_paths: List[str] = Field(default=[], description="Absolute paths on the MCP server's local filesystem (terminal/CLI use). Ask the user for the exact path — never construct or guess it. Multiple files are uploaded into the same folder."),
    source_url: Optional[str] = Field(default=None, description="Google Drive share link, Dropbox share link, or any public direct download URL. The MCP server fetches the file — no encoding needed. IMPORTANT: a Google Drive link must be set to 'Anyone with the link'."),
    source_url_filename: Optional[str] = Field(default=None, description="Original filename with extension (e.g. 'PRD.pdf'). Optional — inferred from the URL path or the Content-Disposition header when omitted. Only pass it if auto-detection fails or the user names the file."),
    folder_name: Optional[str] = Field(default=None, description="Knowledge base folder to add the document to. Matched case-insensitively; created at root level when no folder has that name. Omit to use the project's first knowledge base folder."),
    folder_id: Optional[int] = Field(default=None, description="Knowledge base folder identifier. Use only when the user picked a specific folder from a list — folder_name is the normal way to target a folder.", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Upload one or more documents to a project's knowledge base.

    Posts to /v1/knowledgebase/add as multipart/form-data with `kbType=upload_file`,
    mirroring the web app's "Import from file" flow. Each file is sent as its own
    field `choose_file_<index>`. The upstream API requires a `folderId`, so the
    folder is resolved (and created when needed) before the upload.

    Args:
        file_paths: Absolute local paths to upload (the MCP server must be able to read them)
        source_url: Public/share link the server downloads the file from
        source_url_filename: Original filename for source_url when it cannot be detected
        folder_name: Folder to file the document in (created when it does not exist)
        folder_id: Explicit folder identifier (takes precedence over folder_name)
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'kb_ids': [int],            # ids of the created knowledge base entries
            'folder_id': int,
            'folder_name': str,
            'folder_created': bool,
            'uploaded_files': [str],
            'knowledge_base_url': str,  # web app link, when the web base is known
            'message': str,
            'next_step': str
        }
        OR a selection prompt / failure envelope.

    Examples:
        # Into a named folder (created if it does not exist)
        upload_knowledge_base_document(file_paths=["/home/me/PRD.pdf"], folder_name="Product Specs")

        # No folder given — uses the project's first knowledge base folder
        upload_knowledge_base_document(file_paths=["/home/me/api-notes.md"], team_id=12, project_id=34)

        # From a share link
        upload_knowledge_base_document(source_url="https://drive.google.com/file/d/abc123/view")
    """
    context = await _connector_context(api_key, team_id, project_id,
                                       'bugasura_upload_knowledge_base_document',
                                       'upload_knowledge_base_document')
    if context.get('status') != 'OK':
        return context
    api_key, team_id, project_id = context['api_key'], context['team_id'], context['project_id']

    # Need exactly one content source.
    if not file_paths and not source_url:
        return {
            'status': 'failed',
            'error': 'No file provided',
            'error_type': 'ValidationError',
            'message': (
                'Ask the user how they want to provide the document. In the terminal, ask for the exact '
                'absolute file path and pass file_paths=[...]. Elsewhere, ask them to share a Google Drive '
                'or Dropbox link ("Anyone with the link") and pass source_url=<link>. '
                'Never read or encode the file yourself.'
            )
        }
    if file_paths and source_url:
        return {
            'status': 'failed',
            'error': 'Multiple content sources provided',
            'error_type': 'ValidationError',
            'message': 'Provide either file_paths or source_url per call, not both.'
        }

    # Read the documents first, so a bad path or unsupported file never creates a folder.
    collected = await asyncio.to_thread(
        _collect_upload_files, file_paths, source_url, source_url_filename)
    if collected.get('status') != 'OK':
        return collected
    files = collected['files']
    filenames = collected['filenames']

    # Resolve (or create) the destination folder — folderId is required upstream.
    folder = await _resolve_kb_folder(api_key, team_id, project_id, folder_id, folder_name)
    if folder.get('status') != 'OK':
        return folder

    logger.info(f"upload_knowledge_base_document: Uploading {len(files)} document(s) to "
                f"folder_id={folder['folder_id']} ('{folder['folder_name']}'), project_id={project_id}")

    response = await make_api_request('POST', '/v1/knowledgebase/add', api_key, data={
        'appId': str(project_id),
        'teamId': str(team_id),
        'folderId': str(folder['folder_id']),
        'kbType': 'upload_file',
    }, files=files)

    if response.get('status') != 'OK':
        logger.error(f"upload_knowledge_base_document: Upload failed: {response.get('message')}")
        return response

    response['kb_ids'] = response.get('kbIds', [])
    response['folder_id'] = folder['folder_id']
    response['folder_name'] = folder['folder_name']
    response['folder_created'] = folder.get('created', False)
    response['uploaded_files'] = filenames

    folder_phrase = (f"a new folder '{folder['folder_name']}'" if folder.get('created')
                     else f"the '{folder['folder_name']}' folder")
    response['message'] = (f"Added {len(filenames)} document(s) to {folder_phrase} "
                           f"in the knowledge base: {', '.join(filenames)}.")

    if WEB_BASE_URL:
        knowledge_base_url = f"{WEB_BASE_URL}knowledgeBase/{project_id}"
        response['knowledge_base_url'] = knowledge_base_url
        response['message'] += f" You can view the knowledge base here: {knowledge_base_url}"

    response['next_step'] = (
        "Tell the user in plain language which folder the document(s) landed in and share "
        "knowledge_base_url. Bugasura processes the document(s) in the background — they become "
        "searchable project context once processing finishes, so there is nothing else to do now. "
        "Ask whether they'd like to add more documents."
    )

    logger.info(f"upload_knowledge_base_document: Uploaded kb_ids={response['kb_ids']}")
    return response


@mcp.tool(
    name="bugasura_import_website_to_knowledge_base",
    description=(
        "Import a website into a Bugasura project's Knowledge Base — the Knowledge Base "
        "page's 'Import from Website' action. Bugasura crawls the URL and the pages linked "
        "from it, then turns what it finds into searchable project context. "
        "Pass one http:// or https:// URL per call. By default it follows links from that "
        "page up to 1000 pages; set include_linked_pages=False to take only the page itself, "
        "or max_pages to cap the crawl. "
        "The crawl runs in the background — this returns as soon as it is queued, and "
        "bugasura_list_knowledge_base_documents shows its progress in `stage`. "
        "Folders work as they do for uploads: pass folder_name to file it there, or omit it "
        "to use the project's first knowledge base folder."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def import_website_to_knowledge_base(
    website_url: str = Field(description="The website to import, e.g. 'https://docs.acme.dev'. Must start with http:// or https://. One URL per call — call again for another site."),
    max_pages: int = Field(default=_KB_MAX_WEBSITE_PAGES, description=f"Most pages to crawl (1-{_KB_MAX_WEBSITE_PAGES}, default {_KB_MAX_WEBSITE_PAGES}). Lower it when the user only wants a section of a large site.", ge=1, le=_KB_MAX_WEBSITE_PAGES),
    include_linked_pages: bool = Field(default=True, description="Follow links from the given page and import those too (default: True). Set False to import only the one page at website_url."),
    folder_name: Optional[str] = Field(default=None, description="Knowledge base folder to import into. Matched case-insensitively; created at root level when no folder has that name. Omit to use the project's first knowledge base folder."),
    folder_id: Optional[int] = Field(default=None, description="Knowledge base folder identifier. Use only when the user picked a specific folder from a list — folder_name is the normal way to target a folder.", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Import a website into a project's knowledge base.

    Posts to /v1/knowledgebase/add with `kbType=url` and a `toolsConnectionDetails` payload
    of `{website_url, max_limit, is_recursive}`, mirroring the web app's "Import from
    Website" flow. The API validates and stores the URL, then leaves the row at stage
    CONNECTED for the engine to pick up — the crawl, the page extraction and the AI indexing
    all happen in the background, so nothing here waits on them.

    `max_pages` is clamped to `_KB_MAX_WEBSITE_PAGES` upstream, and a trailing slash is
    stripped from the URL, so the stored URL may differ slightly from the one passed in.

    Args:
        website_url: The site to crawl (http:// or https://)
        max_pages: Cap on the number of pages crawled
        include_linked_pages: Follow links from the given page (`is_recursive` upstream)
        folder_name: Folder to import into (created when it does not exist)
        folder_id: Explicit folder identifier (takes precedence over folder_name)
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'kb_id': int,
            'kb_ids': [int],
            'website_url': str,
            'max_pages': int,
            'include_linked_pages': bool,
            'folder_id': int,
            'folder_name': str,
            'folder_created': bool,
            'knowledge_base_url': str,
            'message': str,
            'next_step': str
        }
        OR a selection prompt / failure envelope.

    Examples:
        # Crawl a documentation site into a named folder
        import_website_to_knowledge_base(website_url="https://docs.acme.dev",
                                         folder_name="Product Docs")

        # Just the one page
        import_website_to_knowledge_base(website_url="https://acme.dev/pricing",
                                         include_linked_pages=False)

        # Cap a large site
        import_website_to_knowledge_base(website_url="https://docs.acme.dev", max_pages=50)
    """
    context = await _connector_context(api_key, team_id, project_id,
                                       'bugasura_import_website_to_knowledge_base',
                                       'import_website_to_knowledge_base',
                                       f', website_url="{website_url}"')
    if context.get('status') != 'OK':
        return context
    api_key, team_id, project_id = context['api_key'], context['team_id'], context['project_id']

    # The crawler only speaks http(s), and the web app rejects anything else up front.
    website_url = (website_url or '').strip()
    invalid_url = _require_http_url(website_url, 'website_url', 'https://docs.acme.dev')
    if invalid_url:
        return invalid_url

    # One site per import — a list would silently crawl only the first.
    if len(website_url.split()) > 1:
        return _fail('More than one URL provided',
                     'Import one website per call. Call this tool again for each site the user '
                     'wants imported.')

    # folderId is required upstream, so resolve (or create) the folder before the import.
    folder = await _resolve_kb_folder(api_key, team_id, project_id, folder_id, folder_name)
    if folder.get('status') != 'OK':
        return folder

    logger.info(f"import_website_to_knowledge_base: Importing '{website_url}' "
                f"(max_pages={max_pages}, include_linked_pages={include_linked_pages}) into "
                f"folder_id={folder['folder_id']}, project_id={project_id}")

    response = await make_api_request('POST', '/v1/knowledgebase/add', api_key, data={
        'appId': str(project_id),
        'teamId': str(team_id),
        'folderId': str(folder['folder_id']),
        'kbType': 'url',
        'toolsConnectionDetails': json.dumps({
            'website_url': website_url,
            'max_limit': max_pages,
            'is_recursive': 1 if include_linked_pages else 0,
        }),
    })

    if response.get('status') != 'OK':
        logger.error(f"import_website_to_knowledge_base: Import failed for '{website_url}': "
                     f"{response.get('message')}")
        return response

    kb_ids = response.get('kbIds') or []
    response['kb_ids'] = kb_ids
    response['kb_id'] = next(iter(kb_ids), None)
    response['website_url'] = website_url
    response['max_pages'] = max_pages
    response['include_linked_pages'] = include_linked_pages
    response['folder_id'] = folder['folder_id']
    response['folder_name'] = folder['folder_name']
    response['folder_created'] = folder.get('created', False)

    folder_phrase = (f"a new folder '{folder['folder_name']}'" if folder.get('created')
                     else f"the '{folder['folder_name']}' folder")
    scope = (f"it and up to {max_pages} page(s) linked from it" if include_linked_pages
             else "that page only")
    response['message'] = (f"Started importing {website_url} into {folder_phrase}. Bugasura is "
                           f"crawling {scope}.")

    if WEB_BASE_URL:
        knowledge_base_url = f"{WEB_BASE_URL}knowledgeBase/{project_id}"
        response['knowledge_base_url'] = knowledge_base_url
        response['message'] += f" You can watch it here: {knowledge_base_url}"

    response['next_step'] = (
        "The crawl runs in the background and can take a while on a large site — do not wait "
        "on it. Tell the user it has started and share knowledge_base_url. If they ask how far "
        "along it is, call bugasura_list_knowledge_base_documents and read the entry's `stage`: "
        "CONNECTED or DOWNLOADING means it is still working, PROCESSED means the content is "
        "searchable, ERROR means the crawl failed."
    )

    logger.info(f"import_website_to_knowledge_base: Queued kb_ids={kb_ids} for '{website_url}'")
    return response

@mcp.tool(
    name="bugasura_list_coda_docs",
    description=(
        "List the Coda docs a Coda API key can see, so the user can pick which one to import "
        "into a Bugasura Knowledge Base. Ask the user for their Coda API key (Coda → account "
        "settings → API settings → Generate API token) — this server does not store it, so it "
        "is needed on every call. "
        "If the key is restricted to specific docs it cannot list them at all; ask the user for "
        "the doc's URL instead and pass it straight to bugasura_import_coda_to_knowledge_base."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def list_coda_docs(
    coda_api_key: str = Field(description="The user's Coda API key (Coda → account settings → API settings). Never guess or reuse one — ask the user each time."),
    start_at: int = Field(default=0, description="Pagination offset (default: 0)", ge=0),
    max_results: int = Field(default=_KB_CONNECTOR_PAGE_SIZE, description=f"Number of docs to return (default: {_KB_CONNECTOR_PAGE_SIZE})", ge=1, le=100),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    List the Coda docs available to a Coda API key.

    Reads /v1/coda/getDocs, which pages through Coda's own docs endpoint. No Bugasura
    project is involved, so this needs no team/project context.

    Args:
        coda_api_key: The user's Coda API key
        start_at / max_results: Pagination window
        response_format: 'json' or 'markdown'
        api_key: User's Bugasura API key

    Returns:
        dict: Standard pagination envelope whose items are
        {'doc_id', 'doc_name', 'browser_link'}, plus 'docs' and 'message'.
        OR a failure envelope — `RestrictedCodaKey` when the key cannot list docs.

    Examples:
        list_coda_docs(coda_api_key="abcd-1234")
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return _respond(validation, response_format)

    docs_response = await _fetch_coda_docs(api_key, coda_api_key)
    if docs_response.get('status') != 'OK':
        return _respond(docs_response, response_format)

    docs = docs_response['docs']
    page = docs[start_at:start_at + max_results]

    message = f"{len(docs)} Coda doc(s) available to this API key."
    if not docs:
        message = ("This Coda API key can see no docs. Check with the user that the key belongs "
                   "to the account holding the doc they want to import.")

    logger.info(f"list_coda_docs: Returning {len(page)} of {len(docs)} Coda doc(s)")
    return _respond(_paginated(page, total=len(docs), offset=start_at, docs=page,
                               message=message), response_format)


@mcp.tool(
    name="bugasura_list_coda_pages",
    description=(
        "List the pages of one Coda doc, so the user can choose which pages to import into a "
        "Bugasura Knowledge Base. Pass the doc's URL, its id, or its name as shown by "
        "bugasura_list_coda_docs. Sub-pages are included, with `page_path` showing where each "
        "one sits. "
        "Only call this when the user wants to pick individual pages — "
        "bugasura_import_coda_to_knowledge_base imports every page by default."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def list_coda_pages(
    coda_api_key: str = Field(description="The user's Coda API key (Coda → account settings → API settings). Never guess or reuse one — ask the user each time."),
    coda_doc: str = Field(description="The Coda doc: its share URL (e.g. 'https://coda.io/d/Product-Spec_dAbC123'), its doc id, or its name as listed by bugasura_list_coda_docs."),
    start_at: int = Field(default=0, description="Pagination offset (default: 0)", ge=0),
    max_results: int = Field(default=_KB_CONNECTOR_PAGE_SIZE, description=f"Number of pages to return (default: {_KB_CONNECTOR_PAGE_SIZE})", ge=1, le=100),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    List the pages of a Coda doc.

    Resolves the doc through /v1/coda/getDocDetails (URL/id) or /v1/coda/getDocs (name),
    then reads /v1/coda/getPages and flattens the nested page tree.

    Args:
        coda_api_key: The user's Coda API key
        coda_doc: Doc URL, id or name
        start_at / max_results: Pagination window
        response_format: 'json' or 'markdown'
        api_key: User's Bugasura API key

    Returns:
        dict: Standard pagination envelope whose items are {'page_id', 'page_name',
        'parent_page_id', 'ancestor_page_ids', 'page_path', 'depth'}, plus 'pages',
        'doc_id', 'doc_name' and 'message'.
        OR a failure envelope.

    Examples:
        list_coda_pages(coda_api_key="abcd-1234",
                        coda_doc="https://coda.io/d/Product-Spec_dAbC123")
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return _respond(validation, response_format)

    doc = await _resolve_coda_doc(api_key, coda_api_key, coda_doc)
    if doc.get('status') != 'OK':
        return _respond(doc, response_format)

    pages_response = await _fetch_coda_pages(api_key, coda_api_key, doc['doc_id'])
    if pages_response.get('status') != 'OK':
        return _respond(pages_response, response_format)

    pages = pages_response['pages']
    page = pages[start_at:start_at + max_results]

    message = f"{len(pages)} page(s) in the Coda doc '{doc['doc_name']}'."
    if not pages:
        message = f"The Coda doc '{doc['doc_name']}' has no pages to import."

    logger.info(f"list_coda_pages: Returning {len(page)} of {len(pages)} page(s) for Coda "
                f"doc_id={doc['doc_id']}")
    return _respond(_paginated(page, total=len(pages), offset=start_at, pages=page,
                               doc_id=doc['doc_id'], doc_name=doc['doc_name'],
                               message=message), response_format)


@mcp.tool(
    name="bugasura_import_coda_to_knowledge_base",
    description=(
        "Import a Coda doc into a Bugasura project's Knowledge Base — the Knowledge Base page's "
        "'Superhuman Import' action. Bugasura pulls the doc's pages in and turns them into "
        "searchable project context, keeping the page/sub-page structure. "
        "Ask the user for their Coda API key and which doc to import (a share URL works, and is "
        "the only form a doc-restricted key supports). Every page is imported unless "
        "page_identifiers names specific ones — use bugasura_list_coda_pages to show the user "
        "what is there first. "
        "The import runs in the background — this returns as soon as it is queued, and "
        "bugasura_list_knowledge_base_documents shows its progress in `stage`. "
        "Folders work as they do for uploads: pass folder_name to file it there, or omit it to "
        "use the project's first knowledge base folder."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def import_coda_to_knowledge_base(
    coda_api_key: str = Field(description="The user's Coda API key (Coda → account settings → API settings). Never guess or reuse one — ask the user each time."),
    coda_doc: str = Field(description="The Coda doc to import: its share URL (e.g. 'https://coda.io/d/Product-Spec_dAbC123'), its doc id, or its name as listed by bugasura_list_coda_docs. A doc-restricted API key only works with the URL or the id."),
    page_identifiers: List[str] = Field(default=[], description="Pages to import, by page name or page id (see bugasura_list_coda_pages). Omit to import every page in the doc. A page whose parent is left out is re-filed under the nearest ancestor that was included."),
    folder_name: Optional[str] = Field(default=None, description="Knowledge base folder to import into. Matched case-insensitively; created at root level when no folder has that name. Omit to use the project's first knowledge base folder."),
    folder_id: Optional[int] = Field(default=None, description="Knowledge base folder identifier. Use only when the user picked a specific folder from a list — folder_name is the normal way to target a folder.", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Import a Coda doc into a project's knowledge base.

    Posts to /v1/knowledgebase/add with `kbType=coda` and a `toolsConnectionDetails`
    payload of `{doc_id, doc_name, api_key, pages}`, mirroring the web app's "Superhuman
    Import" flow. The API stores the selection in the same page-tree shape a page document
    uses and leaves the row at stage CONNECTED for the import worker, so the page contents
    arrive in the background.

    Args:
        coda_api_key: The user's Coda API key
        coda_doc: Doc URL, id or name
        page_identifiers: Pages to import (empty imports all of them)
        folder_name: Folder to import into (created when it does not exist)
        folder_id: Explicit folder identifier (takes precedence over folder_name)
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'kb_id': int,
            'kb_ids': [int],
            'doc_id': str,
            'doc_name': str,
            'imported_pages': [{'page_id', 'page_name', 'page_path'}],
            'folder_id': int,
            'folder_name': str,
            'folder_created': bool,
            'knowledge_base_url': str,
            'message': str,
            'next_step': str
        }
        OR a selection prompt / failure envelope.

    Examples:
        # The whole doc
        import_coda_to_knowledge_base(coda_api_key="abcd-1234",
                                      coda_doc="https://coda.io/d/Product-Spec_dAbC123")

        # Two named pages into a named folder
        import_coda_to_knowledge_base(coda_api_key="abcd-1234", coda_doc="Product Spec",
                                      page_identifiers=["Overview", "API Reference"],
                                      folder_name="Product Docs")
    """
    context = await _connector_context(api_key, team_id, project_id,
                                       'bugasura_import_coda_to_knowledge_base',
                                       'import_coda_to_knowledge_base',
                                       f', coda_doc="{coda_doc}"')
    if context.get('status') != 'OK':
        return context
    api_key, team_id, project_id = context['api_key'], context['team_id'], context['project_id']

    doc = await _resolve_coda_doc(api_key, coda_api_key, coda_doc)
    if doc.get('status') != 'OK':
        return doc

    pages_response = await _fetch_coda_pages(api_key, coda_api_key, doc['doc_id'])
    if pages_response.get('status') != 'OK':
        return pages_response

    selection = _select_items(page_identifiers, pages_response['pages'], 'page_id', 'page_name',
                              'Coda pages', 'bugasura_list_coda_pages')
    if selection.get('status') != 'OK':
        return selection
    selected_pages = selection['items']

    # folderId is required upstream, so resolve (or create) the folder before the import.
    folder = await _resolve_kb_folder(api_key, team_id, project_id, folder_id, folder_name)
    if folder.get('status') != 'OK':
        return folder

    response = await _submit_kb_import(api_key, team_id, project_id, 'coda', {
        'doc_id': doc['doc_id'],
        'doc_name': doc['doc_name'],
        'api_key': coda_api_key,
        'pages': [{
            'id': page['page_id'],
            'name': page['page_name'],
            'is_subpage': 1 if page['parent_page_id'] else 0,
            'parent_id': page['parent_page_id'],
            'ancestor_ids': page['ancestor_page_ids'],
        } for page in selected_pages],
    }, folder)
    if response.get('status') != 'OK':
        return response

    response['doc_id'] = doc['doc_id']
    response['doc_name'] = doc['doc_name']
    response['imported_pages'] = [{'page_id': p['page_id'], 'page_name': p['page_name'],
                                   'page_path': p['page_path']} for p in selected_pages]

    folder_phrase = (f"a new folder '{folder['folder_name']}'" if folder.get('created')
                     else f"the '{folder['folder_name']}' folder")
    scope = ("all of its pages" if not page_identifiers
             else f"{len(selected_pages)} of its pages")
    response['message'] = (f"Started importing the Coda doc '{doc['doc_name']}' into "
                           f"{folder_phrase} — {scope}.")

    if WEB_BASE_URL:
        knowledge_base_url = f"{WEB_BASE_URL}knowledgeBase/{project_id}"
        response['knowledge_base_url'] = knowledge_base_url
        response['message'] += f" You can watch it here: {knowledge_base_url}"

    response['next_step'] = (
        "The import runs in the background — do not wait on it. Tell the user it has started "
        "and share knowledge_base_url. If they ask how far along it is, call "
        "bugasura_list_knowledge_base_documents and read the entry's `stage`: CONNECTED or "
        "DOWNLOADING means it is still working, PROCESSED means the pages are searchable, ERROR "
        "means the import failed. Once it is PROCESSED the pages can be read and edited with "
        "the bugasura_*_knowledge_base_page tools."
    )

    logger.info(f"import_coda_to_knowledge_base: Queued kb_ids={response['kb_ids']} for Coda "
                f"doc_id={doc['doc_id']} ({len(selected_pages)} page(s))")
    return response

@mcp.tool(
    name="bugasura_list_jira_projects",
    description=(
        "List the Jira projects an account can see, so the user can pick which ones to import "
        "into a Bugasura Knowledge Base. Ask the user for their Jira site URL, the account "
        "email, and an API token (Jira Cloud) or password (Jira Server/Enterprise) — this "
        "server does not store them, so they are needed on every call. "
        "`total_issue_count` tells you how big each project is before importing it."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def list_jira_projects(
    jira_url: str = Field(description="The Jira site URL, e.g. 'https://acme.atlassian.net'."),
    user_name: str = Field(description="The Jira account email (Cloud) or username (Server/Enterprise)."),
    api_token: str = Field(description="The Jira API token (Cloud) or the account password (Server/Enterprise). Ask the user — never guess or reuse one."),
    deployment_type: Literal["CLOUD", "SERVER"] = Field(default="CLOUD", description="'CLOUD' for Jira Cloud (*.atlassian.net, API token), 'SERVER' for a self-hosted Jira/Data Center (password). Default: CLOUD."),
    start_at: int = Field(default=0, description="Pagination offset (default: 0)", ge=0),
    max_results: int = Field(default=_KB_CONNECTOR_PAGE_SIZE, description=f"Number of projects to return (default: {_KB_CONNECTOR_PAGE_SIZE})", ge=1, le=100),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    List the Jira projects reachable with the given credentials.

    Reads /v1/bugTracker/getProjectList with `toolName=JIRA`. The credentials are passed
    through to Jira and are not stored by Bugasura.

    Args:
        jira_url / user_name / api_token / deployment_type: Jira credentials
        start_at / max_results: Pagination window
        team_id / project_id: Resolved interactively if omitted
        response_format: 'json' or 'markdown'
        api_key: User's Bugasura API key

    Returns:
        dict: Standard pagination envelope whose items are {'project_key', 'project_name',
        'total_issue_count'}, plus 'projects' and 'message'.
        OR a selection prompt / failure envelope.

    Examples:
        list_jira_projects(jira_url="https://acme.atlassian.net",
                           user_name="qa@acme.dev", api_token="...")
    """
    context = await _connector_context(api_key, team_id, project_id,
                                       'bugasura_list_jira_projects', 'list_jira_projects',
                                       f', jira_url="{jira_url}", user_name="{user_name}"')
    if context.get('status') != 'OK':
        return _respond(context, response_format)
    api_key, team_id, project_id = context['api_key'], context['team_id'], context['project_id']

    invalid_url = _require_http_url(jira_url.strip(), 'jira_url', 'https://acme.atlassian.net')
    if invalid_url:
        return _respond(invalid_url, response_format)

    credentials = _jira_credentials(jira_url.strip(), user_name, api_token, deployment_type)
    projects_response = await _fetch_jira_projects(api_key, team_id, project_id, credentials)
    if projects_response.get('status') != 'OK':
        return _respond(projects_response, response_format)

    projects = projects_response['projects']
    page = projects[start_at:start_at + max_results]

    message = f"{len(projects)} Jira project(s) visible to {user_name}."
    if not projects:
        message = (f"{user_name} can see no projects on {jira_url}. Check the credentials and "
                   f"that the account has access to at least one project.")

    logger.info(f"list_jira_projects: Returning {len(page)} of {len(projects)} Jira project(s)")
    return _respond(_paginated(page, total=len(projects), offset=start_at, projects=page,
                               message=message), response_format)


@mcp.tool(
    name="bugasura_list_jira_issues",
    description=(
        "List (or search) the issues of one Jira project, so the user can pick individual issues "
        "to import into a Bugasura Knowledge Base. Same credentials as "
        "bugasura_list_jira_projects. "
        "Only call this when the user wants specific issues — "
        "bugasura_import_jira_to_knowledge_base imports every issue in a project by default. "
        "Results are paged: pass the returned `next_page_token` back as page_token for the next "
        "page."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def list_jira_issues(
    jira_url: str = Field(description="The Jira site URL, e.g. 'https://acme.atlassian.net'."),
    user_name: str = Field(description="The Jira account email (Cloud) or username (Server/Enterprise)."),
    api_token: str = Field(description="The Jira API token (Cloud) or the account password (Server/Enterprise). Ask the user — never guess or reuse one."),
    project_key: str = Field(description="The Jira project key to list issues from, e.g. 'ACME' (see bugasura_list_jira_projects)."),
    deployment_type: Literal["CLOUD", "SERVER"] = Field(default="CLOUD", description="'CLOUD' for Jira Cloud (*.atlassian.net, API token), 'SERVER' for a self-hosted Jira/Data Center (password). Default: CLOUD."),
    search_text: str = Field(default="", description="Filter issues whose summary or key matches this text. Omit to list the project's issues in order."),
    page_token: str = Field(default="", description="Continue from a previous call — pass the `next_page_token` it returned. Omit for the first page."),
    max_results: int = Field(default=_KB_CONNECTOR_PAGE_SIZE, description=f"Number of issues to return (default: {_KB_CONNECTOR_PAGE_SIZE})", ge=1, le=100),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    List the issues of a Jira project.

    Reads /v1/testpert/searchToolsProjectIssues with `toolName=JIRA`. Jira pages this
    endpoint with an opaque token rather than an offset, so the token is passed back
    through `page_token` instead of the usual `start_at`.

    Args:
        jira_url / user_name / api_token / deployment_type: Jira credentials
        project_key: The Jira project to list
        search_text: Optional summary/key filter
        page_token / max_results: Pagination window
        team_id / project_id: Resolved interactively if omitted
        response_format: 'json' or 'markdown'
        api_key: User's Bugasura API key

    Returns:
        dict: Standard pagination envelope whose items are {'issue_key', 'summary', 'type',
        'link'} — `total`/`count` describe this page, since Jira pages with a token — plus
        'issues', 'project_key', 'project_issue_count', 'next_page_token', 'is_last_page'
        and 'message'.
        OR a selection prompt / failure envelope.

    Examples:
        list_jira_issues(jira_url="https://acme.atlassian.net", user_name="qa@acme.dev",
                         api_token="...", project_key="ACME", search_text="checkout")
    """
    context = await _connector_context(api_key, team_id, project_id,
                                       'bugasura_list_jira_issues', 'list_jira_issues',
                                       f', jira_url="{jira_url}", project_key="{project_key}"')
    if context.get('status') != 'OK':
        return _respond(context, response_format)
    api_key, team_id, project_id = context['api_key'], context['team_id'], context['project_id']

    invalid_url = _require_http_url(jira_url.strip(), 'jira_url', 'https://acme.atlassian.net')
    if invalid_url:
        return _respond(invalid_url, response_format)

    credentials = _jira_credentials(jira_url.strip(), user_name, api_token, deployment_type)
    response = await make_api_request('POST', '/v1/testpert/searchToolsProjectIssues', api_key,
                                      data={
                                          'toolName': 'JIRA',
                                          'appId': str(project_id),
                                          'teamId': str(team_id),
                                          'projectKey': project_key,
                                          'searchString': search_text,
                                          'startIndex': page_token,
                                          'listRange': max_results,
                                          'toolIssueId': '',
                                          'isApiRequest': 0,
                                          **credentials,
                                      })

    if response.get('status') != 'OK':
        logger.error(f"list_jira_issues: Failed to list issues of '{project_key}': "
                     f"{response.get('message')}")
        return _respond(_fail('Failed to list Jira issues',
                              response.get('message', f"Jira did not return the issues of "
                                                      f"'{project_key}'."),
                              error_type='JiraFetchError'), response_format)

    issues = [{'issue_key': i.get('key', ''), 'summary': i.get('summary', ''),
               'type': i.get('type', ''), 'link': i.get('link', '')}
              for i in response.get('searchIssuesList') or []]
    is_last_page = str(response.get('isLastPage', '')) == '1' or not response.get('nextPageToken')
    next_page_token = '' if is_last_page else response.get('nextPageToken', '')

    message = f"{len(issues)} issue(s) from the Jira project '{project_key}'."
    if not issues:
        message = (f"No issues matching that search in '{project_key}'."
                   if search_text else f"The Jira project '{project_key}' has no issues.")

    logger.info(f"list_jira_issues: Returning {len(issues)} issue(s) of '{project_key}'")
    # Jira pages with an opaque token, so the envelope describes this page only and the
    # continuation is `next_page_token` rather than `next_offset`. total=None keeps
    # _paginated from computing a total it cannot know; has_more is overridden from Jira's
    # own is_last_page, so a caller reading the standard envelope still sees more pages.
    envelope = _paginated(issues, total=None, offset=0,
                          issues=issues, project_key=project_key,
                          project_issue_count=response.get('totalCount'),
                          next_page_token=next_page_token, is_last_page=is_last_page,
                          message=message)
    envelope['has_more'] = not is_last_page
    return _respond(envelope, response_format)


@mcp.tool(
    name="bugasura_import_jira_to_knowledge_base",
    description=(
        "Import Jira issues into a Bugasura project's Knowledge Base — the Knowledge Base page's "
        "'Jira Import' action. Bugasura pulls the selected projects' issues in and turns them "
        "into searchable project context, one page per Jira project. "
        "Ask the user for their Jira site URL, account email and API token (or password for a "
        "self-hosted Jira), then which projects to import — bugasura_list_jira_projects shows "
        "what is available. Every issue in each project is imported unless issue_keys names "
        "specific ones. "
        "By default this creates a new Knowledge Base document; pass document_identifier to add "
        "the issues to an existing document instead. "
        "The import runs in the background — this returns as soon as it is queued, and "
        "bugasura_list_knowledge_base_documents shows its progress in `stage`."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def import_jira_to_knowledge_base(
    jira_url: str = Field(description="The Jira site URL, e.g. 'https://acme.atlassian.net'."),
    user_name: str = Field(description="The Jira account email (Cloud) or username (Server/Enterprise)."),
    api_token: str = Field(description="The Jira API token (Cloud) or the account password (Server/Enterprise). Ask the user — never guess or reuse one."),
    project_keys: List[str] = Field(default=[], description="Jira project keys or project names to import, e.g. ['ACME', 'Payments'] (see bugasura_list_jira_projects). Omit to import every project the account can see — check with the user before doing that."),
    issue_keys: List[str] = Field(default=[], description="Import only these issues, by Jira issue key (e.g. ['ACME-12', 'ACME-31']). Every key's project must also be in project_keys. Omit to import all issues of each selected project."),
    deployment_type: Literal["CLOUD", "SERVER"] = Field(default="CLOUD", description="'CLOUD' for Jira Cloud (*.atlassian.net, API token), 'SERVER' for a self-hosted Jira/Data Center (password). Default: CLOUD."),
    document_identifier: Optional[str] = Field(default=None, description="Add the issues to this existing Knowledge Base document instead of creating a new one — its name or its kb_id (see bugasura_list_knowledge_base_documents). Only a page document accepts an import; an uploaded file does not."),
    folder_name: Optional[str] = Field(default=None, description="Knowledge base folder to import into (or, with document_identifier, the folder to look the document up in). Matched case-insensitively; created at root level when no folder has that name. Omit to use the project's first knowledge base folder."),
    folder_id: Optional[int] = Field(default=None, description="Knowledge base folder identifier. Use only when the user picked a specific folder from a list — folder_name is the normal way to target a folder.", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Import Jira issues into a project's knowledge base.

    Posts to /v1/knowledgebase/add with `kbType=jira` and a `toolsConnectionDetails`
    payload of the credentials plus `projectDetails` (keyed by project key, each with the
    chosen issue keys or the "all" marker), mirroring the web app's Jira Import modal. The
    API creates one page per Jira project, flags them pending and queues the
    `import_jira_kb` worker, which fetches the issues in the background.

    With `document_identifier` the same payload goes to /v1/knowledgebase/importDocPages
    instead, which merges the selection into an existing page document — the web app's
    "Import → Jira" from inside a document.

    Args:
        jira_url / user_name / api_token / deployment_type: Jira credentials
        project_keys: Jira projects to import (empty imports every visible project)
        issue_keys: Restrict the import to these issues
        document_identifier: Import into this existing page document instead of a new one
        folder_name: Folder to import into, or to scope the document lookup to
        folder_id: Explicit folder identifier (takes precedence over folder_name)
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'kb_id': int,
            'kb_ids': [int],              # new-document imports only
            'imported_projects': [{'project_key', 'project_name', 'issue_count'}],
            'folder_id': int,             # new-document imports only
            'folder_name': str,
            'folder_created': bool,
            'document_url': str,
            'knowledge_base_url': str,
            'message': str,
            'next_step': str
        }
        OR a selection prompt / failure envelope.

    Examples:
        # Two whole projects into a new document
        import_jira_to_knowledge_base(jira_url="https://acme.atlassian.net",
                                      user_name="qa@acme.dev", api_token="...",
                                      project_keys=["ACME", "PAY"])

        # Specific issues, added to an existing document
        import_jira_to_knowledge_base(jira_url="https://acme.atlassian.net",
                                      user_name="qa@acme.dev", api_token="...",
                                      project_keys=["ACME"], issue_keys=["ACME-12", "ACME-31"],
                                      document_identifier="Release Notes")
    """
    context = await _connector_context(api_key, team_id, project_id,
                                       'bugasura_import_jira_to_knowledge_base',
                                       'import_jira_to_knowledge_base',
                                       f', jira_url="{jira_url}", project_keys={project_keys}')
    if context.get('status') != 'OK':
        return context
    api_key, team_id, project_id = context['api_key'], context['team_id'], context['project_id']

    invalid_url = _require_http_url(jira_url.strip(), 'jira_url', 'https://acme.atlassian.net')
    if invalid_url:
        return invalid_url

    credentials = _jira_credentials(jira_url.strip(), user_name, api_token, deployment_type)

    # The API needs each project's display name, so the project list is fetched even when
    # the caller already knows the keys.
    projects_response = await _fetch_jira_projects(api_key, team_id, project_id, credentials)
    if projects_response.get('status') != 'OK':
        return projects_response

    selection = _select_items(project_keys, projects_response['projects'], 'project_key',
                              'project_name', 'Jira projects', 'bugasura_list_jira_projects')
    if selection.get('status') != 'OK':
        return selection
    selected_projects = selection['items']

    connection_details = _jira_connection_details(credentials, selected_projects, issue_keys)
    if connection_details.get('status') != 'OK':
        return connection_details
    payload = connection_details['payload']

    imported_projects = [{
        'project_key': key,
        'project_name': details['projectName'],
        'issue_count': details['totalIssueCount'],
        'all_issues': details['issueId'] == _KB_IMPORT_ALL,
    } for key, details in payload['projectDetails'].items()]

    if document_identifier:
        target = await _resolve_import_target_page(api_key, team_id, project_id,
                                                   document_identifier, None,
                                                   folder_id, folder_name)
        if target.get('status') != 'OK':
            return target

        kb_id = target['document']['kb_id']
        response = await _submit_doc_page_import(api_key, team_id, project_id, kb_id,
                                                 target['page']['page_id'], 'jira',
                                                 tools_connection_details=payload)
        if response.get('status') != 'OK':
            logger.error(f"import_jira_to_knowledge_base: Import into kb_id={kb_id} failed: "
                         f"{response.get('message')}")
            return response

        response['kb_id'] = kb_id
        response['doc_name'] = target['doc_name']
        response['message'] = (f"Started importing {len(imported_projects)} Jira project(s) into "
                               f"the document '{target['doc_name']}'.")
    else:
        folder = await _resolve_kb_folder(api_key, team_id, project_id, folder_id, folder_name)
        if folder.get('status') != 'OK':
            return folder

        response = await _submit_kb_import(api_key, team_id, project_id, 'jira', payload, folder)
        if response.get('status') != 'OK':
            return response

        folder_phrase = (f"a new folder '{folder['folder_name']}'" if folder.get('created')
                         else f"the '{folder['folder_name']}' folder")
        response['message'] = (f"Started importing {len(imported_projects)} Jira project(s) into "
                               f"{folder_phrase}: "
                               f"{', '.join(p['project_key'] for p in imported_projects)}.")

    response['imported_projects'] = imported_projects

    document_url = _kb_document_url(project_id, response.get('kb_id'))
    if document_url:
        response['document_url'] = document_url
    if WEB_BASE_URL:
        knowledge_base_url = f"{WEB_BASE_URL}knowledgeBase/{project_id}"
        response['knowledge_base_url'] = knowledge_base_url
        response['message'] += f" You can watch it here: {document_url or knowledge_base_url}"

    response['next_step'] = (
        "The import runs in the background and can take a while on a large project — do not wait "
        "on it. Tell the user it has started and share the link. If they ask how far along it "
        "is, call bugasura_list_knowledge_base_documents and read the entry's `stage`: "
        "IMPORT_PAGES or CONNECTED means it is still working, PROCESSED means the issues are "
        "searchable, ERROR means the import failed."
    )

    logger.info(f"import_jira_to_knowledge_base: Queued kb_id={response.get('kb_id')} for "
                f"{len(imported_projects)} Jira project(s)")
    return response

@mcp.tool(
    name="bugasura_list_confluence_spaces",
    description=(
        "List the Confluence spaces an account can see, so the user can pick which ones to "
        "import into a Bugasura Knowledge Base. Ask the user for their Confluence site URL, the "
        "account email and an API token — this server does not store them, so they are needed on "
        "every call. Omit all three to use the credentials already saved in the project's "
        "Confluence integration, when one is configured."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def list_confluence_spaces(
    confluence_url: str = Field(default="", description="The Confluence site URL, e.g. 'https://acme.atlassian.net'. Omit to use the project's saved Confluence integration."),
    user_email: str = Field(default="", description="The Confluence account email. Omit to use the project's saved Confluence integration."),
    api_token: str = Field(default="", description="The Confluence API token. Ask the user — never guess or reuse one. Omit to use the project's saved Confluence integration."),
    start_at: int = Field(default=0, description="Pagination offset (default: 0)", ge=0),
    max_results: int = Field(default=_KB_CONNECTOR_PAGE_SIZE, description=f"Number of spaces to return (default: {_KB_CONNECTOR_PAGE_SIZE})", ge=1, le=100),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    List the Confluence spaces reachable with the given credentials.

    Reads /v1/confluence/getSpaceList. Passing all three credentials bypasses the
    project's stored Confluence integration; passing none falls back to it.

    Args:
        confluence_url / user_email / api_token: Confluence credentials (all three, or none)
        start_at / max_results: Pagination window
        team_id / project_id: Resolved interactively if omitted
        response_format: 'json' or 'markdown'
        api_key: User's Bugasura API key

    Returns:
        dict: Standard pagination envelope whose items are {'space_key', 'space_name'},
        plus 'spaces' and 'message'.
        OR a selection prompt / failure envelope.

    Examples:
        list_confluence_spaces(confluence_url="https://acme.atlassian.net",
                               user_email="qa@acme.dev", api_token="...")
    """
    context = await _connector_context(api_key, team_id, project_id,
                                       'bugasura_list_confluence_spaces',
                                       'list_confluence_spaces')
    if context.get('status') != 'OK':
        return _respond(context, response_format)
    api_key, team_id, project_id = context['api_key'], context['team_id'], context['project_id']

    supplied = [value for value in (confluence_url, user_email, api_token) if value.strip()]
    if supplied and len(supplied) < 3:
        return _respond(_fail('Incomplete Confluence credentials',
                              'Pass confluence_url, user_email and api_token together, or leave '
                              'all three out to use the project\'s saved Confluence '
                              'integration.'), response_format)

    credentials = (_confluence_credentials(confluence_url.strip(), user_email, api_token)
                   if supplied else {})
    spaces_response = await _fetch_confluence_spaces(api_key, team_id, project_id, credentials)
    if spaces_response.get('status') != 'OK':
        return _respond(spaces_response, response_format)

    spaces = spaces_response['spaces']
    page = spaces[start_at:start_at + max_results]

    message = f"{len(spaces)} Confluence space(s) available."
    if not spaces:
        message = ("No Confluence spaces are visible to this account. Check the credentials and "
                   "that the account has access to at least one space.")

    logger.info(f"list_confluence_spaces: Returning {len(page)} of {len(spaces)} space(s)")
    return _respond(_paginated(page, total=len(spaces), offset=start_at, spaces=page,
                               message=message), response_format)


@mcp.tool(
    name="bugasura_list_confluence_pages",
    description=(
        "List the pages of one Confluence space, so the user can pick individual pages to import "
        "into a Bugasura Knowledge Base. Same credentials as bugasura_list_confluence_spaces. "
        "Only call this when the user wants specific pages — "
        "bugasura_import_confluence_to_knowledge_base imports whole spaces by default."
    ),
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def list_confluence_pages(
    space_key: str = Field(description="The Confluence space key to list pages from, e.g. 'PROD' (see bugasura_list_confluence_spaces)."),
    confluence_url: str = Field(default="", description="The Confluence site URL, e.g. 'https://acme.atlassian.net'. Omit to use the project's saved Confluence integration."),
    user_email: str = Field(default="", description="The Confluence account email. Omit to use the project's saved Confluence integration."),
    api_token: str = Field(default="", description="The Confluence API token. Ask the user — never guess or reuse one. Omit to use the project's saved Confluence integration."),
    start_at: int = Field(default=0, description="Pagination offset (default: 0)", ge=0),
    max_results: int = Field(default=_KB_CONNECTOR_PAGE_SIZE, description=f"Number of pages to return (default: {_KB_CONNECTOR_PAGE_SIZE})", ge=1, le=100),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    response_format: Literal["json", "markdown"] = Field(default="json", description="Output format: 'json' (structured dict) or 'markdown' (human-readable text)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    List the pages of a Confluence space.

    Reads /v1/confluence/getPagesBySpace, which pages through Confluence's content search
    for that space, ordered by title.

    Args:
        space_key: The space to list
        confluence_url / user_email / api_token: Confluence credentials (all three, or none)
        start_at / max_results: Pagination window
        team_id / project_id: Resolved interactively if omitted
        response_format: 'json' or 'markdown'
        api_key: User's Bugasura API key

    Returns:
        dict: Standard pagination envelope whose items are {'page_id', 'page_title',
        'page_url'}, plus 'pages', 'space_key' and 'message'.
        OR a selection prompt / failure envelope.

    Examples:
        list_confluence_pages(space_key="PROD", confluence_url="https://acme.atlassian.net",
                              user_email="qa@acme.dev", api_token="...")
    """
    context = await _connector_context(api_key, team_id, project_id,
                                       'bugasura_list_confluence_pages',
                                       'list_confluence_pages', f', space_key="{space_key}"')
    if context.get('status') != 'OK':
        return _respond(context, response_format)
    api_key, team_id, project_id = context['api_key'], context['team_id'], context['project_id']

    supplied = [value for value in (confluence_url, user_email, api_token) if value.strip()]
    if supplied and len(supplied) < 3:
        return _respond(_fail('Incomplete Confluence credentials',
                              'Pass confluence_url, user_email and api_token together, or leave '
                              'all three out to use the project\'s saved Confluence '
                              'integration.'), response_format)

    credentials = (_confluence_credentials(confluence_url.strip(), user_email, api_token)
                   if supplied else {})
    pages_response = await _fetch_confluence_pages(api_key, team_id, project_id, credentials,
                                                   space_key)
    if pages_response.get('status') != 'OK':
        return _respond(pages_response, response_format)

    pages = pages_response['pages']
    page = pages[start_at:start_at + max_results]

    message = f"{len(pages)} page(s) in the Confluence space '{space_key}'."
    if not pages:
        message = f"The Confluence space '{space_key}' has no pages to import."

    logger.info(f"list_confluence_pages: Returning {len(page)} of {len(pages)} page(s) of "
                f"space '{space_key}'")
    return _respond(_paginated(page, total=len(pages), offset=start_at, pages=page,
                               space_key=space_key, message=message), response_format)


@mcp.tool(
    name="bugasura_import_confluence_to_knowledge_base",
    description=(
        "Import Confluence pages into a Bugasura project's Knowledge Base — the Knowledge Base "
        "page's 'Confluence Import' action. Bugasura pulls the selected spaces in and turns them "
        "into searchable project context, one page tree per Confluence space. "
        "Ask the user for their Confluence site URL, account email and API token, then which "
        "spaces to import — bugasura_list_confluence_spaces shows what is available. Whole "
        "spaces are imported unless page_ids names specific pages, which needs a single space. "
        "By default this creates a new Knowledge Base document; pass document_identifier to add "
        "the pages to an existing document instead. "
        "The import runs in the background — this returns as soon as it is queued, and "
        "bugasura_list_knowledge_base_documents shows its progress in `stage`."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def import_confluence_to_knowledge_base(
    confluence_url: str = Field(description="The Confluence site URL, e.g. 'https://acme.atlassian.net'."),
    user_email: str = Field(description="The Confluence account email."),
    api_token: str = Field(description="The Confluence API token. Ask the user — never guess or reuse one."),
    space_keys: List[str] = Field(default=[], description="Confluence space keys or space names to import, e.g. ['PROD', 'Engineering'] (see bugasura_list_confluence_spaces). Omit to import every space the account can see — check with the user before doing that."),
    page_ids: List[str] = Field(default=[], description="Import only these pages, by page id or page title (see bugasura_list_confluence_pages). Needs exactly one space in space_keys, since a page id only identifies a page within its space. Omit to import whole spaces."),
    document_identifier: Optional[str] = Field(default=None, description="Add the pages to this existing Knowledge Base document instead of creating a new one — its name or its kb_id (see bugasura_list_knowledge_base_documents). Only a page document accepts an import; an uploaded file does not."),
    folder_name: Optional[str] = Field(default=None, description="Knowledge base folder to import into (or, with document_identifier, the folder to look the document up in). Matched case-insensitively; created at root level when no folder has that name. Omit to use the project's first knowledge base folder."),
    folder_id: Optional[int] = Field(default=None, description="Knowledge base folder identifier. Use only when the user picked a specific folder from a list — folder_name is the normal way to target a folder.", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Import Confluence pages into a project's knowledge base.

    Posts to /v1/knowledgebase/add with `kbType=confluence` and a `toolsConnectionDetails`
    payload of the credentials plus `spaceDetails` (keyed by space key, each with the
    chosen page ids or the "all" marker), mirroring the web app's Confluence Import modal.
    The API creates one page per Confluence space, flags them pending and queues the
    `import_confluence_kb` worker, which fetches the content in the background.

    With `document_identifier` the same payload goes to /v1/knowledgebase/importDocPages
    instead, which merges the selection into an existing page document.

    Args:
        confluence_url / user_email / api_token: Confluence credentials
        space_keys: Spaces to import (empty imports every visible space)
        page_ids: Restrict a single space's import to these pages
        document_identifier: Import into this existing page document instead of a new one
        folder_name: Folder to import into, or to scope the document lookup to
        folder_id: Explicit folder identifier (takes precedence over folder_name)
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'kb_id': int,
            'kb_ids': [int],              # new-document imports only
            'imported_spaces': [{'space_key', 'space_name', 'page_count', 'all_pages'}],
            'folder_id': int,             # new-document imports only
            'folder_name': str,
            'folder_created': bool,
            'document_url': str,
            'knowledge_base_url': str,
            'message': str,
            'next_step': str
        }
        OR a selection prompt / failure envelope.

    Examples:
        # A whole space into a new document
        import_confluence_to_knowledge_base(confluence_url="https://acme.atlassian.net",
                                            user_email="qa@acme.dev", api_token="...",
                                            space_keys=["PROD"])

        # Specific pages, added to an existing document
        import_confluence_to_knowledge_base(confluence_url="https://acme.atlassian.net",
                                            user_email="qa@acme.dev", api_token="...",
                                            space_keys=["PROD"],
                                            page_ids=["Checkout flow", "Refunds"],
                                            document_identifier="Product Docs")
    """
    context = await _connector_context(api_key, team_id, project_id,
                                       'bugasura_import_confluence_to_knowledge_base',
                                       'import_confluence_to_knowledge_base',
                                       f', confluence_url="{confluence_url}", '
                                       f'space_keys={space_keys}')
    if context.get('status') != 'OK':
        return context
    api_key, team_id, project_id = context['api_key'], context['team_id'], context['project_id']

    invalid_url = _require_http_url(confluence_url.strip(), 'confluence_url',
                                    'https://acme.atlassian.net')
    if invalid_url:
        return invalid_url

    credentials = _confluence_credentials(confluence_url.strip(), user_email, api_token)

    # The API needs each space's display name, so the space list is fetched even when the
    # caller already knows the keys.
    spaces_response = await _fetch_confluence_spaces(api_key, team_id, project_id, credentials)
    if spaces_response.get('status') != 'OK':
        return spaces_response

    selection = _select_items(space_keys, spaces_response['spaces'], 'space_key', 'space_name',
                              'Confluence spaces', 'bugasura_list_confluence_spaces')
    if selection.get('status') != 'OK':
        return selection
    selected_spaces = selection['items']

    connection_details = await _confluence_connection_details(api_key, team_id, project_id,
                                                              credentials, selected_spaces,
                                                              page_ids)
    if connection_details.get('status') != 'OK':
        return connection_details
    payload = connection_details['payload']

    imported_spaces = [{
        'space_key': key,
        'space_name': details['spaceName'],
        'page_count': details['totalPageCount'],
        'all_pages': details['pageId'] == _KB_IMPORT_ALL,
    } for key, details in payload['spaceDetails'].items()]

    if document_identifier:
        target = await _resolve_import_target_page(api_key, team_id, project_id,
                                                   document_identifier, None,
                                                   folder_id, folder_name)
        if target.get('status') != 'OK':
            return target

        kb_id = target['document']['kb_id']
        response = await _submit_doc_page_import(api_key, team_id, project_id, kb_id,
                                                 target['page']['page_id'], 'confluence',
                                                 tools_connection_details=payload)
        if response.get('status') != 'OK':
            logger.error(f"import_confluence_to_knowledge_base: Import into kb_id={kb_id} "
                         f"failed: {response.get('message')}")
            return response

        response['kb_id'] = kb_id
        response['doc_name'] = target['doc_name']
        response['message'] = (f"Started importing {len(imported_spaces)} Confluence space(s) "
                               f"into the document '{target['doc_name']}'.")
    else:
        folder = await _resolve_kb_folder(api_key, team_id, project_id, folder_id, folder_name)
        if folder.get('status') != 'OK':
            return folder

        response = await _submit_kb_import(api_key, team_id, project_id, 'confluence', payload,
                                           folder)
        if response.get('status') != 'OK':
            return response

        folder_phrase = (f"a new folder '{folder['folder_name']}'" if folder.get('created')
                         else f"the '{folder['folder_name']}' folder")
        response['message'] = (f"Started importing {len(imported_spaces)} Confluence space(s) "
                               f"into {folder_phrase}: "
                               f"{', '.join(s['space_key'] for s in imported_spaces)}.")

    response['imported_spaces'] = imported_spaces

    document_url = _kb_document_url(project_id, response.get('kb_id'))
    if document_url:
        response['document_url'] = document_url
    if WEB_BASE_URL:
        knowledge_base_url = f"{WEB_BASE_URL}knowledgeBase/{project_id}"
        response['knowledge_base_url'] = knowledge_base_url
        response['message'] += f" You can watch it here: {document_url or knowledge_base_url}"

    response['next_step'] = (
        "The import runs in the background and can take a while on a large space — do not wait "
        "on it. Tell the user it has started and share the link. If they ask how far along it "
        "is, call bugasura_list_knowledge_base_documents and read the entry's `stage`: "
        "IMPORT_PAGES or CONNECTED means it is still working, PROCESSED means the pages are "
        "searchable, ERROR means the import failed."
    )

    logger.info(f"import_confluence_to_knowledge_base: Queued kb_id={response.get('kb_id')} for "
                f"{len(imported_spaces)} Confluence space(s)")
    return response

@mcp.tool(
    name="bugasura_import_figma_to_knowledge_base",
    description=(
        "Import Figma frames into a Bugasura project's Knowledge Base — the Knowledge Base "
        "page's 'Figma Import' action. Each frame is rendered to an image and stored as design "
        "context for the project. "
        "Ask the user for a Figma personal access token (Figma → Settings → Security → Personal "
        "access tokens) and for the frame links — each link must point at a *frame*, i.e. carry "
        "a node-id, which is what 'Copy link to selection' gives. A link to a whole file is "
        "rejected. "
        "IMPORTANT: Bugasura stores one set of Figma frames per project, and an import rewrites "
        "that set. This tool keeps the frames already there by default; set replace_existing=True "
        "only when the user has said they want the previous frames removed."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def import_figma_to_knowledge_base(
    figma_api_key: str = Field(description="The user's Figma personal access token (Figma → Settings → Security → Personal access tokens). Never guess or reuse one — ask the user each time."),
    figma_urls: List[str] = Field(description=f"Figma frame links, e.g. ['https://www.figma.com/design/aBc123/Checkout?node-id=1-2']. Each must carry a node-id — use Figma's 'Copy link to selection' on the frame. Up to {_KB_FIGMA_MAX_URLS} per call."),
    replace_existing: bool = Field(default=False, description="Remove the project's existing Figma frames instead of keeping them (default: False). Only set True when the user explicitly asks to replace what is already imported — this deletes those knowledge base entries."),
    folder_name: Optional[str] = Field(default=None, description="Knowledge base folder to import into. Matched case-insensitively; created at root level when no folder has that name. Omit to use the project's first knowledge base folder."),
    folder_id: Optional[int] = Field(default=None, description="Knowledge base folder identifier. Use only when the user picked a specific folder from a list — folder_name is the normal way to target a folder.", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Import Figma frames into a project's knowledge base.

    Each link is resolved against the Figma REST API for the frame's name and a temporary
    PNG export link — the same two calls the web app's own controller makes — and the
    resulting list is posted to /v1/knowledgebase/add with `kbType=figma`. Bugasura
    downloads each export link server-side while handling the request.

    The API treats the posted list as the project's complete set of Figma entries and
    deletes every stored entry missing from it, so unless `replace_existing` is set the
    existing links are read back first (`_fetch_existing_figma_links`) and carried
    forward. A link already stored is not re-downloaded upstream, so carrying them costs
    nothing.

    Args:
        figma_api_key: The user's Figma personal access token
        figma_urls: Frame links (each with a node-id)
        replace_existing: Drop the project's existing Figma entries (DESTRUCTIVE)
        folder_name: Folder to import into (created when it does not exist)
        folder_id: Explicit folder identifier (takes precedence over folder_name)
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'kb_ids': [int],
            'imported_frames': [{'frame_name', 'figma_url'}],   # newly added only
            'already_imported_frames': int,  # links that were already stored
            'kept_frames': int,          # existing entries carried forward
            'removed_frames': int,       # existing entries deleted (replace_existing only)
            'folder_id': int,
            'folder_name': str,
            'folder_created': bool,
            'knowledge_base_url': str,
            'message': str,
            'next_step': str
        }
        OR a selection prompt / failure envelope.

    Examples:
        # Add two frames, keeping whatever is already imported
        import_figma_to_knowledge_base(
            figma_api_key="figd_...",
            figma_urls=["https://www.figma.com/design/aBc123/Checkout?node-id=1-2",
                        "https://www.figma.com/design/aBc123/Checkout?node-id=5-9"])

        # Replace the project's Figma set with one frame
        import_figma_to_knowledge_base(figma_api_key="figd_...",
                                       figma_urls=["https://www.figma.com/design/aBc123/Checkout?node-id=1-2"],
                                       replace_existing=True)
    """
    context = await _connector_context(api_key, team_id, project_id,
                                       'bugasura_import_figma_to_knowledge_base',
                                       'import_figma_to_knowledge_base',
                                       f', figma_urls={figma_urls}')
    if context.get('status') != 'OK':
        return context
    api_key, team_id, project_id = context['api_key'], context['team_id'], context['project_id']

    urls = [url.strip() for url in figma_urls if url and url.strip()]
    if not urls:
        return _fail('figma_urls is required',
                     "Ask the user for the Figma frame link(s) to import — right-click the frame "
                     "in Figma and choose 'Copy link to selection'.")
    if len(urls) > _KB_FIGMA_MAX_URLS:
        return _fail('Too many Figma links',
                     f"{len(urls)} links were given; a Figma import takes at most "
                     f"{_KB_FIGMA_MAX_URLS} per call. Split them across several calls.")

    # Resolve every frame before touching Bugasura, so a bad link never rewrites the
    # project's Figma set.
    frames = []
    for url in urls:
        frame_response = await _fetch_figma_frame(figma_api_key, url)
        if frame_response.get('status') != 'OK':
            return _with_hint(frame_response, f"This was the link '{url}'. Nothing has been "
                                              f"imported.")
        frames.append(frame_response['frame'])

    existing = await _fetch_existing_figma_links(api_key, team_id, project_id)
    if existing.get('status') != 'OK':
        return existing
    existing_entries = existing['entries']

    new_links = {frame['imageLink'] for frame in frames}
    existing_links = {entry['imageLink'] for entry in existing_entries}
    carried_over = [entry for entry in existing_entries if entry['imageLink'] not in new_links]
    # A frame already stored is not imported again — the API skips the link it already has —
    # so it is reported as such rather than counted as new.
    added = [frame for frame in frames if frame['imageLink'] not in existing_links]

    payload = [{'name': frame['name'], 'imageLink': frame['imageLink'],
                'exportLink': frame['exportLink'], 'apiKey': frame['apiKey']}
               for frame in frames]
    if not replace_existing:
        # Re-listing a stored link keeps its entry: the API skips re-downloading it and,
        # crucially, does not delete it.
        payload += [{'name': entry['doc_name'], 'imageLink': entry['imageLink'],
                     'exportLink': '', 'apiKey': entry['apiKey'] or figma_api_key}
                    for entry in carried_over]

    folder = await _resolve_kb_folder(api_key, team_id, project_id, folder_id, folder_name)
    if folder.get('status') != 'OK':
        return folder

    response = await _submit_kb_import(api_key, team_id, project_id, 'figma', payload, folder,
                                       kb_source=_KB_FIGMA_SOURCE,
                                       kb_source_type=_KB_FIGMA_SOURCE_TYPE)
    if response.get('status') != 'OK':
        return response

    response['imported_frames'] = [{'frame_name': f['name'], 'figma_url': f['imageLink']}
                                   for f in added]
    response['already_imported_frames'] = len(frames) - len(added)
    response['kept_frames'] = 0 if replace_existing else len(carried_over)
    response['removed_frames'] = len(carried_over) if replace_existing else 0

    folder_phrase = (f"a new folder '{folder['folder_name']}'" if folder.get('created')
                     else f"the '{folder['folder_name']}' folder")
    response['message'] = (
        f"Imported {len(added)} Figma frame(s) into {folder_phrase}: "
        f"{', '.join(f['name'] for f in added)}." if added
        else "Every frame given was already in the knowledge base; nothing new was imported."
    )
    if response['already_imported_frames']:
        response['message'] += (f" {response['already_imported_frames']} of the frame(s) given "
                                f"were already there.")
    if replace_existing and carried_over:
        response['message'] += (f" {len(carried_over)} previously imported frame(s) were "
                                f"removed.")
    elif carried_over:
        response['message'] += f" {len(carried_over)} previously imported frame(s) were kept."

    if WEB_BASE_URL:
        knowledge_base_url = f"{WEB_BASE_URL}knowledgeBase/{project_id}"
        response['knowledge_base_url'] = knowledge_base_url
        response['message'] += f" You can view them here: {knowledge_base_url}"

    response['next_step'] = (
        "Tell the user which frames landed in the knowledge base and share "
        "knowledge_base_url. Bugasura downloads and processes the images in the background, so "
        "there is nothing else to do now. Ask whether they'd like to add more frames."
    )

    logger.info(f"import_figma_to_knowledge_base: Imported {len(added)} of {len(frames)} frame(s) "
                f"into project_id={project_id} (kept={response['kept_frames']}, "
                f"removed={response['removed_frames']})")
    return response

@mcp.tool(
    name="bugasura_import_file_to_knowledge_base_document",
    description=(
        "Import a Markdown, CSV or Excel file into an existing Bugasura Knowledge Base document "
        "— the document editor's 'Import' menu. "
        "A .md file becomes a NEW page in the document, named after the file. A .csv/.xlsx/.xls "
        "file is converted to a Markdown table and APPENDED to one existing page — pass "
        "page_identifier to say which, or the document's first page is used. "
        "TWO WAYS TO PROVIDE THE FILE — pick ONE per call: (1) file_path — an absolute path on "
        "the machine running this server (terminal/CLI use); ask the user for the exact path, "
        "never guess it. (2) source_url — a Google Drive / Dropbox / public download link. Never "
        "read, encode, or convert the file yourself. "
        "To add a document to the knowledge base as a file in its own right, use "
        "bugasura_upload_knowledge_base_document instead."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def import_file_to_knowledge_base_document(
    document_identifier: str = Field(description="The Knowledge Base document to import into — its name or its kb_id (see bugasura_list_knowledge_base_documents). Must be a page document; an uploaded file has no pages to import into."),
    file_path: Optional[str] = Field(default=None, description="Absolute path on the MCP server's local filesystem (terminal/CLI use). Ask the user for the exact path — never construct or guess it. Must be a .md, .csv, .xlsx or .xls file."),
    source_url: Optional[str] = Field(default=None, description="Google Drive share link, Dropbox share link, or any public direct download URL. The MCP server fetches the file — no encoding needed. IMPORTANT: a Google Drive link must be set to 'Anyone with the link'."),
    source_url_filename: Optional[str] = Field(default=None, description="Original filename with extension (e.g. 'metrics.csv'). Optional — inferred from the URL path when omitted. Only pass it if auto-detection fails or the user names the file."),
    page_identifier: Optional[str] = Field(default=None, description="For a CSV/Excel import, the page to append the table to — its name or its page id (see bugasura_list_knowledge_base_pages). Omit to use the document's first page. Ignored for a Markdown import, which always creates its own page."),
    folder_name: Optional[str] = Field(default=None, description="Knowledge base folder the document lives in. Only needed when the same document name exists in more than one folder."),
    folder_id: Optional[int] = Field(default=None, description="Knowledge base folder identifier. Use only when the user picked a specific folder from a list — folder_name is the normal way to target a folder.", ge=1),
    team_id: Optional[int] = Field(default=None, description="Team identifier (optional - will prompt if not provided, ge=1)"),
    project_id: Optional[int] = Field(default=None, description="Project identifier (optional - will prompt if not provided, ge=1)"),
    api_key: str = Field(default="", description="User's Bugasura API key. If not provided, uses BUGASURA_API_KEY from environment.")
) -> ToolResponse:
    """
    Import a Markdown, CSV or Excel file into an existing knowledge base page document.

    Posts to /v1/knowledgebase/importDocPages as multipart/form-data with the file in the
    `importFile` field; the `importType` follows from the extension (`md_file`,
    `csv_file`, `excel_file`).

    A CSV/Excel import *appends* its table to the target page, and the API rebuilds that
    page from the `pageContent` it is handed — so the page's current markdown is read back
    off the CDN first and sent along, the same read-modify-write every page edit in this
    server does. A page whose content cannot be read is refused rather than overwritten.

    Args:
        document_identifier: The page document to import into
        file_path: Absolute local path to the .md/.csv/.xlsx/.xls file
        source_url: Public/share link the server downloads the file from
        source_url_filename: Original filename for source_url when it cannot be detected
        page_identifier: Page a CSV/Excel table is appended to (first page when omitted)
        folder_name / folder_id: Scope the document lookup to one folder
        team_id / project_id: Resolved interactively if omitted
        api_key: User's Bugasura API key

    Returns:
        dict: {
            'status': 'OK',
            'kb_id': int,
            'doc_name': str,
            'import_type': str,          # 'md_file' | 'csv_file' | 'excel_file'
            'imported_file': str,
            'created_page': {...},       # Markdown imports only
            'target_page': {...},        # CSV/Excel imports only
            'pages': [...],              # the document's pages after the import
            'document_url': str,
            'message': str,
            'next_step': str
        }
        OR a selection prompt / failure envelope.

    Examples:
        # A Markdown file as a new page
        import_file_to_knowledge_base_document(document_identifier="Product Docs",
                                               file_path="/home/me/release-notes.md")

        # A spreadsheet appended to a named page
        import_file_to_knowledge_base_document(document_identifier="Product Docs",
                                               file_path="/home/me/metrics.xlsx",
                                               page_identifier="Metrics")
    """
    context = await _connector_context(api_key, team_id, project_id,
                                       'bugasura_import_file_to_knowledge_base_document',
                                       'import_file_to_knowledge_base_document',
                                       f', document_identifier="{document_identifier}"')
    if context.get('status') != 'OK':
        return context
    api_key, team_id, project_id = context['api_key'], context['team_id'], context['project_id']

    # Need exactly one content source.
    if not file_path and not source_url:
        return _fail('No file provided',
                     'Ask the user how they want to provide the file. In the terminal, ask for '
                     'the exact absolute path and pass file_path=... Elsewhere, ask them to '
                     'share a Google Drive or Dropbox link ("Anyone with the link") and pass '
                     'source_url=<link>. Never read or encode the file yourself.')
    if file_path and source_url:
        return _fail('Multiple content sources provided',
                     'Provide either file_path or source_url per call, not both.')

    # Read the file first, so a bad path or unsupported type never touches the document.
    collected = await asyncio.to_thread(
        _collect_doc_import_file, file_path, source_url, source_url_filename)
    if collected.get('status') != 'OK':
        return collected
    import_type = collected['import_type']

    target = await _resolve_import_target_page(api_key, team_id, project_id, document_identifier,
                                               page_identifier, folder_id, folder_name)
    if target.get('status') != 'OK':
        return target

    kb_id = target['document']['kb_id']
    page = target['page']

    # A table import replaces the page with "what was there + the table", so what was
    # there has to be read first — a blind write would drop the page's body.
    page_content = None
    if import_type in ('csv_file', 'excel_file'):
        content_response = await asyncio.to_thread(_read_kb_page_content, page)
        if content_response.get('status') != 'OK':
            return _with_hint(content_response,
                              "The table is appended to this page's existing content, so the "
                              "import is not run until that content can be read. Nothing has "
                              "been changed.")
        page_content = content_response['content']

    response = await _submit_doc_page_import(api_key, team_id, project_id, kb_id,
                                             page['page_id'], import_type,
                                             page_content=page_content,
                                             files=collected['files'])
    if response.get('status') != 'OK':
        logger.error(f"import_file_to_knowledge_base_document: Import of "
                     f"'{collected['filename']}' into kb_id={kb_id} failed: "
                     f"{response.get('message')}")
        return response

    pages = _pages_from_update_response(response, kb_id)
    response['kb_id'] = kb_id
    response['doc_name'] = target['doc_name']
    response['import_type'] = import_type
    response['imported_file'] = collected['filename']
    response['pages'] = _normalise_kb_pages(pages)

    if import_type == 'md_file':
        created = response.get('pageDetails') or {}
        response['created_page'] = {'page_id': created.get('page_id'),
                                    'page_name': created.get('page_name', '')}
        response['message'] = (f"Imported '{collected['filename']}' into the document "
                               f"'{target['doc_name']}' as a new page "
                               f"'{response['created_page']['page_name']}'.")
    else:
        response['target_page'] = {'page_id': page.get('page_id'),
                                   'page_name': page.get('page_name', '')}
        response['message'] = (f"Appended '{collected['filename']}' as a table to the page "
                               f"'{page.get('page_name', '')}' in the document "
                               f"'{target['doc_name']}'.")

    document_url = _kb_document_url(project_id, kb_id)
    if document_url:
        response['document_url'] = document_url
        response['message'] += f" You can view it here: {document_url}"

    response['next_step'] = (
        "Tell the user in plain language where the content landed and share document_url. "
        "Read the result back with bugasura_get_knowledge_base_page_content if they want to "
        "check it, and edit it with bugasura_update_knowledge_base_page_content."
    )

    logger.info(f"import_file_to_knowledge_base_document: Imported '{collected['filename']}' "
                f"({import_type}) into kb_id={kb_id}")
    return response


def _flatten_kb_folders(nodes: Any, parent_folder_id: Any = '') -> list:
    """
    Flatten the nested KB folder structure returned by /v1/projectFolders/get.

    The upstream `tcRepoStructure` is a tree of {id, name, parent_id, children};
    a flat list makes name lookups match sub-folders too, not just root folders.

    Returns:
        list: [{'folder_id': int, 'folder_name': str, 'parent_folder_id': Any, 'kb_count': int}]
    """
    folders = []
    for node in nodes or []:
        if not isinstance(node, dict):
            continue
        folder_id = node.get('id')
        if folder_id is None or folder_id == '':
            continue
        folders.append({
            'folder_id': folder_id,
            'folder_name': node.get('name', ''),
            'parent_folder_id': node.get('parent_id') or parent_folder_id or '',
            'kb_count': node.get('kb_count', 0),
        })
        folders.extend(_flatten_kb_folders(node.get('children'), folder_id))
    return folders


async def _fetch_kb_folders(api_key: str, team_id: int, project_id: int) -> dict:
    """
    Fetch the project's knowledge base folders as a flat list.

    Returns:
        dict: {'status': 'OK', 'folders': [...]} — an empty list when the project
        has no knowledge base folder yet — or a failure envelope.
    """
    response = await make_api_request('GET', '/v1/projectFolders/get', api_key, params={
        'appId': str(project_id),
        'teamId': str(team_id),
        'folderId': '',
        'parentFolderId': '',
        'isGetReportList': 0,
        'folderType': _KB_FOLDER_TYPE,
    })

    if response.get('status') != 'OK':
        logger.error(f"_fetch_kb_folders: Failed to fetch KB folders for project_id={project_id}: "
                     f"{response.get('message')}")
        return {
            'status': 'failed',
            'error': 'Failed to fetch knowledge base folders',
            'error_type': 'FolderFetchError',
            'message': response.get('message', 'Could not retrieve the knowledge base folder list')
        }

    folders = _flatten_kb_folders(response.get('tcRepoStructure', []))
    logger.info(f"_fetch_kb_folders: Found {len(folders)} knowledge base folder(s) for project_id={project_id}")
    return {'status': 'OK', 'folders': folders}


async def _create_kb_folder(api_key: str, team_id: int, project_id: int, folder_name: str,
                            parent_folder_id: int = 0) -> dict:
    """
    Create a knowledge base folder, reusing the existing one on a name clash.

    The API rejects a duplicate name at the same level. Its inner handler builds
    `existingFolderId`/`existingFolderDetails` for exactly this case, but the /add wrapper
    returns only {status, message} on a non-OK status, so those keys never reach us — the
    duplicate is instead resolved by re-listing the folders and matching by name. That also
    covers a folder created between the caller's lookup and this call, so a race does not
    fail the upload.

    The folder name is read back from the stored row rather than echoed from the request:
    the API sanitises names (stripping quotes and backticks) before insert, so the two can
    differ and a later name-based lookup would miss.

    Returns:
        dict: {'status': 'OK', 'folder_id': int, 'folder_name': str, 'created': bool}
        or a failure envelope.
    """
    # The API expects an empty parentFolderId (not 0) for root-level folders.
    is_root_folder = 1 if not parent_folder_id else 0

    logger.info(f"_create_kb_folder: Creating knowledge base folder '{folder_name}' for "
                f"project_id={project_id}, parent_folder_id={parent_folder_id or 'root'}")

    response = await make_api_request('POST', '/v1/projectFolders/add', api_key, data={
        'appId': str(project_id),
        'teamId': str(team_id),
        'folderName': folder_name,
        'parentFolderId': '' if is_root_folder else str(parent_folder_id),
        'isRootFolder': is_root_folder,
        'folderType': _KB_FOLDER_TYPE,
    })

    if response.get('status') == 'OK':
        created = response.get('folderDetails', {}) or {}
        created_folder_id = created.get('id')
        logger.info(f"_create_kb_folder: Created folder '{folder_name}' with folder_id={created_folder_id}")
        return {
            'status': 'OK',
            'folder_id': created_folder_id,
            # Read the stored name back — the API sanitises it before insert.
            'folder_name': created.get('name') or created.get('folder_name') or folder_name,
            'created': True
        }

    # A name clash comes back as a plain error (see the docstring), so find the existing
    # folder ourselves. The clash is per parent level — the same name may legitimately
    # exist elsewhere in the tree — so match the parent too, exactly as the API does.
    listed = await _fetch_kb_folders(api_key, team_id, project_id)
    if listed.get('status') == 'OK':
        wanted_parent = '' if is_root_folder else str(parent_folder_id)
        wanted_name = folder_name.strip().casefold()
        for folder in listed['folders']:
            if (str(folder.get('parent_folder_id') or '') == wanted_parent
                    and str(folder.get('folder_name') or '').strip().casefold() == wanted_name):
                logger.info(f"_create_kb_folder: Folder '{folder_name}' already exists "
                            f"(folder_id={folder['folder_id']}), reusing it")
                return {
                    'status': 'OK',
                    'folder_id': folder['folder_id'],
                    'folder_name': folder.get('folder_name') or folder_name,
                    'created': False
                }

    logger.error(f"_create_kb_folder: Failed to create folder '{folder_name}': {response.get('message')}")
    return {
        'status': 'failed',
        'error': 'Failed to create knowledge base folder',
        'error_type': 'FolderCreateError',
        'message': f"Could not create the knowledge base folder '{folder_name}': "
                   f"{response.get('message', 'Unknown error')}"
    }


async def _resolve_project_team_id(api_key: str, team_id: int, project_id: int,
                                   caller: str) -> int:
    """
    Return the team the project actually belongs to.

    A project may live in a different team than the one the context selection picked,
    and the folder / knowledge base endpoints validate against the project's own team.
    Falls back to the given team_id when the project details cannot be read.
    """
    response = await make_api_request('GET', '/v1/projects/get', api_key, params={
        'team_id': team_id,
        'project_id': project_id
    })

    if response.get('status') != 'OK':
        logger.warning(f"{caller}: Could not verify team_id from project details, "
                       f"proceeding with team_id={team_id}")
        return team_id

    project_team_id = response.get('project_details', {}).get('team_id')
    if project_team_id and project_team_id != team_id:
        logger.warning(f"{caller}: Team ID mismatch - context team_id={team_id}, "
                       f"project team_id={project_team_id}. Using project's team_id.")
        return project_team_id
    return team_id


def _with_hint(failure: dict, hint: str) -> dict:
    """Append a caller-specific next-action hint to a failure envelope's message."""
    failure['message'] = f"{failure.get('message', '')} {hint}".strip()
    return failure


async def _find_kb_folder(api_key: str, team_id: int, project_id: int,
                          folder_id: Optional[int] = None, folder_name: Optional[str] = None,
                          role: str = 'folder') -> dict:
    """
    Find an existing knowledge base folder by id or name. Never creates one.

    `folder_id` wins over `folder_name`; names are matched case-insensitively anywhere
    in the folder tree. `role` names the folder in error messages ('folder',
    'parent folder'), so callers can report which of their arguments went wrong.

    Returns:
        dict: {'status': 'OK', 'folder_id': int, 'folder_name': str, 'folders': [...]}
        or a failure envelope carrying `available_folders` / `matches`.
    """
    folders_response = await _fetch_kb_folders(api_key, team_id, project_id)
    if folders_response.get('status') != 'OK':
        return folders_response

    folders = folders_response['folders']

    if folder_id is not None:
        match = next((f for f in folders if str(f['folder_id']) == str(folder_id)), None)
        if match is None:
            logger.error(f"_find_kb_folder: folder_id={folder_id} is not a knowledge base folder "
                         f"of project_id={project_id}")
            return {
                'status': 'failed',
                'error': f'Knowledge base {role} not found',
                'error_type': 'FolderNotFound',
                'message': f"Folder {folder_id} is not a knowledge base folder of project {project_id}.",
                'available_folders': folders
            }
        return {'status': 'OK', 'folder_id': match['folder_id'],
                'folder_name': match['folder_name'], 'folders': folders}

    if folder_name and folder_name.strip():
        wanted_name = folder_name.strip()
        matches = [f for f in folders
                   if (f['folder_name'] or '').strip().lower() == wanted_name.lower()]

        if len(matches) == 1:
            logger.info(f"_find_kb_folder: Matched {role} '{wanted_name}' to "
                        f"folder_id={matches[0]['folder_id']}")
            return {'status': 'OK', 'folder_id': matches[0]['folder_id'],
                    'folder_name': matches[0]['folder_name'], 'folders': folders}

        if len(matches) > 1:
            logger.warning(f"_find_kb_folder: {len(matches)} folders named '{wanted_name}' in "
                           f"project_id={project_id}")
            return {
                'status': 'failed',
                'error': 'Multiple knowledge base folders match',
                'error_type': 'AmbiguousFolderName',
                'message': f"{len(matches)} knowledge base folders are named '{wanted_name}'. "
                           f"Ask the user which one they mean.",
                'matches': matches
            }

        logger.info(f"_find_kb_folder: No knowledge base folder named '{wanted_name}' in "
                    f"project_id={project_id}")
        return {
            'status': 'failed',
            'error': f'Knowledge base {role} not found',
            'error_type': 'FolderNotFound',
            'message': f"No knowledge base folder named '{wanted_name}' in project {project_id}.",
            'available_folders': folders
        }

    return {
        'status': 'failed',
        'error': f'No knowledge base {role} given',
        'error_type': 'ValidationError',
        'message': f"Provide the {role} to act on, by name or by id.",
        'available_folders': folders
    }


async def _resolve_kb_folder(api_key: str, team_id: int, project_id: int,
                             folder_id: Optional[int], folder_name: Optional[str]) -> dict:
    """
    Resolve the knowledge base folder a document should be filed in, creating it when needed.

    Precedence:
    1. `folder_id` — validated against the project's knowledge base folders.
    2. `folder_name` — reused when a folder carries that name, created at root level otherwise.
    3. Neither — the project's first root-level knowledge base folder, or a newly
       created default folder (_KB_DEFAULT_FOLDER_NAME) when the project has none.

    Returns:
        dict: {'status': 'OK', 'folder_id': int, 'folder_name': str, 'created': bool}
        or a failure envelope.
    """
    if folder_id is not None or (folder_name and folder_name.strip()):
        found = await _find_kb_folder(api_key, team_id, project_id, folder_id, folder_name)
        if found.get('status') == 'OK':
            return {'status': 'OK', 'folder_id': found['folder_id'],
                    'folder_name': found['folder_name'], 'created': False}

        # An unknown *name* is the create case; anything else is a real failure.
        if found.get('error_type') != 'FolderNotFound' or folder_id is not None:
            if folder_id is not None:
                return _with_hint(found, "Pass folder_name instead and the folder will be "
                                         "created if needed.")
            return found

        logger.info(f"_resolve_kb_folder: Creating missing folder '{folder_name.strip()}'")
        return await _create_kb_folder(api_key, team_id, project_id, folder_name.strip())

    # No folder given — reuse the first existing folder, else create the default one.
    folders_response = await _fetch_kb_folders(api_key, team_id, project_id)
    if folders_response.get('status') != 'OK':
        return folders_response

    folders = folders_response['folders']
    root_folders = [f for f in folders if not f['parent_folder_id']]
    existing_folders = root_folders or folders
    if existing_folders:
        chosen = existing_folders[0]
        logger.info(f"_resolve_kb_folder: No folder specified, using existing folder "
                    f"'{chosen['folder_name']}' (folder_id={chosen['folder_id']})")
        return {'status': 'OK', 'folder_id': chosen['folder_id'],
                'folder_name': chosen['folder_name'], 'created': False}

    logger.info(f"_resolve_kb_folder: Project {project_id} has no knowledge base folder, "
                f"creating '{_KB_DEFAULT_FOLDER_NAME}'")
    return await _create_kb_folder(api_key, team_id, project_id, _KB_DEFAULT_FOLDER_NAME)

def _normalise_kb_document(raw: dict, folder_names: dict,
                           include_connection_details: bool = False) -> dict:
    """
    Reduce an upstream kbDocsDetails entry to the fields tools return.

    `include_connection_details` keeps the decoded `connection_details` blob — the page
    tools need it for `pageDetails`; the listing tools leave it out because it carries the
    whole page tree of every document.
    """
    document = {
        'kb_id': raw.get('kb_id'),
        'doc_name': raw.get('doc_name', ''),
        'folder_id': raw.get('folder_id'),
        'folder_name': folder_names.get(str(raw.get('folder_id')), ''),
        'source': raw.get('source', ''),
        'source_type': raw.get('source_type', ''),
        'type': raw.get('type', ''),
        'stage': raw.get('stage', ''),
        'file_size': raw.get('file_size', ''),
        # CDN-relative path of the stored file; empty for documents that have no file of
        # their own (page documents, website entries, Jira/Confluence imports).
        'file_path': raw.get('kbFilePath', ''),
        'is_starred': str(raw.get('is_starred', '0')) == '1',
        'created_by': raw.get('created_by_name', ''),
        'created_date': raw.get('created_date', ''),
        'last_modified': raw.get('last_modified_relative') or raw.get('last_modified_date', ''),
    }
    if include_connection_details:
        # An empty connection_details decodes to [] upstream, so normalise it to a dict.
        connection_details = raw.get('connection_details')
        document['connection_details'] = connection_details if isinstance(connection_details, dict) else {}
    return document


async def _fetch_kb_documents(api_key: str, team_id: int, project_id: int,
                              folder_id: Optional[int] = None,
                              starred_only: bool = False,
                              include_connection_details: bool = False) -> dict:
    """
    Fetch the knowledge base documents of a folder (and its sub-folders), or of the
    whole project when `folder_id` is omitted.

    Returns:
        dict: {'status': 'OK', 'documents': [...], 'folders': [...]} or a failure envelope.
    """
    response = await make_api_request('GET', '/v1/knowledgebase/getDocs', api_key, params={
        'appId': str(project_id),
        'teamId': str(team_id),
        # 'ALL' asks for every knowledge base folder of the project.
        'folderId': str(folder_id) if folder_id is not None else 'ALL',
        'isStarredOnly': 1 if starred_only else 0,
    })

    if response.get('status') != 'OK':
        logger.error(f"_fetch_kb_documents: Failed to fetch KB documents for project_id={project_id}, "
                     f"folder_id={folder_id}: {response.get('message')}")
        return {
            'status': 'failed',
            'error': 'Failed to fetch knowledge base documents',
            'error_type': 'DocumentFetchError',
            'message': response.get('message', 'Could not retrieve the knowledge base documents')
        }

    folders = response.get('kbRepoFoldersDetails') or []
    folder_names = {str(folder.get('id')): folder.get('name', '') for folder in folders}
    documents = [_normalise_kb_document(doc, folder_names, include_connection_details)
                 for doc in response.get('kbDocsDetails') or []]

    logger.info(f"_fetch_kb_documents: Found {len(documents)} document(s) for project_id={project_id}, "
                f"folder_id={folder_id or 'ALL'}")
    return {'status': 'OK', 'documents': documents, 'folders': folders}


async def _find_kb_document(api_key: str, team_id: int, project_id: int,
                            document_identifier: str, folder_id: Optional[int] = None,
                            include_connection_details: bool = False) -> dict:
    """
    Resolve a document identifier to a single knowledge base document.

    Matching order: numeric kb_id → exact file name (case-insensitive) → partial file
    name. Searching is scoped to `folder_id` when given, otherwise the whole project.

    `include_connection_details` carries the decoded `connection_details` on the matched
    document, which is what the page tools read `pageDetails` from.

    Returns:
        dict: {'status': 'OK', 'document': {...}} or a failure envelope carrying
        `available_documents` / `matches`.
    """
    identifier = str(document_identifier or '').strip()
    if not identifier:
        return {
            'status': 'failed',
            'error': 'document_identifier is required',
            'error_type': 'ValidationError',
            'message': 'Provide the document id or its file name (e.g. "PRD.pdf").'
        }

    documents_response = await _fetch_kb_documents(api_key, team_id, project_id, folder_id,
                                                   include_connection_details=include_connection_details)
    if documents_response.get('status') != 'OK':
        return documents_response

    documents = documents_response['documents']

    if identifier.isdigit():
        match = next((d for d in documents if str(d['kb_id']) == identifier), None)
        if match is None:
            logger.error(f"_find_kb_document: kb_id={identifier} not found in project_id={project_id}")
            return {
                'status': 'failed',
                'error': 'Knowledge base document not found',
                'error_type': 'DocumentNotFound',
                'message': f"No knowledge base document with id {identifier} in project {project_id}. "
                           f"List the documents with bugasura_list_knowledge_base_documents.",
                'available_documents': _document_choices(documents)
            }
        return {'status': 'OK', 'document': match}

    needle = identifier.lower()
    matches = [d for d in documents if (d['doc_name'] or '').strip().lower() == needle]
    if not matches:
        matches = [d for d in documents if needle in (d['doc_name'] or '').lower()]

    if not matches:
        logger.error(f"_find_kb_document: No document matching '{identifier}' in project_id={project_id}")
        return {
            'status': 'failed',
            'error': 'Knowledge base document not found',
            'error_type': 'DocumentNotFound',
            'message': f"No knowledge base document matching '{identifier}' in project {project_id}. "
                       f"List the documents with bugasura_list_knowledge_base_documents.",
            'available_documents': _document_choices(documents)
        }

    if len(matches) > 1:
        logger.warning(f"_find_kb_document: {len(matches)} documents match '{identifier}' in "
                       f"project_id={project_id}")
        return {
            'status': 'failed',
            'error': 'Multiple knowledge base documents match',
            'error_type': 'AmbiguousDocument',
            'message': f"{len(matches)} documents match '{identifier}'. Ask the user which one, "
                       f"then pass its id.",
            'matches': _document_choices(matches)
        }

    logger.info(f"_find_kb_document: Matched '{identifier}' to kb_id={matches[0]['kb_id']}")
    return {'status': 'OK', 'document': matches[0]}


def _document_choices(documents: list) -> list:
    """Compact document list for error envelopes — enough for the user to pick one."""
    return [{'kb_id': d['kb_id'], 'doc_name': d['doc_name'], 'folder_name': d['folder_name']}
            for d in documents[:_KB_MAX_CHOICES]]


def _kb_file_url(file_path: str) -> Optional[str]:
    """
    Turn a document's CDN-relative file path into a direct download URL.

    Stored files are public objects on the CDN — the web app fetches them with a plain GET
    and hands Office documents straight to view.officeapps.live.com — so the URL needs no
    signing and works in a browser as-is. Returns None when the deployment's CDN base is
    not known (see CDN_BASE_URL in helpers).
    """
    if not CDN_BASE_URL or not file_path:
        return None
    return f"{CDN_BASE_URL}{file_path.lstrip('/')}"

def _kb_page_path(page: dict, pages_by_id: dict) -> str:
    """
    Build the 'Parent / Child / Page' breadcrumb of a page.

    Parents are followed through `parent_id`; a visited set stops a corrupted
    parent chain from looping forever.
    """
    names = [page.get('page_name', '')]
    seen = {str(page.get('page_id'))}
    parent_id = str(page.get('parent_id') or '')
    while parent_id and parent_id not in seen:
        seen.add(parent_id)
        parent = pages_by_id.get(parent_id)
        if parent is None:
            break
        names.append(parent.get('page_name', ''))
        parent_id = str(parent.get('parent_id') or '')
    return ' / '.join(reversed(names))


def _normalise_kb_page(raw: dict, pages_by_id: dict) -> dict:
    """Reduce a connection_details.pageDetails entry to the fields the page tools return."""
    parent_id = str(raw.get('parent_id') or '')
    parent = pages_by_id.get(parent_id) or {}
    page_path = _kb_page_path(raw, pages_by_id)
    return {
        'page_id': raw.get('page_id'),
        'page_name': raw.get('page_name', ''),
        'parent_page_id': parent_id,
        'parent_page_name': parent.get('page_name', ''),
        'page_path': page_path,
        # Depth of the page in the tree; 0 for a root-level page.
        'depth': page_path.count(' / '),
        # The body lives in its own S3 file — an empty path means the page has no content yet.
        'has_content': bool((raw.get('uploaded_file_path') or '').strip()),
        'created_on': raw.get('created_on', ''),
        'modified_on': raw.get('modified_on', ''),
    }


def _normalise_kb_pages(pages: list) -> list:
    """Normalise a document's whole flat page list, keeping the stored order."""
    pages_by_id = {str(p.get('page_id')): p for p in pages or [] if isinstance(p, dict)}
    return [_normalise_kb_page(p, pages_by_id) for p in pages or [] if isinstance(p, dict)]


def _page_choices(pages: list) -> list:
    """Compact page list for error envelopes — enough for the user to pick one."""
    return [{'page_id': p['page_id'], 'page_name': p['page_name'], 'page_path': p['page_path']}
            for p in _normalise_kb_pages(pages)[:_KB_MAX_CHOICES]]


def _kb_descendant_page_ids(pages: list, page_id: str) -> list:
    """
    Collect every descendant of a page, breadth-first over the `parent_id` chains.

    Mirrors the API's own removeKBDocPageById() walk, so a delete/move preview counts
    exactly the pages the upstream action would touch.
    """
    descendant_ids = []
    # `seen` holds the page itself plus everything already collected, so a corrupted
    # parent chain that loops back cannot re-add a page or spin forever.
    seen = {str(page_id)}
    frontier = {str(page_id)}
    while frontier:
        children = [str(p.get('page_id')) for p in pages
                    if str(p.get('parent_id') or '') in frontier
                    and str(p.get('page_id')) not in seen]
        if not children:
            break
        descendant_ids.extend(children)
        seen.update(children)
        frontier = set(children)
    return descendant_ids


def _find_kb_page(pages: list, page_identifier: str, role: str = 'page') -> dict:
    """
    Resolve a page identifier to a single page of a knowledge base document.

    Matching order: exact page id ('page_20250104120500') → exact page name
    (case-insensitive) → partial page name. `role` names the page in error messages
    ('page', 'parent page', 'sibling page') so callers can report which argument went wrong.

    Returns:
        dict: {'status': 'OK', 'page': {...}} — the raw stored page — or a failure
        envelope carrying `available_pages` / `matches`.
    """
    identifier = str(page_identifier or '').strip()
    if not identifier:
        return {
            'status': 'failed',
            'error': f'{role} is required'.capitalize(),
            'error_type': 'ValidationError',
            'message': f"Provide the {role} to act on, by name or by page id."
        }

    match = next((p for p in pages if str(p.get('page_id')) == identifier), None)
    if match is not None:
        return {'status': 'OK', 'page': match}

    needle = identifier.lower()
    matches = [p for p in pages if (p.get('page_name') or '').strip().lower() == needle]
    if not matches:
        matches = [p for p in pages if needle in (p.get('page_name') or '').lower()]

    if not matches:
        logger.error(f"_find_kb_page: No page matching '{identifier}' in the document")
        return {
            'status': 'failed',
            'error': f'Knowledge base {role} not found',
            'error_type': 'PageNotFound',
            'message': f"No page matching '{identifier}' in this document. List its pages with "
                       f"bugasura_list_knowledge_base_pages.",
            'available_pages': _page_choices(pages)
        }

    if len(matches) > 1:
        logger.warning(f"_find_kb_page: {len(matches)} pages match '{identifier}'")
        return {
            'status': 'failed',
            'error': f'Multiple knowledge base {role}s match',
            'error_type': 'AmbiguousPage',
            'message': f"{len(matches)} pages match '{identifier}'. Ask the user which one, "
                       f"then pass its page id.",
            'matches': _page_choices(matches)
        }

    logger.info(f"_find_kb_page: Matched '{identifier}' to page_id={matches[0].get('page_id')}")
    return {'status': 'OK', 'page': matches[0]}


async def _find_kb_page_document(api_key: str, team_id: int, project_id: int,
                                 document_identifier: str,
                                 folder_id: Optional[int] = None) -> dict:
    """
    Resolve a document identifier to a knowledge base document that holds pages.

    Uploaded files (.pdf/.docx/...), Figma files and website entries have no page tree, so
    they are rejected here rather than upstream — only the types in `_KB_PAGE_DOC_TYPES`
    store their body as `connection_details.pageDetails`.

    Returns:
        dict: {'status': 'OK', 'document': {...}, 'doc_type': str, 'doc_name': str,
        'pages': [...]} — `pages` being the raw stored page entries — or a failure envelope.
    """
    found = await _find_kb_document(api_key, team_id, project_id, document_identifier, folder_id,
                                    include_connection_details=True)
    if found.get('status') != 'OK':
        return found

    document = found['document']
    doc_type = (document.get('type') or '').lower()
    connection_details = document.get('connection_details') or {}
    pages = connection_details.get('pageDetails')

    if doc_type not in _KB_PAGE_DOC_TYPES or not isinstance(pages, list):
        logger.error(f"_find_kb_page_document: kb_id={document.get('kb_id')} is a '{doc_type}' "
                     f"document and has no pages")
        return {
            'status': 'failed',
            'error': 'Not a page document',
            'error_type': 'NotAPageDocument',
            'message': (f"'{document.get('doc_name')}' is a {doc_type or 'file'} document — it has no "
                        f"pages. Pages belong to documents created with "
                        f"bugasura_create_knowledge_base_document, and to documents synced from Coda, "
                        f"Jira, Confluence or a URL."),
            'kb_id': document.get('kb_id'),
            'doc_name': document.get('doc_name'),
            'type': doc_type
        }

    return {
        'status': 'OK',
        'document': document,
        'doc_type': doc_type,
        'doc_name': connection_details.get('doc_name') or document.get('doc_name') or '',
        'pages': pages
    }


def _read_kb_page_content(page: dict) -> dict:
    """
    Read a page's stored markdown back from the CDN.

    A page's body is written to `{team}/{app}/ai-testpertkb/kb-{kbId}/kb-doc/{pageId}.md` and
    the path is kept on the page as `uploaded_file_path`. The API has no endpoint that
    returns it — the web app's editor loads it straight off the CDN through its attachment
    proxy — so this reads the same public object the editor does.

    An empty `uploaded_file_path` is a page that has never been written, which is a normal
    state and comes back as empty content, not an error. A page larger than
    `_KB_MAX_PAGE_CONTENT_BYTES` is refused outright rather than truncated, because a write
    replaces the whole body and a partial read would turn an edit into a deletion.

    Returns:
        dict: {'status': 'OK', 'content': str, 'content_url': str | None} or a failure envelope.
    """
    file_path = (page.get('uploaded_file_path') or '').strip()
    if not file_path:
        return {'status': 'OK', 'content': '', 'content_url': None}

    content_url = _kb_file_url(file_path)
    if not content_url:
        logger.error("_read_kb_page_content: CDN base is not configured, cannot read "
                     f"page_id={page.get('page_id')}")
        return {
            'status': 'failed',
            'error': 'Page content unavailable',
            'error_type': 'PageContentUnavailable',
            'message': ("This server does not know where this Bugasura deployment stores its "
                        "files, so it cannot read the page's content. Set CDN_BASE_URL in the MCP "
                        "server's .env to the deployment's CDN base URL. Until then the page can "
                        "only be read by opening the document in the web app."),
            'file_path': file_path
        }

    try:
        raw, exceeded = _fetch_url_bytes(content_url, _KB_MAX_PAGE_CONTENT_BYTES)
    except Exception as e:
        logger.error(f"_read_kb_page_content: Could not fetch '{content_url}': {e}")
        return {
            'status': 'failed',
            'error': "Could not read the page's content",
            'error_type': 'IOError',
            'message': (f"The page's stored content could not be fetched: {e}. Do not write to "
                        f"this page until it can be read — a write replaces the whole body, so "
                        f"editing it blind would discard whatever is there."),
            'content_url': content_url
        }

    if exceeded:
        logger.warning(f"_read_kb_page_content: page_id={page.get('page_id')} is larger than "
                       f"{_KB_MAX_PAGE_CONTENT_BYTES} bytes; refusing to return a partial body")
        return {
            'status': 'failed',
            'error': 'Page content too large',
            'error_type': 'PageContentTooLarge',
            'message': (f"This page is larger than {_KB_MAX_PAGE_CONTENT_BYTES // 1024}KB, so its "
                        f"content is not returned — a partial copy must never be written back, as "
                        f"that would delete the rest of the page. Tell the user to edit this page "
                        f"in the web app; the raw file is at {content_url}"),
            'content_url': content_url
        }

    # The API writes whatever string it was given; decode leniently so a stray byte cannot
    # turn a readable page into a failure.
    return {'status': 'OK', 'content': raw.decode('utf-8', errors='replace'),
            'content_url': content_url}


async def _resolve_page_document(api_key: str, team_id: int, project_id: int,
                                 document_identifier: str, folder_id: Optional[int] = None,
                                 folder_name: Optional[str] = None) -> dict:
    """
    Narrow the search to a folder when the caller named one, then resolve the page document.

    Shared by every page tool: they all take the same optional folder scope so a document
    name that repeats across folders can be pinned down.
    """
    scope_folder_id = None
    if folder_id is not None or (folder_name and folder_name.strip()):
        folder = await _find_kb_folder(api_key, team_id, project_id, folder_id, folder_name)
        if folder.get('status') != 'OK':
            return _with_hint(folder, "List the folders with bugasura_list_knowledge_base_folders.")
        scope_folder_id = folder['folder_id']

    return await _find_kb_page_document(api_key, team_id, project_id, document_identifier,
                                        scope_folder_id)


async def _kb_doc_page_action(api_key: str, team_id: int, project_id: int, kb_id: Any,
                              doc_type: str, action: str, page_details: Optional[list] = None,
                              doc_name: Optional[str] = None) -> dict:
    """
    Apply one page action to a knowledge base page document.

    Every page action is a POST /v1/knowledgebase/update carrying a `customFileDetails`
    envelope — `{"action": ..., "doc_name": ..., "pageDetails": [...]}` — exactly as the
    web app's document editor sends it. `kbType` must be the document's own type, since the
    API only dispatches page actions for the types in `_KB_PAGE_DOC_TYPES`.

    Args:
        kb_id: Document the action applies to
        doc_type: The document's stored type ('custom_doc', 'coda', 'url', 'jira', 'confluence')
        action: 'add_page', 'add_subpage', 'add_sibling_page', 'edit_page_name',
                'edit_page_content', 'delete_page', 'duplicate_page', 'page_reposition'
                or 'edit_doc_name'
        page_details: The action's page entries (the API only reads the first one, except
                      for page_reposition which takes the whole structure)
        doc_name: New document name, for 'edit_doc_name' only

    Returns:
        dict: The upstream response — 'pageDetails' carries the created/duplicated page,
        'knowledgeBaseDetails' the updated document row — or a failure envelope.
    """
    # doc_name is `false` on every action but edit_doc_name, matching the web app's payload.
    custom_file_details = {
        'action': action,
        'doc_name': doc_name if doc_name else False,
        'pageDetails': page_details if page_details is not None else []
    }

    logger.info(f"_kb_doc_page_action: Applying action='{action}' on kb_id={kb_id} "
                f"(type='{doc_type}') in project_id={project_id}")

    return await make_api_request('POST', '/v1/knowledgebase/update', api_key, data={
        'appId': str(project_id),
        'teamId': str(team_id),
        'kbId': str(kb_id),
        'kbType': doc_type,
        'kbSourceType': '',
        'kbSource': '',
        'customFileDetails': json.dumps(custom_file_details),
    })


def _pages_from_update_response(response: dict, kb_id: Any) -> list:
    """
    Read the document's pages back out of a /v1/knowledgebase/update response.

    `knowledgeBaseDetails` is the raw document row, so `connection_details` arrives as a
    JSON string. Returns an empty list when the response does not carry the row.
    """
    for row in response.get('knowledgeBaseDetails') or []:
        if str(row.get('kb_id')) != str(kb_id):
            continue
        connection_details = row.get('connection_details')
        if isinstance(connection_details, str):
            try:
                connection_details = json.loads(connection_details)
            except ValueError:
                logger.error(f"_pages_from_update_response: Could not parse connection_details "
                             f"for kb_id={kb_id}")
                return []
        if isinstance(connection_details, dict):
            pages = connection_details.get('pageDetails')
            return pages if isinstance(pages, list) else []
    return []


def _doc_name_from_update_response(response: dict, kb_id: Any) -> Optional[str]:
    """
    Read the document's stored name back out of a /v1/knowledgebase/update response.

    The API sanitises a document name (stripping < > and trimming) before saving it, so the
    stored name can differ from the one that was requested. Returns None when the response
    does not carry the row, leaving the caller to fall back on the requested name.
    """
    for row in response.get('knowledgeBaseDetails') or []:
        if str(row.get('kb_id')) != str(kb_id):
            continue
        connection_details = row.get('connection_details')
        if isinstance(connection_details, str):
            try:
                connection_details = json.loads(connection_details)
            except ValueError:
                return None
        if isinstance(connection_details, dict):
            stored = connection_details.get('doc_name')
            return stored if isinstance(stored, str) and stored.strip() else None
    return None


def _kb_document_url(project_id: int, kb_id: Any) -> Optional[str]:
    """Web app link that opens a knowledge base document, when the web base is known.

    Returns None without a kb_id — an import that queued without returning one would
    otherwise produce a '?doc=None' link.
    """
    if not WEB_BASE_URL or not kb_id:
        return None
    return f"{WEB_BASE_URL}knowledgeBase/{project_id}?doc={kb_id}"


def _fail(error: str, message: str, error_type: str = 'ValidationError', **extra) -> dict:
    """Build a failure envelope. `extra` carries the choices a caller needs to recover."""
    return {'status': 'failed', 'error': error, 'error_type': error_type,
            'message': message, **extra}


def _require_http_url(url: str, field: str, example: str) -> Optional[dict]:
    """
    Reject a tool URL that is not http(s), returning the failure envelope or None.

    Every connector talks to its tool over HTTP, and each upstream endpoint rejects
    anything else with a generic message — checking here names the argument instead.
    """
    if not url:
        return _fail(f'{field} is required',
                     f"Ask the user for their {field}, e.g. '{example}'.")
    if not url.lower().startswith(('http://', 'https://')):
        return _fail(f'Invalid {field}',
                     f"'{url}' does not start with http:// or https://. Ask the user for the "
                     f"full address, e.g. '{example}'.")
    return None


def _select_items(identifiers: List[str], items: list, id_key: str, name_key: str,
                  label: str, listed_by: str) -> dict:
    """
    Resolve caller-supplied ids/names to entries of a connector listing.

    An empty `identifiers` selects everything, which is what "import the whole doc /
    project / space" means at every call site. Each identifier is matched against the
    entry's id first, then its name case-insensitively, then as a substring of the name —
    the same order `_find_kb_document` uses, so naming things works the way users talk
    about them. An identifier that matches nothing, or more than one entry, fails the
    whole call rather than silently importing a subset.

    Returns:
        dict: {'status': 'OK', 'items': [...]} or a failure envelope carrying
        `available` / `matches`.
    """
    choices = [{id_key: item.get(id_key), name_key: item.get(name_key)}
               for item in items[:_KB_MAX_CHOICES]]

    if not identifiers:
        if not items:
            return _fail(f'No {label} available',
                         f"There is nothing to import — {listed_by} returned no {label}.",
                         error_type='NothingToImport')
        return {'status': 'OK', 'items': list(items)}

    selected = []
    for identifier in identifiers:
        needle = str(identifier or '').strip()
        if not needle:
            continue

        matches = [i for i in items if str(i.get(id_key) or '') == needle]
        if not matches:
            matches = [i for i in items
                       if (i.get(name_key) or '').strip().lower() == needle.lower()]
        if not matches:
            matches = [i for i in items if needle.lower() in (i.get(name_key) or '').lower()]

        if not matches:
            logger.error(f"_select_items: No {label} matching '{needle}'")
            return _fail(f'{label.capitalize()} not found',
                         f"Nothing matching '{needle}' is available. List the {label} with "
                         f"{listed_by} and pass one of the values it returns.",
                         error_type='NotFound', available=choices)
        if len(matches) > 1:
            logger.warning(f"_select_items: {len(matches)} {label} match '{needle}'")
            return _fail(f'Multiple {label} match',
                         f"{len(matches)} entries match '{needle}'. Ask the user which one, "
                         f"then pass its id.",
                         error_type='Ambiguous',
                         matches=[{id_key: m.get(id_key), name_key: m.get(name_key)}
                                  for m in matches[:_KB_MAX_CHOICES]])

        if matches[0] not in selected:
            selected.append(matches[0])

    if not selected:
        return _fail(f'No {label} selected',
                     f"Every value passed was blank. Omit the argument to import all "
                     f"{label}, or pass the values {listed_by} returns.",
                     available=choices)

    return {'status': 'OK', 'items': selected}


async def _connector_context(api_key: str, team_id: Optional[int], project_id: Optional[int],
                             tool_name: str, caller: str,
                             operation_params: str = "") -> dict:
    """
    Run the shared API-key + team/project resolution every connector tool starts with.

    Returns:
        dict: {'status': 'OK', 'api_key': str, 'team_id': int, 'project_id': int}, or the
        selection prompt / failure envelope to hand straight back to the caller.
    """
    api_key = _get_api_key(api_key)
    validation = await validate_api_key(api_key)
    if not validation.get('valid'):
        return validation

    context = await select_team_project_context(api_key, team_id, project_id, tool_name,
                                                operation_params)
    # A resolved context carries the ids and no status; everything else is a prompt or a
    # failure the caller hands straight back.
    if 'team_id' not in context or 'project_id' not in context:
        return context

    project_team_id = await _resolve_project_team_id(api_key, context['team_id'],
                                                     context['project_id'], caller)
    return {'status': 'OK', 'api_key': api_key, 'team_id': project_team_id,
            'project_id': context['project_id']}


async def _submit_kb_import(api_key: str, team_id: int, project_id: int, kb_type: str,
                            tools_connection_details: Any, folder: dict,
                            kb_source: str = '', kb_source_type: str = '') -> dict:
    """
    Create a knowledge base entry for a connector selection.

    Mirrors the web app's modals: POST /v1/knowledgebase/add with the connector's
    `kbType` and the selection as a JSON `toolsConnectionDetails` blob — an object for
    every connector but Figma, whose payload is a list of frames. `kbSource` /
    `kbSourceType` are left empty for every connector but Figma, so the API falls back to
    the connector name and the folder name the way the website import already does.

    Returns:
        dict: The upstream response with `kb_id` / `kb_ids` normalised onto it, or a
        failure envelope.
    """
    logger.info(f"_submit_kb_import: Adding a '{kb_type}' knowledge base entry to "
                f"folder_id={folder['folder_id']} ('{folder['folder_name']}'), "
                f"project_id={project_id}")

    data = {
        'appId': str(project_id),
        'teamId': str(team_id),
        'folderId': str(folder['folder_id']),
        'kbType': kb_type,
        'toolsConnectionDetails': json.dumps(tools_connection_details),
    }
    if kb_source:
        data['kbSource'] = kb_source
    if kb_source_type:
        data['kbSourceType'] = kb_source_type

    response = await make_api_request('POST', '/v1/knowledgebase/add', api_key, data=data)
    if response.get('status') != 'OK':
        logger.error(f"_submit_kb_import: '{kb_type}' import failed: {response.get('message')}")
        return response

    kb_ids = response.get('kbIds') or []
    response['kb_ids'] = kb_ids
    response['kb_id'] = next(iter(kb_ids), None)
    response['folder_id'] = folder['folder_id']
    response['folder_name'] = folder['folder_name']
    response['folder_created'] = folder.get('created', False)
    return response


async def _submit_doc_page_import(api_key: str, team_id: int, project_id: int, kb_id: Any,
                                  page_id: str, import_type: str,
                                  tools_connection_details: Optional[dict] = None,
                                  page_content: Optional[str] = None,
                                  files: Optional[list] = None) -> dict:
    """
    Import into an existing knowledge base page document.

    POST /v1/knowledgebase/importDocPages — the KB document editor's Import menu and the
    Jira/Confluence modals opened from inside a document both land here. `pageId` is
    required upstream for every import type, but only csv_file/excel_file actually write
    to that page; for md_file the new page is created at root level, and for
    jira/confluence the imported tree is merged into the document as a whole.

    Returns:
        dict: The upstream response — `knowledgeBaseDetails` is the updated document row,
        `pageDetails` the page a Markdown import created — or a failure envelope.
    """
    logger.info(f"_submit_doc_page_import: importType='{import_type}' into kb_id={kb_id} "
                f"(page_id={page_id}), project_id={project_id}")

    data = {
        'appId': str(project_id),
        'teamId': str(team_id),
        'kbId': str(kb_id),
        'pageId': str(page_id),
        'importType': import_type,
    }
    if tools_connection_details is not None:
        data['toolsConnectionDetails'] = json.dumps(tools_connection_details)
    if page_content is not None:
        data['pageContent'] = page_content

    return await make_api_request('POST', '/v1/knowledgebase/importDocPages', api_key,
                                  data=data, files=files)


async def _resolve_import_target_page(api_key: str, team_id: int, project_id: int,
                                      document_identifier: str,
                                      page_identifier: Optional[str],
                                      folder_id: Optional[int],
                                      folder_name: Optional[str]) -> dict:
    """
    Resolve the page document an in-document import writes into, and one of its pages.

    Every importDocPages call needs a `pageId`, even the import types that do not write to
    that page. When the caller names no page the document's first page is used, which is
    what the web app effectively sends (the page open in the editor).

    Returns:
        dict: {'status': 'OK', 'document', 'doc_type', 'doc_name', 'pages', 'page'} or a
        failure envelope.
    """
    found = await _resolve_page_document(api_key, team_id, project_id, document_identifier,
                                         folder_id, folder_name)
    if found.get('status') != 'OK':
        return found

    document = found['document']
    stage = (document.get('stage') or '').upper()
    if stage in _KB_DOC_IMPORTING_STAGES:
        return _fail('Import already in progress',
                     f"'{document.get('doc_name')}' is still importing pages from an earlier "
                     f"request. Wait for it to finish — bugasura_list_knowledge_base_documents "
                     f"shows PROCESSED once it is done — then import again.",
                     error_type='ImportInProgress', kb_id=document.get('kb_id'), stage=stage)

    pages = found['pages']
    if not pages:
        return _fail('Document has no pages',
                     f"'{document.get('doc_name')}' has no pages to import into. Add one with "
                     f"bugasura_create_knowledge_base_page first.",
                     error_type='PageNotFound', kb_id=document.get('kb_id'))

    if page_identifier and page_identifier.strip():
        page = _find_kb_page(pages, page_identifier)
        if page.get('status') != 'OK':
            return page
        found['page'] = page['page']
    else:
        found['page'] = pages[0]

    return found

async def _fetch_coda_docs(api_key: str, coda_api_key: str) -> dict:
    """
    List the Coda docs the given Coda API key can see.

    Returns:
        dict: {'status': 'OK', 'docs': [{'doc_id', 'doc_name', 'browser_link'}]} or a
        failure envelope. A doc-restricted Coda key cannot list docs at all — that comes
        back as a `RestrictedCodaKey` failure telling the caller to name the doc instead.
    """
    response = await make_api_request('POST', '/v1/coda/getDocs', api_key,
                                      data={'apiKey': coda_api_key})

    if response.get('status') != 'OK':
        if response.get('restrictedKey'):
            logger.info("_fetch_coda_docs: The Coda API key is restricted to specific docs")
            return _fail('Coda API key is doc-restricted',
                         "This Coda API key cannot list docs — it is scoped to specific ones. "
                         "Ask the user for the Coda doc's URL (or its id) and pass it as "
                         "coda_doc; that works with a restricted key.",
                         error_type='RestrictedCodaKey')
        logger.error(f"_fetch_coda_docs: Failed to list Coda docs: {response.get('message')}")
        return _fail('Failed to list Coda docs',
                     response.get('message', 'Coda did not return the docs list. Check that the '
                                             'API key is correct and still active.'),
                     error_type='CodaFetchError')

    docs = [{'doc_id': doc.get('id', ''), 'doc_name': doc.get('name', ''),
             'browser_link': doc.get('browserLink', '')}
            for doc in response.get('docsDetails') or []]
    logger.info(f"_fetch_coda_docs: Found {len(docs)} Coda doc(s)")
    return {'status': 'OK', 'docs': docs}


async def _resolve_coda_doc(api_key: str, coda_api_key: str, coda_doc: str) -> dict:
    """
    Resolve a Coda doc URL, id or name to {'doc_id', 'doc_name'}.

    A URL or a bare id goes through /v1/coda/getDocDetails, which validates that the key
    can actually open that doc and returns Coda's canonical id — the only lookup that
    works with a doc-restricted key. Anything else is treated as a doc *name* and matched
    against the key's doc list.

    Returns:
        dict: {'status': 'OK', 'doc_id': str, 'doc_name': str} or a failure envelope.
    """
    doc_input = (coda_doc or '').strip()
    if not doc_input:
        return _fail('coda_doc is required',
                     "Ask the user which Coda doc to import — its URL, its id, or its name "
                     "as shown by bugasura_list_coda_docs.")

    # A name with spaces can never be a URL or an id, so only the id/URL forms are worth a
    # getDocDetails round trip.
    if '/' in doc_input or ' ' not in doc_input:
        response = await make_api_request('POST', '/v1/coda/getDocDetails', api_key,
                                          data={'apiKey': coda_api_key, 'docInput': doc_input})
        if response.get('status') == 'OK':
            details = response.get('docDetails') or {}
            logger.info(f"_resolve_coda_doc: Resolved '{doc_input}' to "
                        f"doc_id={details.get('id')}")
            return {'status': 'OK', 'doc_id': details.get('id', ''),
                    'doc_name': details.get('name', '')}
        if '/' in doc_input:
            logger.error(f"_resolve_coda_doc: Coda rejected doc URL '{doc_input}': "
                         f"{response.get('message')}")
            return _fail('Coda doc not accessible',
                         f"Coda could not open '{doc_input}' with this API key: "
                         f"{response.get('message', 'unknown error')}. Check the link, and that "
                         f"the key has access to that doc.",
                         error_type='CodaDocNotFound')

    docs_response = await _fetch_coda_docs(api_key, coda_api_key)
    if docs_response.get('status') != 'OK':
        return docs_response

    selection = _select_items([doc_input], docs_response['docs'], 'doc_id', 'doc_name',
                              'Coda docs', 'bugasura_list_coda_docs')
    if selection.get('status') != 'OK':
        return selection

    doc = selection['items'][0]
    return {'status': 'OK', 'doc_id': doc['doc_id'], 'doc_name': doc['doc_name']}


def _flatten_coda_pages(nodes: Any, ancestors: Optional[List[str]] = None) -> list:
    """
    Flatten the nested page tree /v1/coda/getPages returns.

    Each page carries the id chain from the top-most ancestor down to its parent, which is
    what the import payload's `ancestor_ids` is: when the user imports a page but not its
    parent, the API walks that chain nearest-first to re-parent the page onto whichever
    ancestor *was* selected (see healCodaPageParents upstream).

    Returns:
        list: [{'page_id', 'page_name', 'parent_page_id', 'ancestor_page_ids',
        'page_path', 'depth'}] in tree order.
    """
    ancestors = ancestors or []
    pages = []
    for node in nodes or []:
        if not isinstance(node, dict):
            continue
        page_id = node.get('id', '')
        page_name = node.get('name', '')
        pages.append({
            'page_id': page_id,
            'page_name': page_name,
            'parent_page_id': ancestors[-1] if ancestors else '',
            # Farthest-to-nearest, the order the API's re-parenting walk expects.
            'ancestor_page_ids': ','.join(ancestors),
            'page_path': page_name,
            'depth': len(ancestors),
        })
        pages.extend(_flatten_coda_pages(node.get('subpages'), ancestors + [page_id]))
    return pages


async def _fetch_coda_pages(api_key: str, coda_api_key: str, doc_id: str) -> dict:
    """
    Fetch a Coda doc's pages as a flat list.

    Returns:
        dict: {'status': 'OK', 'pages': [...]} — see `_flatten_coda_pages` — or a failure
        envelope.
    """
    response = await make_api_request('POST', '/v1/coda/getPages', api_key,
                                      data={'apiKey': coda_api_key, 'docId': doc_id})
    if response.get('status') != 'OK':
        logger.error(f"_fetch_coda_pages: Failed to fetch pages of doc_id={doc_id}: "
                     f"{response.get('message')}")
        return _fail('Failed to list Coda pages',
                     response.get('message', 'Coda did not return this doc\'s pages.'),
                     error_type='CodaFetchError')

    pages = _flatten_coda_pages(response.get('pagesDetails'))
    # Fill in the breadcrumb now that every page is in one flat list.
    names_by_id = {p['page_id']: p['page_name'] for p in pages}
    for page in pages:
        ancestor_ids = [a for a in page['ancestor_page_ids'].split(',') if a]
        page['page_path'] = ' / '.join([names_by_id.get(a, '') for a in ancestor_ids]
                                       + [page['page_name']])

    logger.info(f"_fetch_coda_pages: Found {len(pages)} page(s) in Coda doc_id={doc_id}")
    return {'status': 'OK', 'pages': pages}

def _jira_credentials(jira_url: str, user_name: str, secret: str,
                      deployment_type: str) -> dict:
    """
    Build the credential half of a Jira payload.

    Jira Cloud authenticates with an API token and Jira Server/Data Center with a
    password, but the API reads both keys off the same payload — so the one secret the
    user gave is sent in both, which is exactly what the web app's modal does.
    """
    return {
        'jiraUrl': jira_url.rstrip('/'),
        'userName': user_name,
        'accessToken': secret,
        'password': secret,
        'deploymentType': deployment_type,
    }


async def _fetch_jira_projects(api_key: str, team_id: int, project_id: int,
                               credentials: dict) -> dict:
    """
    List the Jira projects the given credentials can see.

    Returns:
        dict: {'status': 'OK', 'projects': [{'project_key', 'project_name',
        'total_issue_count'}]} or a failure envelope.
    """
    response = await make_api_request('POST', '/v1/bugTracker/getProjectList', api_key, data={
        'toolName': 'JIRA',
        'toolUrl': credentials['jiraUrl'],
        'userName': credentials['userName'],
        'password': credentials['password'],
        'accessToken': credentials['accessToken'],
        'deploymentType': credentials['deploymentType'],
        'appId': str(project_id),
        'teamId': str(team_id),
        # The Bugasura-side team/project listing this endpoint can also return is only
        # used by the integration settings screens; skip it.
        'isGetUserTeamProjects': 0,
    })

    if response.get('status') != 'OK':
        logger.error(f"_fetch_jira_projects: Failed to list Jira projects: "
                     f"{response.get('message')}")
        return _fail('Failed to list Jira projects',
                     response.get('message', 'Jira did not return the project list. Check the '
                                             'URL, the account email and the API token.'),
                     error_type='JiraFetchError')

    projects = [{'project_key': p.get('key', ''), 'project_name': p.get('name', ''),
                 'total_issue_count': (p.get('insight') or {}).get('totalIssueCount', 0)}
                for p in response.get('projectsList') or []]
    logger.info(f"_fetch_jira_projects: Found {len(projects)} Jira project(s)")
    return {'status': 'OK', 'projects': projects}


def _group_issue_keys_by_project(issue_keys: List[str]) -> dict:
    """
    Group Jira issue keys by the project key they start with ('ACME-12' -> 'ACME').

    A Jira project key never contains a hyphen, so the part before the first one is the
    project. Returns {'grouped': {project_key: [issue_key, ...]},
                      'malformed': [key, ...]} — anything without a hyphen is reported
    rather than dropped, since a dropped key silently widens the import to the whole project.
    """
    grouped: Dict[str, List[str]] = {}
    malformed: List[str] = []
    for issue_key in issue_keys:
        key = str(issue_key or '').strip()
        if not key or '-' not in key:
            # Dropping these silently would leave the project with no explicit issue list,
            # which the payload builder reads as "import everything" — the opposite of what
            # a caller naming specific issues wants.
            malformed.append(key or str(issue_key))
            continue
        grouped.setdefault(key.split('-', 1)[0].upper(), []).append(key)
    return {'grouped': grouped, 'malformed': malformed}


def _jira_connection_details(credentials: dict, projects: list, issue_keys: List[str]) -> dict:
    """
    Build the `toolsConnectionDetails` payload of a Jira import.

    `projectDetails` is keyed by project key and carries either the explicit issue keys
    chosen for that project or the "everything" marker. Returns the payload, or a failure
    envelope when an issue key is malformed or names a project that was not selected.
    """
    grouping = _group_issue_keys_by_project(issue_keys)
    issues_by_project = grouping['grouped']
    if grouping['malformed']:
        return _fail('Unrecognised Jira issue key(s)',
                     f"Not valid Jira issue keys: {', '.join(repr(k) for k in grouping['malformed'])}. "
                     f"A key is the project key, a hyphen, then the number (e.g. 'ACME-123'). "
                     f"Fix them, or drop issue_keys entirely to import whole projects.")

    selected_keys = {p['project_key'].upper() for p in projects}
    unknown = sorted(set(issues_by_project) - selected_keys)
    if unknown:
        return _fail('Issue keys outside the selected projects',
                     f"issue_keys names project(s) {', '.join(unknown)}, which are not in "
                     f"project_keys. Add them to project_keys, or drop those issues.")

    project_details = {}
    for project in projects:
        key = project['project_key']
        issues = issues_by_project.get(key.upper())
        project_details[key] = {
            'projectName': project['project_name'],
            'issueId': issues if issues else _KB_IMPORT_ALL,
            'totalIssueCount': len(issues) if issues else project.get('total_issue_count', 0),
        }

    return {
        'status': 'OK',
        'payload': {
            **credentials,
            'projectDetails': project_details,
            'projectKeys': [p['project_key'] for p in projects],
        },
    }

def _confluence_credentials(confluence_url: str, user_email: str, api_token: str) -> dict:
    """Build the credential half of a Confluence payload."""
    return {
        'confluenceUrl': confluence_url.rstrip('/'),
        'userEmail': user_email,
        'apiToken': api_token,
    }


async def _fetch_confluence_spaces(api_key: str, team_id: int, project_id: int,
                                   credentials: dict) -> dict:
    """
    List the Confluence spaces the given credentials can see.

    Returns:
        dict: {'status': 'OK', 'spaces': [{'space_key', 'space_name'}]} or a failure
        envelope.
    """
    response = await make_api_request('POST', '/v1/confluence/getSpaceList', api_key, data={
        'appId': str(project_id),
        'teamId': str(team_id),
        **credentials,
    })

    if response.get('status') != 'OK':
        logger.error(f"_fetch_confluence_spaces: Failed to list Confluence spaces: "
                     f"{response.get('message')}")
        return _fail('Failed to list Confluence spaces',
                     response.get('message', 'Confluence did not return the space list. Check '
                                             'the URL, the account email and the API token.'),
                     error_type='ConfluenceFetchError')

    spaces = [{'space_key': s.get('key', ''), 'space_name': s.get('name', '')}
              for s in response.get('spaces') or []]
    logger.info(f"_fetch_confluence_spaces: Found {len(spaces)} Confluence space(s)")
    return {'status': 'OK', 'spaces': spaces}


async def _fetch_confluence_pages(api_key: str, team_id: int, project_id: int,
                                  credentials: dict, space_key: str) -> dict:
    """
    List the pages of one Confluence space.

    Returns:
        dict: {'status': 'OK', 'pages': [{'page_id', 'page_title', 'page_url'}]} or a
        failure envelope.
    """
    response = await make_api_request('POST', '/v1/confluence/getPagesBySpace', api_key, data={
        'appId': str(project_id),
        'teamId': str(team_id),
        'spaceKey': space_key,
        **credentials,
    })

    if response.get('status') != 'OK':
        logger.error(f"_fetch_confluence_pages: Failed to list pages of space '{space_key}': "
                     f"{response.get('message')}")
        return _fail('Failed to list Confluence pages',
                     response.get('message', f"Confluence did not return the pages of space "
                                             f"'{space_key}'."),
                     error_type='ConfluenceFetchError')

    pages = [{'page_id': p.get('id', ''), 'page_title': p.get('title', ''),
              'page_url': p.get('url', '')}
             for p in response.get('pages') or []]
    logger.info(f"_fetch_confluence_pages: Found {len(pages)} page(s) in space '{space_key}'")
    return {'status': 'OK', 'pages': pages}


async def _confluence_connection_details(api_key: str, team_id: int, project_id: int,
                                         credentials: dict, spaces: list,
                                         page_ids: List[str]) -> dict:
    """
    Build the `toolsConnectionDetails` payload of a Confluence import.

    `spaceDetails` is keyed by space key. Page ids are only meaningful inside one space,
    so an explicit `page_ids` selection is only allowed when a single space was chosen —
    the pages are then verified against that space rather than sent blind.

    Returns:
        dict: {'status': 'OK', 'payload': {...}} or a failure envelope.
    """
    if page_ids and len(spaces) > 1:
        return _fail('page_ids needs a single space',
                     f"page_ids was given with {len(spaces)} spaces selected, and a page id "
                     f"only identifies a page inside one space. Import one space per call when "
                     f"picking individual pages, or omit page_ids to import whole spaces.")

    space_details = {}
    for space in spaces:
        selected_pages = _KB_IMPORT_ALL
        total_pages = 0
        if page_ids:
            pages_response = await _fetch_confluence_pages(api_key, team_id, project_id,
                                                           credentials, space['space_key'])
            if pages_response.get('status') != 'OK':
                return pages_response
            selection = _select_items(page_ids, pages_response['pages'], 'page_id',
                                      'page_title', 'Confluence pages',
                                      'bugasura_list_confluence_pages')
            if selection.get('status') != 'OK':
                return selection
            selected_pages = [p['page_id'] for p in selection['items']]
            total_pages = len(selected_pages)

        space_details[space['space_key']] = {
            'spaceName': space['space_name'],
            'pageId': selected_pages,
            'totalPageCount': total_pages,
        }

    return {
        'status': 'OK',
        'payload': {
            **credentials,
            'spaceDetails': space_details,
            'spaceKeys': [s['space_key'] for s in spaces],
        },
    }

def _parse_figma_url(figma_url: str) -> dict:
    """
    Split a Figma frame link into its file key and node id.

    A frame link looks like
    `https://www.figma.com/design/<fileKey>/<Name>?node-id=1-2`; the node id is written
    with a hyphen in the URL and with a colon in the API. A link without `node-id` points
    at a whole file rather than a frame, which this import cannot take.

    Returns:
        dict: {'status': 'OK', 'file_key': str, 'node_id': str} or a failure envelope.
    """
    parsed = urllib.parse.urlparse(figma_url)
    if 'figma.com' not in parsed.netloc.lower():
        return _fail('Not a Figma link',
                     f"'{figma_url}' is not a figma.com link. Ask the user to copy the frame's "
                     f"link from Figma (right-click the frame → Copy link).")

    parts = [part for part in parsed.path.split('/') if part]
    if len(parts) < 2 or parts[0].lower() not in _KB_FIGMA_URL_KINDS:
        return _fail('Unrecognised Figma link',
                     f"Could not read a file key out of '{figma_url}'. Ask the user to copy the "
                     f"frame's link from Figma (right-click the frame → Copy link).")

    node_id = (urllib.parse.parse_qs(parsed.query).get('node-id') or [''])[0]
    if not node_id:
        return _fail('Figma link has no frame',
                     f"'{figma_url}' points at a whole Figma file, not a frame — it has no "
                     f"node-id. Ask the user to right-click the frame they want and choose "
                     f"'Copy link to selection'.")

    return {'status': 'OK', 'file_key': parts[1], 'node_id': node_id.replace('-', ':')}


async def _figma_api_get(path: str, figma_api_key: str) -> dict:
    """
    Call the Figma REST API with the user's personal access token.

    Figma is the one connector Bugasura has no proxy endpoint for — the web app queries it
    straight from its own controller, and so does this. Errors are mapped to a failure
    envelope rather than raised, so a bad token reads as a normal tool failure.

    Returns:
        dict: {'status': 'OK', 'data': {...}} or a failure envelope.
    """
    try:
        response = await _get_http_client().get(f"{_KB_FIGMA_API_BASE}{path}",
                                                headers={'X-FIGMA-TOKEN': figma_api_key})
    except httpx.HTTPError as e:
        logger.error(f"_figma_api_get: Request to '{path}' failed: {e}")
        return _fail('Could not reach Figma',
                     f"The request to Figma failed: {e}. Check the machine running this server "
                     f"can reach api.figma.com.",
                     error_type='ConnectionError')

    if response.status_code in (401, 403):
        logger.error(f"_figma_api_get: Figma rejected the token on '{path}' "
                     f"(HTTP {response.status_code})")
        return _fail('Figma rejected the access token',
                     "Figma did not accept this personal access token, or it cannot see this "
                     "file. Ask the user for a token from Figma → Settings → Security → "
                     "Personal access tokens, generated by an account with access to the file.",
                     error_type='FigmaAuthError')
    if response.status_code == 404:
        return _fail('Figma file or frame not found',
                     "Figma has no file or frame at that link. Ask the user to re-copy the "
                     "frame's link.",
                     error_type='FigmaNotFound')

    try:
        data = response.json()
    except ValueError:
        logger.error(f"_figma_api_get: Figma returned a non-JSON body on '{path}'")
        return _fail('Unexpected response from Figma',
                     'Figma did not return a readable response. Try again in a moment.',
                     error_type='FigmaFetchError')

    if response.status_code >= 400 or data.get('err'):
        message = data.get('err') or data.get('message') or f"HTTP {response.status_code}"
        logger.error(f"_figma_api_get: Figma error on '{path}': {message}")
        return _fail('Figma returned an error', f"Figma said: {message}.",
                     error_type='FigmaFetchError')

    return {'status': 'OK', 'data': data}


async def _fetch_figma_frame(figma_api_key: str, figma_url: str) -> dict:
    """
    Resolve one Figma frame link to the entry the import payload needs.

    Two calls, the same pair the web app makes: `/images` renders the frame to a PNG and
    hands back a temporary export link, `/files/{key}/nodes` gives the frame its name.
    Bugasura downloads the export link server-side during the import, so it never has to
    outlive the call.

    Returns:
        dict: {'status': 'OK', 'frame': {'name', 'imageLink', 'exportLink', 'apiKey'}} or a
        failure envelope.
    """
    parsed = _parse_figma_url(figma_url)
    if parsed.get('status') != 'OK':
        return parsed
    file_key, node_id = parsed['file_key'], parsed['node_id']
    encoded_node_id = urllib.parse.quote(node_id)

    images = await _figma_api_get(f"/images/{file_key}?ids={encoded_node_id}&format=png",
                                  figma_api_key)
    if images.get('status') != 'OK':
        return images
    export_link = (images['data'].get('images') or {}).get(node_id)
    if not export_link:
        logger.error(f"_fetch_figma_frame: Figma rendered no image for node_id={node_id}")
        return _fail('Figma could not render the frame',
                     f"Figma returned no image for the frame in '{figma_url}'. It may be empty, "
                     f"or the link may point at something other than a frame.",
                     error_type='FigmaFetchError')

    nodes = await _figma_api_get(f"/files/{file_key}/nodes?ids={encoded_node_id}&depth=1",
                                 figma_api_key)
    if nodes.get('status') != 'OK':
        return nodes
    node = (nodes['data'].get('nodes') or {}).get(node_id) or {}
    frame_name = (node.get('document') or {}).get('name', '')
    if not frame_name:
        logger.warning(f"_fetch_figma_frame: No name on node_id={node_id}, falling back to it")
        frame_name = node_id

    logger.info(f"_fetch_figma_frame: Resolved '{figma_url}' to frame '{frame_name}'")
    return {'status': 'OK', 'frame': {'name': frame_name, 'imageLink': figma_url,
                                      'exportLink': export_link, 'apiKey': figma_api_key}}


async def _fetch_existing_figma_links(api_key: str, team_id: int, project_id: int) -> dict:
    """
    Read back the Figma frame links already stored in the project's knowledge base.

    The add endpoint treats a Figma payload as the complete set: any stored Figma entry
    whose link is missing from it is deleted. This reads the same rows that comparison
    runs over — the project-level entries filed under source FIGMA / source type DESIGN —
    so the import can carry them forward instead of wiping them.

    Returns:
        dict: {'status': 'OK', 'entries': [{'kb_id', 'doc_name', 'imageLink', 'apiKey'}]}
        or a failure envelope.
    """
    response = await make_api_request('GET', '/v1/knowledgebase/list', api_key, params={
        'appId': str(project_id),
        'teamId': str(team_id),
        'kbSource': _KB_FIGMA_SOURCE,
        'kbSourceType': _KB_FIGMA_SOURCE_TYPE,
        # Project-level entries only, matching the scope the add endpoint compares against.
        'isOnlyProjectKB': 1,
    })

    if response.get('status') != 'OK':
        logger.error(f"_fetch_existing_figma_links: Failed to read existing Figma entries: "
                     f"{response.get('message')}")
        return _fail('Could not read the existing Figma entries',
                     f"{response.get('message', 'The knowledge base list could not be read')}. "
                     f"Not importing, because a Figma import replaces the project's whole set "
                     f"of Figma frames and the existing ones could not be preserved.",
                     error_type='DocumentFetchError')

    entries = []
    for row in response.get('kbDetails') or []:
        connection_details = row.get('connection_details')
        if isinstance(connection_details, str):
            try:
                connection_details = json.loads(connection_details)
            except ValueError:
                logger.warning(f"_fetch_existing_figma_links: Unreadable connection_details on "
                               f"kb_id={row.get('kb_id')}")
                continue
        figma = (connection_details or {}).get('figma') or {}
        if figma.get('url'):
            entries.append({'kb_id': row.get('kb_id'), 'doc_name': figma.get('filename', ''),
                            'imageLink': figma['url'], 'apiKey': figma.get('accessToken', '')})

    logger.info(f"_fetch_existing_figma_links: {len(entries)} Figma entry(s) already in "
                f"project_id={project_id}")
    return {'status': 'OK', 'entries': entries}

def _unsupported_extension_error(filename: str, ext: str) -> dict:
    """Build the shared 'this file type is not accepted' failure envelope."""
    return {
        'status': 'failed',
        'error': f'Unsupported extension .{ext}' if ext else 'Missing file extension',
        'error_type': 'ValidationError',
        'message': (f"'{filename}' is not a document type the knowledge base accepts. "
                    f"Allowed: {', '.join('.' + e for e in sorted(_KB_DOC_EXTS))}.")
    }


def _collect_upload_files(file_paths: List[str], source_url: Optional[str],
                          source_url_filename: Optional[str]) -> dict:
    """
    Read the user-supplied documents into multipart fields for the upload.

    `source_url` is downloaded to a temp file (Google Drive / Dropbox share links are
    normalised to direct-download URLs first); local `file_paths` are read as-is. Every
    file is validated for extension and size before being read into memory, and temp
    files are always removed before returning.

    Returns:
        dict: {'status': 'OK', 'files': [(field, (filename, content, content_type))],
               'filenames': [str]} or a failure envelope.
    """
    # Maps each temp-file path -> the display name to upload it under. Every path
    # registered here is unlinked in the finally block regardless of how we exit.
    tmp_display: dict = {}

    try:
        if source_url and not file_paths:
            download_url = _normalise_share_url(source_url)

            if source_url_filename:
                # User supplied the filename — validate the extension before downloading.
                safe_name = os.path.basename(source_url_filename)
                url_ext = os.path.splitext(safe_name)[1].lstrip('.').lower()
                if url_ext not in _KB_DOC_EXTS:
                    return _unsupported_extension_error(safe_name, url_ext)
                download_suffix = f'.{url_ext}'
            else:
                # Try the URL path first (cheap, no network); fall back to the
                # Content-Disposition header of the download response.
                path_name = (_infer_filename_from_url_path(download_url)
                             or _infer_filename_from_url_path(source_url))
                inferred_ext = os.path.splitext(path_name)[1].lstrip('.').lower() if path_name else ''
                if inferred_ext in _KB_DOC_EXTS:
                    safe_name = os.path.basename(path_name)
                    download_suffix = f'.{inferred_ext}'
                else:
                    safe_name = None
                    download_suffix = '.tmp'

            try:
                tmp_path, content_disposition_name = _download_url_tmp(
                    download_url, download_suffix,
                    max_bytes=_KB_MAX_FILE_SIZE_MB * 1024 * 1024)
            except Exception as e:
                logger.error(f"_collect_upload_files: Download failed for '{source_url}': {e}")
                return {
                    'status': 'failed',
                    'error': 'Failed to download file from source_url',
                    'error_type': 'IOError',
                    'message': (f"Could not download '{source_url}': {e}. Make sure the link is set to "
                                "'Anyone with the link' (not restricted to signed-in users).")
                }

            # Register the temp file for cleanup before any further early return.
            tmp_display[tmp_path] = safe_name or ''

            if safe_name is None:
                # Filename still unknown — take it from the response headers.
                if not content_disposition_name:
                    return {
                        'status': 'failed',
                        'error': 'Could not determine filename from URL or response headers',
                        'error_type': 'ValidationError',
                        'message': ("Could not auto-detect the filename. Pass source_url_filename with the "
                                    "original filename and extension (e.g. 'PRD.pdf').")
                    }
                safe_name = os.path.basename(content_disposition_name)
                detected_ext = os.path.splitext(safe_name)[1].lstrip('.').lower()
                if detected_ext not in _KB_DOC_EXTS:
                    return _unsupported_extension_error(safe_name, detected_ext)
                tmp_display[tmp_path] = safe_name

            file_paths = [tmp_path]

        files = []
        filenames = []
        for index, path in enumerate(file_paths):
            if not os.path.isfile(path):
                return {
                    'status': 'failed',
                    'error': f'File not found: {path}',
                    'error_type': 'ValidationError',
                    'message': (f"Could not find a readable file at '{path}'. Ask the user for the exact "
                                "absolute path, or for a Google Drive/Dropbox link to use as source_url.")
                }

            # Extension check: only for real disk paths — temp paths are validated above.
            if path not in tmp_display:
                ext = os.path.splitext(path)[1].lstrip('.').lower()
                if ext not in _KB_DOC_EXTS:
                    return _unsupported_extension_error(os.path.basename(path), ext)

            display_name = tmp_display.get(path) or os.path.basename(path)

            file_size = os.path.getsize(path)
            if file_size > _KB_MAX_FILE_SIZE_MB * 1024 * 1024:
                return {
                    'status': 'failed',
                    'error': 'File too large',
                    'error_type': 'ValidationError',
                    'message': (f"'{display_name}' is {file_size / (1024 * 1024):.1f}MB. The knowledge base "
                                f"accepts files up to {_KB_MAX_FILE_SIZE_MB}MB.")
                }

            try:
                with open(path, 'rb') as file_handle:
                    content = file_handle.read()
            except OSError as e:
                return {
                    'status': 'failed',
                    'error': f'Could not read file: {path}',
                    'error_type': 'IOError',
                    'message': str(e)
                }

            content_type = mimetypes.guess_type(display_name)[0] or 'application/octet-stream'
            # One field per file: choose_file_0, choose_file_1, ...
            files.append((f"{_KB_UPLOAD_FIELD_PREFIX}_{index}", (display_name, content, content_type)))
            filenames.append(display_name)

        return {'status': 'OK', 'files': files, 'filenames': filenames}

    finally:
        for tmp_path in list(tmp_display):
            try:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except OSError:
                pass

def _collect_doc_import_file(file_path: Optional[str], source_url: Optional[str],
                             source_url_filename: Optional[str]) -> dict:
    """
    Read the Markdown/CSV/Excel file a document import uploads.

    Same two ways in as the knowledge base upload — a local path or a share link the
    server downloads — but only one file per call, since the API's importDocPages endpoint
    reads a single `importFile` field and the import type follows from its extension.

    Returns:
        dict: {'status': 'OK', 'files': [(field, (filename, content, content_type))],
        'filename': str, 'import_type': str} or a failure envelope.
    """
    tmp_path = None
    try:
        if source_url:
            download_url = _normalise_share_url(source_url)
            path_name = (source_url_filename
                         or _infer_filename_from_url_path(download_url)
                         or _infer_filename_from_url_path(source_url))
            display_name = os.path.basename(path_name) if path_name else ''
            extension = os.path.splitext(display_name)[1].lstrip('.').lower()
            if extension not in _KB_DOC_IMPORT_TYPES:
                return _fail('Unsupported file for a document import',
                             f"Could not tell from '{source_url}' that the file is one this "
                             f"import accepts ({', '.join('.' + e for e in sorted(_KB_DOC_IMPORT_TYPES))}). "
                             f"Pass source_url_filename with the original filename and extension.")

            try:
                tmp_path, _ = _download_url_tmp(
                    download_url, f'.{extension}',
                    max_bytes=_KB_DOC_IMPORT_MAX_FILE_SIZE_MB * 1024 * 1024)
            except Exception as e:
                logger.error(f"_collect_doc_import_file: Download failed for '{source_url}': {e}")
                return _fail('Failed to download file from source_url',
                             f"Could not download '{source_url}': {e}. Make sure the link is set "
                             f"to 'Anyone with the link' (not restricted to signed-in users).",
                             error_type='IOError')
            path = tmp_path
        else:
            path = file_path
            if not os.path.isfile(path):
                return _fail(f'File not found: {path}',
                             f"Could not find a readable file at '{path}'. Ask the user for the "
                             f"exact absolute path, or for a Google Drive/Dropbox link to use as "
                             f"source_url.")
            display_name = os.path.basename(path)
            extension = os.path.splitext(display_name)[1].lstrip('.').lower()
            if extension not in _KB_DOC_IMPORT_TYPES:
                return _fail(f'Unsupported extension .{extension}' if extension
                             else 'Missing file extension',
                             f"'{display_name}' is not a file type a knowledge base document "
                             f"import accepts. Allowed: "
                             f"{', '.join('.' + e for e in sorted(_KB_DOC_IMPORT_TYPES))}.")

        file_size = os.path.getsize(path)
        if file_size > _KB_DOC_IMPORT_MAX_FILE_SIZE_MB * 1024 * 1024:
            return _fail('File too large',
                         f"'{display_name}' is {file_size / (1024 * 1024):.1f}MB. A document "
                         f"import accepts files up to {_KB_DOC_IMPORT_MAX_FILE_SIZE_MB}MB.")

        try:
            with open(path, 'rb') as file_handle:
                content = file_handle.read()
        except OSError as e:
            return _fail(f'Could not read file: {path}', str(e), error_type='IOError')

        content_type = mimetypes.guess_type(display_name)[0] or 'application/octet-stream'
        return {
            'status': 'OK',
            'files': [('importFile', (display_name, content, content_type))],
            'filename': display_name,
            'import_type': _KB_DOC_IMPORT_TYPES[extension],
        }

    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
