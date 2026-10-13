"""MCP prompt registrations."""
from config.config import MCP_CONNECT_URL
from core.app import mcp


@mcp.prompt(title="Connect to Bugasura")
def connect_bugasura() -> str:
    """
    How authentication works and what to tell the user when a tool returns
    status 'api_key_required'. Tools carry no credential arguments any more.
    """
    return f"""
Bugasura MCP signs users in with OAuth 2.0 when used over HTTP, and falls back to an
API key only for local STDIO setups.

**Hosted / HTTP (recommended)** — the MCP client handles sign-in; tools take no key.
- Claude Desktop / claude.ai: Settings → Connectors → Add custom connector →
  URL `{MCP_CONNECT_URL}` → Connect → sign in to Bugasura → Allow.
- Claude Code: `claude mcp add --transport http bugasura {MCP_CONNECT_URL}`,
  then run `/mcp`, pick Bugasura → Authenticate.
- Cursor / VS Code / Windsurf / Cline / Roo Code: add the URL; the client detects
  OAuth and opens the browser on first use.
Access tokens last 1 hour and refresh silently for 30 days.

**Local STDIO** — set `BUGASURA_API_KEY` in the server's `env` block
(Bugasura → User Settings → API Key) and restart the client.

**When a tool returns `status: 'api_key_required'`**
- Do NOT ask the user to paste an API key; tools no longer accept one.
- HTTP: tell the user to reconnect / re-authorize Bugasura in their MCP client, then retry.
- STDIO: tell the user to set `BUGASURA_API_KEY` and restart the client.
"""


@mcp.prompt(title="Knowledge Base Upload Guide")
def kb_upload_guide() -> str:
    """
    Instructions for AI assistants on how to handle file uploads to a Bugasura
    TestPert knowledge base. Invoke this prompt whenever a user asks to upload
    a document or image to a TestPert sprint.
    """
    return """
# Bugasura KB File Upload — AI Assistant Guide

## The correct upload flow

Never read, encode, or process an attached file yourself: file bytes must not pass through
the conversation. Call bugasura_prepare_kb_upload first; it returns the wording to show.

### Documents (.txt, .pdf, .doc, .docx, .md) on the user's computer
1. Call bugasura_create_upload_link and show the user its upload_url.
   In a terminal client with shell access you may upload a file the user named yourself:
   `curl -sS -F file=@/path/to/PRD.pdf <upload_url>`.
2. When the upload is done, call bugasura_upload_knowledge_base_document(upload_id=...).
3. For a TestPert sprint, link the returned kb_ids with
   bugasura_testpert_upload_kb(existing_kb_ids=[...], sprint_id=...).

### Files already in Google Drive or Dropbox
Ask for a share link set to 'Anyone with the link' and pass it as source_url to
bugasura_upload_knowledge_base_document (documents) or bugasura_testpert_upload_kb
(images, with the matching kb_type). Drive and Dropbox links are auto-converted.

### Local STDIO server
Ask for the exact absolute path on the user's machine and pass file_paths=[...].

### kb_type guide
| File                                      | kb_type             |
|-------------------------------------------|---------------------|
| PRD, spec, doc, PDF, DOCX, MD             | document            |
| API documentation                         | api_docs            |
| Meeting notes                             | meeting_notes       |
| User flow documents                       | user_flow           |
| Test data files                           | test_data           |
| Architecture diagrams                     | architecture_image  |
| Database schema diagrams                  | db_schema_image     |
| Wireframes                                | wireframe_image     |
| UI / design images                        | design_image        |
| Flow diagrams, screenshots                | flow_image          |

### Multiple files
One upload link takes up to 10 documents (100 MB in total), and each
bugasura_upload_knowledge_base_document call adds all of them to the same folder.
"""


@mcp.prompt(title="Project Search Guidance")
def search_projects_guidance() -> str:
    """
    Guidance for AI assistants on how to handle project search/listing when user
    doesn't specify a team.

    This prompt instructs AI assistants on the best approach to discover projects
    across multiple teams.
    """
    return """
# Project Discovery Guidance for AI Assistants

When a user asks to "list projects", "find project", or "search for projects"
WITHOUT specifying a team:

## Best Approach - Use bugasura_find_project_by_name()

If the user mentions a project name or keyword:
✓ Use: bugasura_find_project_by_name(project_name)
  - Searches across ALL teams automatically
  - Returns project_id and team_id for each match
  - Supports partial, case-insensitive matching

Example user requests:
- "Find my mobile app project"
- "Search for projects with 'api' in the name"
- "Show me the authentication project"

## Alternative Approach - Use bugasura_get_user_context()

If the user wants to see ALL projects (no search term):
✓ Use: bugasura_get_user_context()
  - Returns all teams and their projects in one call
  - Shows complete project hierarchy
  - More efficient than calling bugasura_list_teams() then bugasura_list_projects() for each team

Example user requests:
- "List all my projects"
- "Show me all projects I have access to"
- "What projects are available?"

## When to Use bugasura_list_projects()

ONLY use bugasura_list_projects(team_id) when:
- User specifically mentions a team name or ID
- You've already identified the team_id from previous context
- User wants filtered/paginated results for a specific team

Example user requests:
- "List projects in the Acme Corp team"
- "Show me web projects for team 123"

## DO NOT:
❌ Ask user for team_id first when they just want to search/list projects
❌ Use bugasura_list_projects() without team_id (it will fail)
❌ Make the user specify team when it's not necessary

## Best User Experience Flow:
1. User: "Find my mobile project"
2. AI: Calls bugasura_find_project_by_name(project_name="mobile")
3. AI: "I found 2 projects: Mobile App (Team: Acme Corp), Mobile Web (Team: Client XYZ)"
4. User can then work with the discovered project
"""
