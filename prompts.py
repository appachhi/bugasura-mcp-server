"""MCP prompt registrations."""
from app import mcp


@mcp.prompt()
def setup_api_key() -> str:
    """
    Prompt to help AI assistants guide users through initial API key setup.

    This prompt instructs AI assistants to:
    1. Ask the user for their Bugasura API key (not use placeholder values)
    2. Guide them through getting their API key if they don't have it
    3. Validate the API key before proceeding

    IMPORTANT: AI assistants should first check if the API key is already
    configured (env var for STDIO, request header for streamable-HTTP). If it
    is, use it directly without prompting. Only ask the user for their API key
    if no configured source provides one.
    """
    return """
Welcome to Bugasura MCP! To get started, I need your Bugasura API key.

**API key resolution order (server-side):**

1. **Tool-call argument** — if a tool is invoked with an `api_key` parameter,
   that value is used.
2. **HTTP request header** (streamable-HTTP transport only) —
   `X-Bugasura-API-Key: <key>`, or `Authorization: Basic <key>` as fallback.
   Set this in your MCP client's `headers` block for hosted servers.
3. **`BUGASURA_API_KEY` environment variable** — set via the MCP client's
   `env` block (Claude Desktop / Cursor / Claude Code STDIO config), via
   systemd `EnvironmentFile=`, via the project `.env` file, or via the shell.
4. **Ask the user** — if no source above provides a key, the tool returns
   `status: 'api_key_required'` and the assistant should prompt the user.

**IMPORTANT FOR AI ASSISTANTS**:
- Try the tool first WITHOUT an `api_key` argument. The server will use the
  configured env var or request header if available, so most users never need
  to type their key.
- Only ask the user for their key if a tool returns `status: 'api_key_required'`.
- Once the user provides one, pass it via the `api_key` parameter on retry.
- NEVER pass placeholder values like `$BUGASURA_API_KEY` or `YOUR_API_KEY`.

**Instructions for Users**:

1. **Option A - Configure in MCP Client** (Recommended):
   - **STDIO clients** (Claude Desktop, local Cursor/VS Code): set
     `BUGASURA_API_KEY` in the MCP server's `env` block.
   - **HTTP clients** (hosted Bugasura MCP, e.g. mcp.bugasura.io): set
     `X-Bugasura-API-Key` in the MCP server's `headers` block.
   Either way, tools pick the key up automatically with no prompting.

2. **Option B - Get Your API Key**:
   - Go to https://bugasura.io
   - Navigate to: User Settings → API Key
   - Copy your API key and provide it when prompted

3. **Next Steps**:
   Once the API key is available, I will:
   - Validate it
   - Show you your available teams and projects
   - Help you create/manage issues, test cases, and sprints

**Security Note**: Your API key is never logged in full (only first 8 characters for debugging).
"""


@mcp.prompt()
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

## Best Approach - Use find_project_by_name()

If the user mentions a project name or keyword:
✓ Use: find_project_by_name(api_key, project_name)
  - Searches across ALL teams automatically
  - Returns project_id and team_id for each match
  - Supports partial, case-insensitive matching

Example user requests:
- "Find my mobile app project"
- "Search for projects with 'api' in the name"
- "Show me the authentication project"

## Alternative Approach - Use get_user_context()

If the user wants to see ALL projects (no search term):
✓ Use: get_user_context(api_key)
  - Returns all teams and their projects in one call
  - Shows complete project hierarchy
  - More efficient than calling list_teams() then list_projects() for each team

Example user requests:
- "List all my projects"
- "Show me all projects I have access to"
- "What projects are available?"

## When to Use list_projects()

ONLY use list_projects(api_key, team_id) when:
- User specifically mentions a team name or ID
- You've already identified the team_id from previous context
- User wants filtered/paginated results for a specific team

Example user requests:
- "List projects in the Acme Corp team"
- "Show me web projects for team 123"

## DO NOT:
❌ Ask user for team_id first when they just want to search/list projects
❌ Use list_projects() without team_id (it will fail)
❌ Make the user specify team when it's not necessary

## Best User Experience Flow:
1. User: "Find my mobile project"
2. AI: Calls find_project_by_name(api_key, "mobile")
3. AI: "I found 2 projects: Mobile App (Team: Acme Corp), Mobile Web (Team: Client XYZ)"
4. User can then work with the discovered project
"""
