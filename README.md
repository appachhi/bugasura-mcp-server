# Bugasura MCP Server

**Connect AI assistants directly to your test management workspace.**

Bugasura MCP Server enables AI tools like Claude, VS Code Copilot, and Cursor to interact with your Bugasura projects—manage test cases, track issues, plan sprints, and more—all through natural language.

[![Website](https://img.shields.io/badge/Website-bugasura.io-blue)](https://bugasura.io)

---

## Features

- 📋 **Test Case Management** - Create, update, delete, and search test cases
- 🐛 **Issue Tracking** - Report, manage, and delete bugs with rich context
- 🏃 **Sprint Planning** - Create, update, delete, and manage agile sprints
- 👥 **Team Collaboration** - Assign work using names or emails (auto-resolves to user IDs)
- 🔍 **Smart Discovery** - Find projects and teams without memorizing IDs
- 🤖 **Interactive Workflows** - Guided context selection for all operations

---

## Quick Start

### 1. Get Your API Key

1. Go to [Bugasura](https://bugasura.io)
2. Navigate to: **Settings → API Key**
3. Copy your API key

### 2. Install the MCP Server

Choose your AI tool:

<details>
<summary><b>Claude Desktop</b></summary>

Open Claude Desktop → Settings → Connectors → Add Custom Connector

- Name: `Bugasura`
- URL: `https://mcp.bugasura.io/sse`

</details>

<details>
<summary><b>VS Code</b></summary>

Add to your VS Code MCP config:

```json
{
  "servers": {
    "bugasura": {
      "type": "https",
      "url": "https://mcp.bugasura.io/sse"
    }
  }
}
```

[VS Code MCP Documentation](https://code.visualstudio.com/docs/copilot/chat/mcp-servers)

</details>

<details>
<summary><b>Claude Code</b></summary>

```bash
claude mcp add --transport http bugasura https://mcp.bugasura.io/sse
```

[Claude Code MCP Documentation](https://docs.anthropic.com/en/docs/claude-code/mcp)

</details>

<details>
<summary><b>Cursor</b></summary>

Add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "bugasura": {
      "url": "https://mcp.bugasura.io/sse",
      "type": "https"
    }
  }
}
```

</details>

<details>
<summary><b>Windsurf</b></summary>

Add to your Windsurf MCP config:

```json
{
  "mcpServers": {
    "bugasura": {
      "serverUrl": "https://mcp.bugasura.io/sse"
    }
  }
}
```

[Windsurf MCP Documentation](https://docs.windsurf.com/windsurf/cascade/mcp)

</details>

<details>
<summary><b>Cline</b></summary>

1. Open Cline
2. Click ☰ → **MCP Servers** → **Remote Servers** tab
3. Click **Edit Configuration**
4. Add:

```json
{
  "mcpServers": {
    "bugasura": {
      "url": "https://mcp.bugasura.io/sse",
      "type": "streamableHttp"
    }
  }
}
```

</details>

<details>
<summary><b>Roo Code</b></summary>

```json
{
  "mcpServers": {
    "bugasura": {
      "type": "streamable-http",
      "url": "https://mcp.bugasura.io/sse"
    }
  }
}
```

[Roo Code MCP Documentation](https://docs.roocode.com/features/mcp/using-mcp-in-roo)

</details>

### 3. Start Using It

Once installed, just talk naturally to your AI assistant:

```
"List all my Bugasura teams and projects"
```

```
"Create a test case for login functionality with high severity"
```

```
"Show me all critical bugs in sprint 5"
```

---

## How It Works

### No IDs Required

Bugasura MCP features **interactive context selection**. You don't need to know team IDs, project IDs, or user IDs—just describe what you want in natural language.

**Example:** Creating an issue without knowing any IDs:

```
You: "Create a bug for the login button not working"

AI: [Calls MCP server]
    "Which team should I use?
     1. Acme Corp (Admin)
     2. Client Project (Member)"

You: "Acme Corp"

AI: "Which project?
     1. Mobile App
     2. Web App"

You: "Mobile App"

AI: "Which sprint?
     1. Sprint 5 (IN PROGRESS)
     2. Sprint 6 (SCHEDULED)"

You: "Sprint 5"

AI: ✓ "Created issue #ISSUE-123 in Sprint 5"
```

The system guides you through team → project → sprint selection automatically.

### Smart Assignee Resolution

Assign work using **names, emails, or user IDs**—the system automatically converts them:

```
"Assign issue 123 to John Doe"
```

```
"Add jane@example.com and user 789 to issue 456"
```

```
"Remove Sarah from issue 321"
```

Works for both issues and test cases.

### Discovery Tools

Find resources without memorizing IDs:

```
"Find my mobile app project"
→ Searches across ALL teams automatically
```

```
"Show me all projects I have access to"
→ Returns complete context in one call
```

---

## What You Can Do

### 📋 Test Cases

```
Create an API test case for user authentication with priority P1
```

```
List all test cases for the mobile app project
```

```
Update test case 123 to mark it as PASS
```

```
Assign test case 456 to john@example.com
```

```
Delete test case 789
```

```
Delete test case with key "TES5"
```

```
Delete test case named "Verify login with valid credentials"
```

### 🐛 Issues & Bugs

```
Create a critical bug for login page crash in sprint 5
```

```
Show me all open issues assigned to me
```

```
Update issue 789 to change status to "Fixed"
```

```
Add John and Jane as assignees to issue 123
```

```
Delete issue 456
```

```
Delete issue with key "ISS09"
```

```
Delete issue with summary "Login button not working"
```

### 🏃 Sprints

```
Create a new sprint called "Sprint 15" for the mobile app
```

```
List all sprints for project 456
```

```
Update sprint 789 to mark it as COMPLETED
```

```
Show sprint details including issue statistics
```

```
Delete sprint 321
```

```
Delete sprint named "Sprint 15"
```

### 👥 Team Management

```
List all members of team 123
```

```
Find my team by name "Acme"
```

```
Show all projects in team 456
```

---

## Available Tools

<details>
<summary><b>Context & Discovery</b></summary>

- `get_user_context` - Get all teams and projects in one call
- `find_team_by_name` - Search teams by name
- `find_project_by_name` - Search projects across all teams
- `list_teams` - List all teams you belong to
- `list_projects` - List projects for a specific team
- `get_project_details` - Get detailed project information
- `list_team_members` - List team members with IDs, names, and emails

</details>

<details>
<summary><b>Sprint Management</b></summary>

- `list_sprints` - List all sprints for a project
- `get_sprint_details` - Get sprint info and statistics
- `create_sprint` - Create a new sprint
- `update_sprint` - Update sprint details (partial updates supported)
- `delete_sprint` - Delete a sprint permanently (supports ID or name)

**Note:** All sprint tools support interactive context selection. Delete operations can be performed using either numeric IDs or names.

</details>

<details>
<summary><b>Issue Management</b></summary>

- `list_issues` - List issues with optional sprint filter
- `get_issue` - Get detailed issue information
- `create_issue` - Create a new bug/issue
- `update_issue` - Update issue details (partial updates supported)
- `delete_issue` - Delete an issue permanently (supports ID, issue key like "ISS09", or summary/title)
- `add_issue_assignees` - Add assignees by name, email, or ID
- `remove_issue_assignees` - Remove assignees by name, email, or ID

**Note:** All issue tools support interactive context selection. Delete operations can be performed using numeric IDs, issue keys (e.g., "ISS09"), or issue summaries.

</details>

<details>
<summary><b>Test Case Management</b></summary>

- `list_test_cases` - List test cases for a project
- `get_test_case` - Get detailed test case information
- `create_test_case` - Create a new test case
- `update_test_case` - Update test case (partial updates supported, assignees by name/email/ID)
- `delete_test_case` - Delete a test case permanently (supports ID, test case key like "TES5", or scenario name)

**Note:** All test case tools support interactive context selection. Delete operations can be performed using numeric IDs, test case keys (e.g., "TES5"), or scenario names.

</details>

---

## Available Resources

MCP resources provide read-only access to your Bugasura data. AI assistants can access these directly:

| Resource | Description |
|----------|-------------|
| `bugasura://teams` | All teams you belong to |
| `bugasura://teams/{team_id}/projects` | Projects in a team |
| `bugasura://projects/{project_id}/sprints` | Sprints in a project |
| `bugasura://projects/{project_id}/issues` | Issues in a project |
| `bugasura://projects/{project_id}/test-cases` | Test cases in a project |

---

## Advanced Usage

### Pagination

List operations return 10 results by default:

```
Show me the first 20 issues (using max_results=20)
```

```
Show me issues 11-20 (using start_at=10, max_results=10)
```

### Partial Updates

Update only the fields you want to change:

```
Update issue 123 to change severity to HIGH
(other fields remain unchanged)
```

### Custom Fields

```
Create issue with custom fields: {"Environment": "Production", "Build": "1.2.3"}
```

### Filtering

```
List issues for sprint 5 only
```

```
Search projects containing "mobile" in the name
```

---

## Transport Modes

Bugasura MCP supports two transport modes:

**STDIO** (Default) - For local MCP clients
```bash
python server.py --transport stdio
```

**SSE** (Server-Sent Events) - For remote deployment
```bash
python server.py --transport sse
```

The hosted version at `https://mcp.bugasura.io/sse` uses SSE transport.

---

## Important Notes

### API Key

All operations require a Bugasura API key. Get yours from [Bugasura Settings](https://bugasura.io).

**IMPORTANT:** Do not use placeholders like `$BUGASURA_API_KEY`. The server detects and rejects placeholder values.

### Interactive Mode

If you don't provide `team_id` or `project_id`, the system automatically enters interactive mode and guides you through selection. This works for:
- All sprint operations
- All issue operations
- All test case operations

### Smart Assignees

When assigning work, you can use:
- **Names**: `"John Doe"` (partial match, case-insensitive)
- **Emails**: `"john@example.com"` (exact match, case-insensitive)
- **User IDs**: `"123"` (direct match)
- **Mixed**: `"John, jane@example.com, 789"` (comma-separated)

The system automatically resolves names/emails to user IDs.

### Sprint Requirements

- Sprint names must be 5-250 characters
- Issues must be assigned to a sprint
- Updates require the issue to have a sprint assigned

---

## Example Conversations

### Getting Started

```
"What teams and projects do I have access to?"
→ Returns all your teams and projects

"Find my authentication project"
→ Searches across all teams and returns matches
```

### Test Management

```
"Create a test case for password reset with severity HIGH and priority P1"
→ Guides you through team/project selection, then creates test case

"List all test cases in my mobile app project"
→ Returns paginated test case list

"Update test case 456 to mark it as PASS and assign to john@example.com"
→ Updates test case and resolves email to user ID
```

### Bug Tracking

```
"Show me all critical bugs in sprint 5"
→ Lists critical severity issues filtered by sprint

"Create a bug: Login button crashes on iOS 17"
→ Guides through team/project/sprint selection, creates issue

"Assign issue 789 to Jane and mark it as In Progress"
→ Updates assignee and status
```

### Sprint Planning

```
"Create a 2-week sprint called 'Sprint 16' starting next Monday"
→ Guides through project selection, creates sprint with dates

"Show me sprint statistics for sprint 5"
→ Returns issue counts, completion rates, etc.

"Mark sprint 12 as COMPLETED"
→ Updates sprint status
```

---

## Support

- 🌐 [Website](https://bugasura.io)
- 📧 Contact support for assistance
- 📚 [API Documentation](https://docs.bugasura.io)

---

## License

MIT

---
