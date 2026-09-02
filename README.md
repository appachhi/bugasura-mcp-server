# Bugasura MCP Server

**Connect AI assistants directly to your test management workspace.**

Bugasura MCP Server enables AI tools like Claude, VS Code Copilot, and Cursor to interact with your Bugasura projects—manage test cases, track issues, plan sprints, and more—all through natural language.

[![Website](https://img.shields.io/badge/Website-bugasura.io-blue)](https://bugasura.io)

---

## ⚠️ Breaking changes in 2.0

If you're upgrading from 1.x, update your client configuration:

| What changed | 1.x | 2.0 |
|--------------|-----|-----|
| Tool names | `create_issue`, `list_teams`, … | `bugasura_create_issue`, `bugasura_list_teams`, … (prefixed to coexist with other MCP servers) |
| Default HTTP endpoint | `/sse` (SSE) | `/mcp` (streamable HTTP) |
| List/find responses | `{status, project_list, …}` (upstream shape) | Standard pagination envelope `{status, total, count, offset, items, has_more, next_offset}` — legacy keys remain as extras for one release |

1.x clients pointed at `/sse` must migrate to `/mcp` — SSE has been removed.

---

## Features

- 📋 **Test Case Management** - Create, update, delete, and search test cases
- 💬 **Test Case Comments** - Add, update, delete, and list comments on test cases with pagination and filtering
- 🐛 **Issue Tracking** - Report, manage, and delete bugs with rich context
- 💬 **Issue Comments** - Add, update, delete, and list comments on issues with pagination and filtering
- 📝 **Requirements Management** - Create, organize, and manage product requirements with folder structure
- 📚 **Knowledge Base** - Upload, list, star, and delete documents in a project's knowledge base, with folders created on demand; import from a website, Coda, Jira, Confluence or Figma
- 🏃 **Sprint Planning** - Create, update, delete, and manage agile sprints
- 🏁 **Test Runs** - Create one-time or scheduled (recurring) runs, edit/rerun/delete them, pick environments and app builds, and add test cases — all by name or ID
- 🤖 **Testpert Sprints** - Full AI-driven test enrichment flow: upload specs, answer requirement questions, edit the test plan, and generate test cases automatically
- 👥 **Team Collaboration** - Assign work using names or emails (auto-resolves to user IDs)
- 👤 **Team Member Management** - Add, update roles, and remove team members using team names or IDs
- 🔍 **Smart Discovery** - Find projects and teams without memorizing IDs
- 🤖 **Interactive Workflows** - Guided context selection for all operations

---

## Quick Start

### 1. Get Your API Key

1. Go to [Bugasura](https://bugasura.io)
2. Navigate to: **Settings → API Key**
3. Copy your API key

### 2. Install the MCP Server

Choose your AI tool and configure with your API key. The server reads the key from the request `X-Bugasura-API-Key` header (HTTP transport) or the `BUGASURA_API_KEY` environment variable (STDIO transport) — when configured, tools use it automatically without prompting. If no key is configured, tools return `status: 'api_key_required'` and the assistant asks you for one.

<details>
<summary><b>Claude Desktop</b></summary>

Open Claude Desktop → Settings → Connectors → Add Custom Connector

- Name: `Bugasura`
- URL: `https://mcp.bugasura.io/mcp`

</details>

<details>
<summary><b>VS Code</b></summary>

Add to your VS Code MCP config:

```json
{
  "servers": {
    "bugasura": {
      "type": "https",
      "url": "https://mcp.bugasura.io/mcp",
      "headers": {
        "X-Bugasura-API-Key": "your_api_key_here"
      }
    }
  }
}
```

[VS Code MCP Documentation](https://code.visualstudio.com/docs/copilot/chat/mcp-servers)

</details>

<details>
<summary><b>Claude Code</b></summary>

```bash
claude mcp add --transport http bugasura https://mcp.bugasura.io/mcp --header "X-Bugasura-API-Key: your_api_key_here"
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
      "url": "https://mcp.bugasura.io/mcp",
      "type": "https",
      "headers": {
        "X-Bugasura-API-Key": "your_api_key_here"
      }
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
      "serverUrl": "https://mcp.bugasura.io/mcp",
      "headers": {
        "X-Bugasura-API-Key": "your_api_key_here"
      }
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
      "url": "https://mcp.bugasura.io/mcp",
      "type": "streamableHttp",
      "headers": {
        "X-Bugasura-API-Key": "your_api_key_here"
      }
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
      "url": "https://mcp.bugasura.io/mcp",
      "headers": {
        "X-Bugasura-API-Key": "your_api_key_here"
      }
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
"Create a requirement for user authentication feature"
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

### 💬 Test Case Comments

```
List all comments on test case 123
```

```
List comments on test case "Verify login with valid credentials"
```

```
List only user comments on test case 456 (exclude system comments)
```

```
Get details of comment 789
```

```
Add a comment "Test passed on Chrome and Firefox" to test case 123
```

```
Add a private comment to test case 456
```

```
Update comment 789 with new text
```

```
Delete comment 456
```

### 📝 Requirements

```
Create a requirement titled "User Authentication" with details and priority P1
```

```
List all requirements for the mobile app project
```

```
Get requirement details for requirement ID 2036
```

```
Update requirement 2036 to change severity to HIGH
```

```
Assign requirement 456 to john@example.com
```

```
Create a folder named "Sprint 1 Features" for organizing requirements
```

```
List all requirement folders in a project
```

```
Delete requirement 789
```

```
Link test cases to requirement 2036
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

### 💬 Issue Comments

```
List all comments on issue 123
```

```
List comments with pagination (start at 10, show 20 results)
```

```
List only user comments, exclude system comments
```

```
Get details of comment 456
```

```
Add a comment "Fixed in latest build" to issue 789
```

```
Add a private comment to issue 123
```

```
Update comment 456 with new text
```

```
Delete comment 789
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

### 🏁 Test Runs

```
List the test runs for the "Login Sprint"
```

```
Show me the environments and app builds for this project
```

```
Create a test run called "Smoke run" for the "Login Sprint" using the "Staging" environment
```

```
Schedule a daily run "Nightly" for the "Login Sprint" at 09:00, ending after 10 runs
```

```
Schedule a run every 2 weeks on Monday and Friday at 09:00
```

```
Add test cases 12, 15, 18 to the "Smoke run" run
```

```
Rename the "Smoke run" run and mark it COMPLETED
```

```
Pause the "Nightly" scheduler
```

```
Rerun the "Nightly" scheduler
```

```
Delete the "Smoke run" run
```

**Note:** Reports/suites, environments, app builds, runs, and schedulers can all be referenced by **name or numeric ID** — names are resolved automatically (with a helpful prompt if a name is ambiguous).

### 🤖 Testpert Sprints

TestPert is a paid, project-level feature that uses AI to generate a full test plan and test cases from your requirement documents.

**Normal flow** (with document upload):
```
Create a TestPert sprint called "Login Feature Sprint"
```
```
Upload /path/to/login-spec.pdf to the knowledge base
```
```
Start the analysis and answer the requirement questions
```
```
Review the test plan focus areas and feature tree
```
```
Generate test cases for the sprint
```

**Skip-enrich flow** (driven from existing requirements):
```
Create a TestPert sprint with skip_enrich_requirements=true
```
```
Link requirement IDs 101 and 102 to the sprint
```
```
Build the test plan from those requirements
```

### 📋 Projects

```
List all projects in team 123
```

```
Find project by name "Mobile App"
```

```
Get detailed information for project 456
```

```
Create a new project "E-commerce Web App" in team 123
```

```
Update project 789 name to "Mobile Application"
```

```
Update project "Mobile App" to change issue prefix to "MOB"
```

```
Delete project 321
```

```
Delete project "Old Test Project"
```

### 👥 Team Management

```
List all my teams
```

```
Find team by name "Acme"
```

```
Get detailed information for team 123
```

```
Get detailed information for team "Engineering"
```

```
Create a new team called "Mobile App Team"
```

```
Update team 456 name to "Web Development Team"
```

```
Rename team "Mobile Team" to "Mobile App Development"
```

```
List all members in team "Acme Corp"
```

```
Add john@example.com and jane@example.com to team "Engineering"
```

```
Invite user@example.com to team 123
```

```
Promote user 456 to admin in team "Marketing"
```

```
Demote user to regular member in team "Sales"
```

```
Remove john@example.com from team "Sales"
```

```
Remove user by name "John Doe" from team 123
```

```
Show all projects in team 456
```

---

## Available Tools

<details>
<summary><b>Context & Discovery</b></summary>

- `bugasura_get_user_context` - Get all teams and projects in one call
- `bugasura_find_team_by_name` - Search teams by name
- `bugasura_find_project_by_name` - Search projects across all teams
- `bugasura_list_teams` - List all teams you belong to
- `bugasura_get_team` - Get detailed team information including settings and subscription details (supports team_id or team_name)
- `bugasura_create_team` - Create a new team (creator becomes owner/admin)
- `bugasura_update_team` - Update team name (admin-only, supports team_id or team_name)
- `bugasura_delete_team` - Delete team permanently (admin-only, DESTRUCTIVE, supports team_id or team_name)
- `bugasura_list_team_members` - List team members with IDs, names, emails, and roles
- `bugasura_list_projects` - List projects for a specific team
- `bugasura_get_project_details` - Get detailed project information
- `bugasura_create_project` - Create a new project (supports interactive team selection) *(NEW)*
- `bugasura_update_project` - Update project name, prefix, and settings (supports project_id or project_name, admin privileges may be required) *(NEW)*
- `bugasura_delete_project` - Delete project permanently (supports project_id or project_name, admin-only, DESTRUCTIVE) *(NEW)*

**Smart Team Resolution**: The `bugasura_get_team`, `bugasura_update_team`, and `bugasura_delete_team` tools support both `team_id` (numeric ID) and `team_name` (text name with partial matching). Use whichever is more convenient.

**Smart Project Resolution**: The `bugasura_update_project` and `bugasura_delete_project` tools support both `project_id` (numeric ID) and `project_name` (text name with partial matching) for flexible identification. *(NEW)*

**Note:** Team deletion is permanent and removes all associated projects, sprints, issues, test cases, and requirements. Project deletion is also permanent and removes all associated sprints, issues, and test cases. Use with extreme caution!

</details>

<details>
<summary><b>Team Member Management</b></summary>

- `bugasura_add_team_members` - Invite users to a team by email addresses (supports team_id or team_name)
- `bugasura_update_team_member` - Change team member role (admin/member) (supports team_id or team_name)
- `bugasura_delete_team_user` - Remove a user from team (supports team_id or team_name, auto-resolves user by ID/email/name)

**Smart Team Resolution**: All team member tools support both `team_id` (numeric ID) and `team_name` (text name with partial matching). Use whichever is more convenient.

**Smart User Resolution**: The `bugasura_delete_team_user` tool can identify users by:
- User IDs (e.g., "123")
- Email addresses (e.g., "john@example.com")
- Names or partial names (e.g., "John", "John Doe")

**Note:** Only team admins can manage team members. Team owner cannot be removed.

</details>

<details>
<summary><b>Sprint Management</b></summary>

- `bugasura_list_sprints` - List all sprints for a project
- `bugasura_get_sprint_details` - Get sprint info and statistics
- `bugasura_create_sprint` - Create a new sprint
- `bugasura_update_sprint` - Update sprint details (partial updates supported)
- `bugasura_delete_sprint` - Delete a sprint permanently (supports ID or name)

**Note:** All sprint tools support interactive context selection. Delete operations can be performed using either numeric IDs or names.

</details>

<details>
<summary><b>Issue Management</b></summary>

- `bugasura_list_issues` - List issues with optional sprint filter
- `bugasura_get_issue` - Get detailed issue information
- `bugasura_create_issue` - Create a new bug/issue
- `bugasura_update_issue` - Update issue details (partial updates supported)
- `bugasura_delete_issue` - Delete an issue permanently (supports ID, issue key like "ISS09", or summary/title)
- `bugasura_get_issue_assignees` - Get list of assignees for an issue with names, emails, and profile images
- `bugasura_add_issue_assignees` - Add assignees by name, email, or ID
- `bugasura_remove_issue_assignees` - Remove assignees by name, email, or ID

**Note:** All issue tools support interactive context selection. Delete operations can be performed using numeric IDs, issue keys (e.g., "ISS09"), or issue summaries.

</details>

<details>
<summary><b>Issue Comments</b></summary>

- `bugasura_list_issue_comments` - List comments for an issue with pagination and filtering (supports creator_id filter, exclude system comments)
- `bugasura_get_issue_comment` - Get single comment details with full content and metadata
- `bugasura_add_issue_comment` - Create a new comment on an issue (supports public/private visibility, HTML formatting)
- `bugasura_update_issue_comment` - Update existing comment text (author-only, supports interactive comment selection)
- `bugasura_delete_issue_comment` - Delete comment permanently (author or admin, supports interactive comment selection)

**Key Features:**
- **Pagination**: List comments with `start_at` and `max_results` parameters (default: 10 results, max: 100)
- **Filtering**: Filter by comment author (`creator_id`) or exclude system comments (`get_user_comments_only`)
- **Interactive Selection**: Prompts for team → project → issue → comment if not provided
- **Comment Types**: User comments (editable) vs System comments (auto-generated, read-only)
- **Visibility Control**: Public comments (visible to all) vs Private comments (team members only)
- **HTML Support**: Comments support HTML formatting and user mentions (@username)

**Note:** All comment tools support full interactive context selection, including comment selection for update/delete operations. System comments cannot be edited or deleted.

</details>

<details>
<summary><b>Test Case Management</b></summary>

- `bugasura_list_test_cases` - List test cases for a project
- `bugasura_get_test_case` - Get detailed test case information
- `bugasura_create_test_case` - Create a new test case
- `bugasura_update_test_case` - Update test case (partial updates supported, assignees by name/email/ID)
- `bugasura_delete_test_case` - Delete a test case permanently (supports ID, test case key like "TES5", or scenario name)

**Note:** All test case tools support interactive context selection. Delete operations can be performed using numeric IDs, test case keys (e.g., "TES5"), or scenario names.

</details>

<details>
<summary><b>Test Run Management</b></summary>

- `bugasura_list_test_run_environments` - List test data environments and app builds for a project (use to pick an environment / app build by name)
- `bugasura_list_test_runs` - List test run executions and schedulers for a test suite (report)
- `bugasura_get_test_run_details` - Get details for a single test run execution
- `bugasura_create_test_run` - Create a run — one-time or scheduled (recurring) with friendly recurrence options, environment, app build, and seeded test cases
- `bugasura_update_test_run` - Update a single execution run (name, status, environment, app build)
- `bugasura_update_test_run_scheduler` - Edit a run/scheduler (rename, environment/build, switch single↔scheduled, change frequency/recurrence, pause/resume)
- `bugasura_rerun_test_run` - Trigger a fresh execution from an existing scheduler
- `bugasura_add_test_cases_to_run` - Add (copy) test cases into an existing run
- `bugasura_delete_test_run` - Delete one or more execution runs (soft by default, permanent with `is_permanent_delete=1`)
- `bugasura_delete_test_run_scheduler` - Delete one or more schedulers (soft by default, permanent with `is_permanent_delete=1`)

**Note:** All test run tools support interactive context selection. Reports/suites, environments, app builds, runs, and schedulers can be referenced by **name or numeric ID** (names resolved automatically, with disambiguation when needed). Recurrence is set with friendly options (`frequency`, `repeat_value`/`repeat_unit`, `selected_days`, `recurrence_type`) rather than raw JSON.

**API endpoints used:**

| Tool | Method & endpoint | What it does |
|------|-------------------|--------------|
| `bugasura_list_test_run_environments` | `GET /v1/projectTestDataEnvironments/get` | Lists environments and app builds for picking by name. |
| `bugasura_list_test_runs` | `GET /v1/testrunsExecution/getList` | Lists run executions and schedulers for a suite. |
| `bugasura_get_test_run_details` | `GET /v1/testrunsExecution/getList` | Fetches one run (filtered by run id). |
| `bugasura_create_test_run` | `POST /v1/testrunsExecution/add` | Creates a single or scheduled run. |
| `bugasura_update_test_run` | `POST /v1/testrunsExecution/testruns/update` | Updates a single execution run. |
| `bugasura_update_test_run_scheduler` | `POST /v1/testrunsExecution/scheduler/update` | Edits a run/scheduler (the UI edit-run modal). |
| `bugasura_rerun_test_run` | `POST /v1/testrunsExecution/rerun` | Reruns from an existing scheduler. |
| `bugasura_add_test_cases_to_run` | `POST /v1/testrunsExecution/copy` | Adds test cases into a run. |
| `bugasura_delete_test_run` | `POST /v1/testrunsExecution/deleteTestRunsExecution` | Deletes execution run(s). |
| `bugasura_delete_test_run_scheduler` | `POST /v1/testrunsExecution/deleteScheduler` | Deletes scheduler(s). |

Names are resolved via `bugasura_list_sprints` (report ↔ sprint), `bugasura_list_test_run_environments` (environment / app build), and `/v1/testrunsExecution/getList` (run / scheduler).

</details>

<details>
<summary><b>Test Case Comments</b></summary>

- `bugasura_list_testcase_comments` - List comments for a test case with pagination and filtering (supports creator_id filter, exclude system comments)
- `bugasura_get_testcase_comment` - Get single test case comment details with full content and metadata
- `bugasura_add_testcase_comment` - Create a new comment on a test case (supports public/private visibility, HTML formatting)
- `bugasura_update_testcase_comment` - Update existing test case comment text (author-only, supports interactive comment selection)
- `bugasura_delete_testcase_comment` - Delete test case comment permanently (author or admin, supports interactive comment selection)

**Key Features:**
- **Pagination**: List comments with `start_at` and `max_results` parameters (default: 10 results, max: 100)
- **Filtering**: Filter by comment author (`creator_id`) or exclude system comments (`get_user_comments_only`)
- **Interactive Selection**: Prompts for team → project → test case → comment if not provided
- **Comment Types**: User comments (editable) vs System comments (auto-generated, read-only)
- **Visibility Control**: Public comments (visible to all) vs Private comments (team members only)
- **HTML Support**: Comments support HTML formatting and user mentions (@username)

**Note:** All test case comment tools support full interactive context selection, including comment selection for update/delete operations. System comments cannot be edited or deleted.

</details>

<details>
<summary><b>Requirements Management</b></summary>

- `bugasura_list_requirements` - List all requirements for a project or sprint
- `bugasura_get_requirement_details` - Get detailed requirement information including parent/child hierarchy
- `bugasura_create_requirement` - Create a new requirement with interactive folder selection
- `bugasura_update_requirement` - Update requirement details (partial updates supported, preserves all fields)
- `bugasura_delete_requirement` - Delete a requirement permanently
- `bugasura_link_unlink_requirement_testcases` - Link or unlink test cases to/from a requirement
- `bugasura_create_requirement_folder` - Create a folder for organizing requirements
- `bugasura_list_requirement_folders` - List all folders in a project

**Key Features:**
- **Folder Organization**: Requirements must be organized in folders. Interactive folder selection helps you choose or create folders during requirement creation.
- **Parent-Child Hierarchy**: Requirements can have parent requirements for multi-level organization (EPICs → STORYs → TASKs).
- **Smart Assignee Resolution**: Assign by name, email, or user ID (automatically resolved).
- **Field Preservation**: Update operations fetch existing data and preserve all fields not being updated.
- **Test Case Linking**: Link requirements to test cases for traceability.

**Note:** All requirement tools support interactive context selection. The `folder_id` field is required for all requirement operations and will be auto-fetched or interactively selected.

</details>

<details>
<summary><b>Knowledge Base</b></summary>

The knowledge base is a project-level document library, organized in folders and shown on the project's Knowledge Base page. It is separate from a TestPert sprint's own knowledge base (see the Testpert tools below).

**Documents**
- `bugasura_list_knowledge_base_documents` - List documents in a folder or across the whole project (supports `starred_only` and pagination)
- `bugasura_download_knowledge_base_document` - Get a direct download link for an uploaded document, and optionally save it to disk
- `bugasura_star_knowledge_base_document` - Star or unstar a document (`starred=False` removes the star)
- `bugasura_delete_knowledge_base_document` - Delete a document permanently (admin-only, DESTRUCTIVE)

**Imports** (all in `tools/knowledge_base.py`)

The six entries in the Knowledge Base page's "+" menu, plus the document editor's own Import menu. Everything except the file upload runs in the background — the tool returns as soon as the crawl/sync is queued, and `bugasura_list_knowledge_base_documents` shows its progress in `stage`. Connector credentials are supplied per call and are never stored by this server.

- `bugasura_upload_knowledge_base_document` - Upload document(s) (`.txt`, `.pdf`, `.doc`, `.docx`, `.md`) from a local path or a share link
- `bugasura_import_website_to_knowledge_base` - Crawl a website (`max_pages`, `include_linked_pages`)
- `bugasura_import_coda_to_knowledge_base` - Import a Coda doc's pages ("Superhuman Import"); needs a Coda API key and the doc's URL, id or name
- `bugasura_import_jira_to_knowledge_base` - Import Jira issues, one page per Jira project; whole projects by default, or specific `issue_keys`
- `bugasura_import_confluence_to_knowledge_base` - Import Confluence spaces, one page tree per space; whole spaces by default, or specific `page_ids`
- `bugasura_import_figma_to_knowledge_base` - Import Figma frames as design context (DESTRUCTIVE — see Key Features below)
- `bugasura_import_file_to_knowledge_base_document` - The document editor's Import menu: a `.md` file becomes a new page, a `.csv`/`.xlsx`/`.xls` file becomes a Markdown table appended to an existing page

Pick what a connector should import with the listing tools first:

- `bugasura_list_coda_docs` / `bugasura_list_coda_pages` - The docs a Coda API key can see, and one doc's page tree
- `bugasura_list_jira_projects` / `bugasura_list_jira_issues` - The projects an account can see (with issue counts), and one project's issues
- `bugasura_list_confluence_spaces` / `bugasura_list_confluence_pages` - The spaces an account can see, and one space's pages

**Folders**
- `bugasura_list_knowledge_base_folders` - List the knowledge base folders with the document count in each
- `bugasura_create_knowledge_base_folder` - Create a folder, optionally nested under an existing one
- `bugasura_rename_knowledge_base_folder` - Rename a folder in place (keeps its parent and its contents)
- `bugasura_delete_knowledge_base_folder` - Delete a folder (admin-only, DESTRUCTIVE)

**Page Documents**

A page document is written in Bugasura instead of uploaded — the web app's "Create Document" flow. Its body is a tree of pages, each with its own markdown content. Documents synced from Coda, Jira, Confluence or a URL are stored in the same shape, so the page tools work on those too.

- `bugasura_create_knowledge_base_document` - Create a page document (starts with one empty page)
- `bugasura_rename_knowledge_base_document` - Rename a page document
- `bugasura_list_knowledge_base_pages` - List a document's pages, with `page_path`, `depth` and `has_content`
- `bugasura_create_knowledge_base_page` - Add a page, optionally nested under a page or placed after one, with its content
- `bugasura_rename_knowledge_base_page` - Rename a page
- `bugasura_get_knowledge_base_page_content` - Read a page's current markdown body (call before editing one)
- `bugasura_update_knowledge_base_page_content` - Write a page's markdown: replace the whole body (`''` clears it), or `mode='append'` / `mode='prepend'` to add to it
- `bugasura_duplicate_knowledge_base_page` - Copy a page, with or without its sub pages
- `bugasura_move_knowledge_base_page` - Re-parent or reorder a page (`parent_page` / `after_page` / `to_root`)
- `bugasura_delete_knowledge_base_page` - Delete a page and its sub pages (DESTRUCTIVE)

**Key Features:**
- **Automatic Folder Handling**: Pass `folder_name` to file the document in that folder — it is matched case-insensitively and created when the project doesn't have one by that name. Omit it and the project's first knowledge base folder is used, or a `Knowledge Base` folder is created when the project has none.
- **Two Ways to Provide a File**: `file_paths` (absolute paths, for terminal/CLI use) or `source_url` (Google Drive / Dropbox / any public download link — the server fetches it). Files are never encoded by the assistant.
- **Multiple Files**: Several paths in one call are uploaded into the same folder.
- **Folder Names**: A folder name cannot contain `<`, `>`, `/` or `\`, and two folders cannot share a name under the same parent — `bugasura_rename_knowledge_base_folder` reports both cases up front, and renaming a folder to the name it already has is answered without a write.
- **Smart Document Resolution**: Documents are identified by file name (exact match, then partial) or by numeric id. Ambiguous names come back with the matching documents so the user can pick one; add `folder_name` to narrow the search.
- **Background Processing**: Bugasura processes uploaded documents automatically; they become searchable project context once processing finishes.
- **Downloads Are Links First**: Bugasura has no download endpoint — an uploaded file's bytes live on the CDN, and `bugasura_download_knowledge_base_document` turns the stored path into a direct, login-free `download_url`. That link is the answer for most clients; add `save_to_path` to also write the file to the machine running the server, which only helps when that is the user's own machine (terminal use). Set `CDN_BASE_URL` in the server's `.env` for deployments the known-host map doesn't cover — the CDN is a separate CloudFront/S3 host and cannot be derived from `API_BASE_URL`.
- **Only Uploaded Files Are Downloadable**: Page documents, website entries and Jira/Confluence imports have no file of their own, and Bugasura has no PDF export — so a page document cannot be handed over as a PDF. Read those with `bugasura_list_knowledge_base_pages` instead.
- **Smart Page Resolution**: Pages are identified by page name (exact match, then partial) or by page id (`page_20250104120500`). Ambiguous names come back with the matching pages so the user can pick one.
- **Connector Credentials Are Per Call**: Jira, Confluence, Coda and Figma credentials are asked for on every call and forwarded straight through — this server stores none of them. Jira Cloud and Confluence take an API token, a self-hosted Jira (`deployment_type="SERVER"`) takes the account password, Coda takes an API key, and Figma takes a personal access token. Confluence is the one exception: leave its three credential arguments out and the listing tools fall back to the project's saved Confluence integration.
- **Import Into an Existing Document**: `bugasura_import_jira_to_knowledge_base` and `bugasura_import_confluence_to_knowledge_base` create a new document by default; pass `document_identifier` to merge the selection into an existing page document instead, the way the web app's "Import → Jira / Confluence" works from inside a document. A document that is already importing is reported rather than queued twice.
- **Figma Replaces the Project's Frame Set**: Bugasura keeps one set of Figma frames per project, and an import rewrites that set — any stored frame missing from the payload is deleted. `bugasura_import_figma_to_knowledge_base` reads the existing frames back and carries them forward, so an import only *adds*; `replace_existing=True` drops them, and is only for when the user has asked for that. Each link must point at a frame (carry a `node-id`, i.e. Figma's "Copy link to selection"); a link to a whole file is rejected.
- **Editing a Page is Read-Modify-Write**: The API only ever writes a page's markdown, so `bugasura_get_knowledge_base_page_content` reads it back off the CDN the way the web editor does (needs `CDN_BASE_URL`, same as downloads). Because the write replaces the *whole* body, changing part of a page means reading it, editing that text, and writing the full result back with `mode='replace'`. To only add to a page, `mode='append'` / `mode='prepend'` do the read for you — pass just the new text. A page too large to read safely is refused rather than truncated, so a partial copy can never be written back over the full one.

**Note:** Documents are limited to 100MB each, except `bugasura_import_file_to_knowledge_base_document` (the document editor's Markdown/CSV/Excel import), which is capped at 10MB. Call `bugasura_prepare_kb_upload` first when the user wants to share a file — it returns the instructions to show them. Deleting a document removes its file and everything the AI learned from it, and cannot be undone; deleting a folder that still holds documents requires `delete_documents=True` and takes its documents with it. Both deletes require team or project admin rights. Deleting a page that has sub pages likewise requires `delete_sub_pages=True` and takes them with it.

</details>

<details>
<summary><b>Testpert Sprint Generation</b></summary>

TestPert is a paid, project-level AI feature (`is_testpert_enabled` on the project). It generates a full test plan and test cases from your requirement documents or existing requirements.

**Sprint creation**
- `bugasura_create_testpert_sprint` - Create a TestPert sprint (confirms options before creating; set `confirm_options=True` to proceed)

**Normal flow** — upload documents → answer questions → edit plan → generate
- `bugasura_testpert_upload_kb` - Upload requirement docs/images to the sprint knowledge base (`.txt`, `.pdf`, `.docx`, `.md`, `.json`, `.png`, `.jpg`, etc.)
- `bugasura_testpert_list_kb` - List documents currently in the knowledge base
- `bugasura_testpert_delete_kb` - Remove a document from the knowledge base
- `bugasura_testpert_generate_sprint_context` - Start requirement analysis (KB → deepen questions)
- `bugasura_testpert_answer_context_questions` - Submit answers to the AI's deepen-requirement questions
- `bugasura_testpert_get_requirement_contexts` - Fetch deepen questions, missing requirements, and risks for user review
- `bugasura_testpert_update_requirement_contexts` - Write approve/reject/edit decisions back for missing requirements and risks
- `bugasura_testpert_add_context_question` - Add a deepen-requirement question to the sprint (the 'Add Question' button)
- `bugasura_testpert_delete_context_question` - Remove a deepen-requirement question from the sprint
- `bugasura_testpert_get_testplan` - Fetch the generated test plan (focus areas + feature/sub-feature tree)
- `bugasura_testpert_update_testplan` - Edit focus-area levels and the feature tree
- `bugasura_testpert_get_features` - List the live feature/sub-feature tree
- `bugasura_testpert_add_feature` - Add a feature or sub-feature
- `bugasura_testpert_delete_feature` - Delete a feature or sub-feature
- `bugasura_testpert_enrich_requirements` - Run the requirements-enrichment phase explicitly (optional — `generate_coverage` runs it automatically)
- `bugasura_testpert_generate_coverage` - Move the sprint to test coverage (runs enrichment first if needed)
- `bugasura_testpert_get_coverage` - Fetch the coverage mind map
- `bugasura_testpert_generate_testcases` - Generate test cases (polls to completion; re-callable)
- `bugasura_testpert_regenerate_testcases` - Regenerate/retry one sub-feature's test cases after `TEST_CASES` (needs the user's answers to the 3-section context modal; max 5 attempts per sub-feature)

**Skip-enrich flow** — use existing project requirements instead of documents
- `bugasura_testpert_link_requirements` - Link existing project requirements to the sprint as its source
- `bugasura_testpert_start_skip_testplan` - Build the test plan directly from the sprint's linked requirements

**Low-level status driver** (advanced)
- `bugasura_testpert_advance` - Set a specific status and/or poll until a target status — use this when you need direct control over the pipeline

**Flow overview:**
```
Normal:  create → upload_kb → generate_sprint_context → answer_context_questions
         → (missing reqs) → (risks) → get_testplan → enrich → generate_coverage → generate_testcases

Skip:    create (skip_enrich=true) → link_requirements → start_skip_testplan
         → get_testplan → generate_coverage → generate_testcases
```

**Notes:**
- The project must have TestPert enabled (`is_testpert_enabled`). Use `bugasura_create_sprint` for standard sprints.
- Polling tools (`generate_sprint_context`, `start_skip_testplan`, `enrich_requirements`, `generate_coverage`, `generate_testcases`) are time-bounded per call and re-callable — if the AI phase is still running, call the same tool again to keep checking.
- A team-admin API key is required for status transitions and test-plan updates.

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
| `bugasura://projects/{project_id}/requirements` | Requirements in a project |

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

```
Show me the first 50 comments on issue 123 (using max_results=50)
```

```
Show me comments 21-40 on issue 456 (using start_at=20, max_results=20)
```

### Partial Updates

Update only the fields you want to change - all other fields are automatically preserved:

```
Update issue 123 to change severity to HIGH
(other fields like status, description, assignees remain unchanged)
```

```
Update requirement 2036 to change title only
(severity, priority, assignees, and all other fields are preserved)
```

**How It Works:**
All update operations (issues, requirements, test cases, sprints) fetch the existing record first, then merge your changes with existing data before sending to the API. This ensures no fields are accidentally cleared or reset.

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

```
List only user comments on issue 123 (exclude system-generated comments)
```

```
List comments by a specific user on issue 456 (using creator_id filter)
```

---

## Transport Modes

Bugasura MCP supports two transport modes:

**STDIO** (default) — local MCP clients (subprocess over stdin/stdout)
```bash
python server.py --transport stdio
```

**Streamable HTTP** (recommended for remote deployment) — mounted at `/mcp`
```bash
python server.py --transport streamable-http --port 8000
```

The hosted version at `https://mcp.bugasura.io/mcp` uses streamable HTTP.

---

## Local Development — Sample Client Configs

Use these when you're hacking on the server itself and want your AI client to launch your local checkout as a stdio subprocess instead of hitting the hosted `/mcp` endpoint.

> **Replace `/Applications/MAMP/htdocs/Bugasura-MCP/` with the absolute path of your own clone, and `your_api_key_here` with your Bugasura API key (Settings → API Key).** Never commit a real key.

### VS Code (workspace `.vscode/settings.json`)

```json
{
  "settings": {
    "mcp": {
      "inputs": [],
      "servers": {
        "bugasura-local-mcp": {
          "type": "stdio",
          "command": "/Applications/MAMP/htdocs/Bugasura-MCP/.venv/bin/python3",
          "args": [
            "/Applications/MAMP/htdocs/Bugasura-MCP/server.py"
          ],
          "env": {
            "BUGASURA_API_KEY": "your_api_key_here"
          }
        }
      }
    }
  }
}
```

### Claude Desktop (`claude_desktop_config.json`)

macOS path: `~/Library/Application Support/Claude/claude_desktop_config.json`
Windows path: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "bugasura": {
      "command": "/Applications/MAMP/htdocs/Bugasura-MCP/.venv/bin/python",
      "args": [
        "/Applications/MAMP/htdocs/Bugasura-MCP/server.py"
      ],
      "env": {
        "BUGASURA_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

After editing the config, restart the client (VS Code window reload / Claude Desktop quit-and-relaunch) so it picks up the new server. The server logs to stderr — tail your client's MCP server logs to confirm `Bugasura MCP Server | API: ... | Transport: stdio` appears on startup.

---

## Testing & Debugging with MCP Inspector

The MCP Inspector provides a web-based interface to test and debug your MCP server.

### Quick Start

1. **Install MCP Inspector** (if not already installed):
   ```bash
   npm install -g @modelcontextprotocol/inspector
   ```

2. **Run the Inspector**:
   ```bash
   cd /Applications/MAMP/htdocs/api.appachhi.com/Bugasura-MCP
   source .venv/bin/activate
   npx @modelcontextprotocol/inspector python server.py
   ```

3. **Open your browser** - The inspector will automatically open at `http://localhost:5173`

### What You Can Do

- ✅ **View all tools** with their parameters and documentation
- ✅ **Test tools interactively** - Call any tool and see real responses
- ✅ **Debug workflows** - Test create → update → delete flows
- ✅ **Validate parameters** - Ensure correct formats and types
- ✅ **Test name-based operations** - Try deleting by issue key (ISS09), test case key (TES5), or names
- ✅ **Test team resolution** - Use team names instead of IDs for team member management

### Example Tests

**Test Issue Deletion by Key:**
```json
Tool: bugasura_delete_issue
Parameters: {
  "issue_identifier": "ISS09"
}
```
> Note: `api_key` is optional if `BUGASURA_API_KEY` is set in the environment.

**Test Interactive Sprint Selection:**
```json
Tool: bugasura_create_issue
Parameters: {
  "summary": "Test issue"
}
// Returns selection prompt for team → project → sprint
```

**Test Team Member Management with Team Name:**
```json
Tool: bugasura_add_team_members
Parameters: {
  "team_name": "Engineering",
  "email_list": "john@example.com, jane@example.com"
}
// Resolves team name and sends invitations
```

**Test User Removal with Smart Resolution:**
```json
Tool: bugasura_delete_team_user
Parameters: {
  "team_id": 123,
  "user_identifier": "john@example.com"
}
// Resolves user by email and removes from team
```

For detailed instructions, see [MCP_INSPECTOR_GUIDE.md](./MCP_INSPECTOR_GUIDE.md)

---

## Important Notes

### API Key

All operations require a Bugasura API key. Get yours from [Bugasura Settings](https://bugasura.io).

**Recommended — configure once in your MCP client** (see setup examples above):
- **STDIO clients** (Claude Desktop, local Cursor/VS Code STDIO): set `BUGASURA_API_KEY` in the `env` block.
- **HTTP clients** (hosted `/mcp`, e.g. `mcp.stage.bugasura.io`): set `X-Bugasura-API-Key` in the `headers` block. `Authorization: Basic <key>` is also accepted.

When configured, all tools use the key automatically — no need to provide it on every call. If neither source is configured, the first tool call returns `status: 'api_key_required'` and the assistant will ask you for one.

You can also pass `api_key` explicitly as a tool parameter, which takes precedence over both env and header.

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

### Smart Team Resolution

Team member management tools support flexible team identification:
- **Team IDs**: `team_id=123` (direct numeric ID)
- **Team Names**: `team_name="Acme Corp"` (partial match, case-insensitive)

You can use either parameter for:
- `bugasura_add_team_members` - Invite users to a team
- `bugasura_update_team_member` - Change member roles
- `bugasura_delete_team_user` - Remove team members

**Examples:**
```
add_team_members(team_name="Engineering", email_list="john@example.com")
update_team_member(team_id=123, user_id=456, is_admin=1)
delete_team_user(team_name="Sales", user_identifier="john@example.com")
```
> Note: `api_key` can be omitted when `BUGASURA_API_KEY` is configured in the environment.

### Data Requirements

**Sprints:**
- Sprint names must be 5-250 characters
- Issues must be assigned to a sprint
- Updates require the issue to have a sprint assigned

**Requirements:**
- Requirements must be organized in folders
- Folder ID is required for all requirement operations
- Requirements can have parent-child hierarchy (max 2 levels: parent cannot have another parent)

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

### Issue Comments

```
"List all comments on issue 123"
→ Returns all comments with user details and timestamps

"Show me the next 10 comments starting from comment 11"
→ Uses pagination (start_at=10, max_results=10)

"List only user comments, exclude system-generated ones"
→ Uses get_user_comments_only=True to filter out system comments

"Add a comment 'Fixed in version 2.1.0' to issue 456"
→ Guides through team/project/issue selection, creates public comment

"Add a private comment about internal notes to issue 789"
→ Creates comment with is_public_comment=0

"Update comment 321 to fix a typo"
→ Guides through interactive selection if comment details not provided

"Delete comment 456"
→ Shows deletion warning, removes comment permanently
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

### Requirements Management

```
"Create a requirement titled 'User Authentication' with details 'Implement OAuth 2.0' and priority P1"
→ Guides through team/project selection, prompts for folder selection, creates requirement

"List all requirements in my mobile app project"
→ Returns all requirements with their hierarchy and test case counts

"Link test cases 123 and 456 to requirement 2036"
→ Creates traceability between requirements and test cases

"Update requirement 2036 to change severity to HIGH and assign to john@example.com"
→ Updates requirement fields while preserving all other data
```

### Testpert Sprint Generation

```
"Create a TestPert sprint called 'Checkout Flow Sprint'"
→ Confirms options (testing type, depth, skip enrich), then creates the sprint

"Upload /docs/checkout-spec.pdf and /docs/api-contract.md to the knowledge base"
→ Uploads both files, moves sprint to KNOWLEDGE_BASE stage

"Start the analysis"
→ Kicks off requirement analysis, then automatically shows the AI's contextual questions

"Answer: Q1: Users must be able to pay by card or wallet. Q2: Guest checkout is required."
→ Saves answers and advances to the missing requirements stage

"Approve all missing requirements and proceed"
→ Approves rows, advances through risks to the test plan

"Set Authentication focus to EXHAUSTIVE and Performance to MINIMAL"
→ Edits focus-area levels in the test plan

"Generate the test cases"
→ Runs enrichment + coverage + test case generation; returns sprint link when done
```

```
"Create a TestPert sprint with skip enrich, link requirements 101 and 102, then build the test plan"
→ Creates sprint (skip_enrich=true), links requirements, starts test plan generation
```

### Team Member Management

```
"Add john@example.com and jane@example.com to the Engineering team"
→ Resolves team by name, sends email invitations to new members

"List all members of team Acme Corp"
→ Returns team members with names, emails, user IDs, and roles

"Promote user 456 to admin in the Marketing team"
→ Updates team member role from member to admin

"Remove john@example.com from the Sales team"
→ Resolves user by email, removes from team and unassigns all their issues

"Make Sarah an admin in team 123"
→ Resolves user by name, promotes to admin role
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
