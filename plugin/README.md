# Bugasura

Bug tracking and test management for [Bugasura](https://bugasura.io), right from your AI assistant.

This plugin connects your assistant to Bugasura's hosted MCP server at `https://mcp.bugasura.io/mcp`. Once connected you can:

- **Issues**: create, update, assign, comment on and attach files to bugs
- **Test cases**: write test cases, link them to sprints and report pass/fail results
- **Sprints and test runs**: plan sprints, schedule runs, pick environments and app builds
- **Requirements**: manage requirements and folders, and link them to test cases
- **Knowledge base**: keep project documents and pages, upload files and import websites
- **TestPert**: generate and review AI test cases from your requirements

Refer to teams, projects and issues by name or key (such as `ISS09`); the server resolves them for you.

## Setup

In Claude Code:

```
/plugin install bugasura --marketplace appachhi/bugasura-mcp-server
```

You need a Bugasura account. The first time a Bugasura tool runs, your assistant opens the Bugasura sign-in page in your browser. Sign in, click **Allow**, and you're connected. There's no API key to copy, and the assistant never sees your password or tokens.

## What the plugin runs and sends

The plugin contains no code. It only registers the remote MCP server above. Requests you make through Bugasura tools go to `mcp.bugasura.io`, which calls the Bugasura API (`api.bugasura.io`) as you, with your own permissions. Nothing is sent anywhere else.

## Privacy

The server passes your requests to the Bugasura API under your own account. It keeps your session's OAuth tokens encrypted, caches your team and project list in memory for a few minutes, and writes operational logs. It has no database of its own. Data collection, usage, storage, sharing and retention are covered by the [Bugasura Privacy Policy](https://bugasura.io/privacy/) and [Terms of Service](https://bugasura.io/terms-of-service/).

## Support

- Documentation: <https://github.com/appachhi/bugasura-mcp-server#readme>
- Issues: <https://github.com/appachhi/bugasura-mcp-server/issues>
- Email: [support@bugasura.io](mailto:support@bugasura.io)
