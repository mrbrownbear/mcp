# Novamira Visual MCP

MCP server for connecting coding agents to Novamira Visual in WordPress.

## Usage

Add this server to your MCP client configuration:

```json
{
  "mcpServers": {
    "novamira-visual": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "novamira-visual-mcp@latest"],
      "env": {
        "NOVAMIRA_VISUAL_WORKSPACE_URL": "https://example.com/wp-admin/admin-post.php?action=novamira-visual"
      }
    }
  }
}
```

Open the Novamira Visual page in WordPress, then paste the connection code shown by the MCP server.

The first MCP client for a WordPress site starts a local daemon automatically. Later MCP clients configured with a
Novamira Visual URL on the same site reuse the same daemon through a per-site local control endpoint, so multiple agents
can connect to the same Novamira Visual workspace without changing the user's MCP configuration. Different WordPress
sites use different daemons. A daemon exits after its last MCP client disconnects.

On Linux the MCP control socket and per-site bridge state are created under `~/.local/state/novamira-visual/`; on macOS
they use `~/Library/Application Support/novamira-visual/`. On Windows the MCP control endpoint is a named pipe under
`\\.\pipe\`, while per-site bridge state is stored under `%LOCALAPPDATA%\novamira-visual\`. The browser dashboard still
connects through the local TCP bridge port shown as `visual:<port>`, because browsers cannot open local control
endpoints directly.

## Options

- `--workspace-url <url>` or `NOVAMIRA_VISUAL_WORKSPACE_URL`: Novamira Visual URL.
- `--host <host>` or `NOVAMIRA_VISUAL_WORKSPACE_HOST`: bridge host. Defaults to `127.0.0.1`.
- `--port <port>` or `NOVAMIRA_VISUAL_WORKSPACE_PORT`: browser bridge port for this workspace URL. Defaults to the saved per-site bridge port, or an ephemeral port that is saved after startup.
- `--token <token>` or `NOVAMIRA_VISUAL_WORKSPACE_TOKEN`: connection token. Defaults to a generated token.
- `--timeout <ms>` or `NOVAMIRA_VISUAL_WORKSPACE_TIMEOUT`: workspace request timeout. Defaults to `30000`.
