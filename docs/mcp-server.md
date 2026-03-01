# MCP Server for git-secret-vault

`git-secret-vault` includes a built-in [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server so AI assistants such as Claude Desktop can interact with your vault directly.

## Starting the server

```sh
VAULT_PASSWORD=<your-password> git-secret-vault --mcp
```

Optional flags to specify non-default paths:

```sh
VAULT_PASSWORD=<your-password> git-secret-vault --mcp \
  --vault git-secret-vault.zip \
  --index .git-secret-vault.index.json
```

The server communicates over **stdio** using JSON-RPC 2.0 (MCP 2025-11-25).

## Claude Desktop integration

Add the following to your `claude_desktop_config.json` (usually at
`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "git-secret-vault": {
      "command": "git-secret-vault",
      "args": ["--mcp"],
      "env": {
        "VAULT_PASSWORD": "your-vault-password"
      }
    }
  }
}
```

Restart Claude Desktop after saving the config.

## Available tools

| Tool | Description |
|------|-------------|
| `vault_status` | List all entries tracked in the encrypted vault |
| `vault_lock` | Lock (encrypt) one or more files into the vault |
| `vault_unlock` | Unlock (decrypt) all vault entries to plaintext |
| `vault_verify` | Verify vault integrity — checks all entries match stored hashes |

### vault_lock parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `files` | `string[]` | File paths to lock into the vault |

## Security notes

- The vault password is passed via the `VAULT_PASSWORD` environment variable.
- The MCP server subprocess calls the `git-secret-vault` binary for each tool invocation, inheriting the environment.
- Keep your MCP config file permissions restricted (`chmod 600`) since it contains the vault password.
