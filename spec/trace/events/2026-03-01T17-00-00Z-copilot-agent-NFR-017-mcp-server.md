---
req_id: NFR-017
change_type: implement
files:
  - src/mcp/mod.rs
  - src/lib.rs
  - src/cli/mod.rs
  - src/main.rs
  - docs/mcp-server.md
  - spec/requirements/NFR-017.md
  - spec/TRACE.md
tests:
  - src/mcp/mod.rs (vault_server_constructs unit test)
  - tests/golden_path.rs (all passing)
docs:
  - docs/mcp-server.md
pr: null
commit: null
author: copilot-agent
timestamp: 2026-03-01T17:00:00Z
---

Implemented MCP server via rmcp 0.17.0 crate exposing vault_status, vault_lock, vault_unlock,
and vault_verify as MCP tools over stdio transport. Added --mcp flag to CLI. Compatible with
Claude Desktop and other MCP clients.
