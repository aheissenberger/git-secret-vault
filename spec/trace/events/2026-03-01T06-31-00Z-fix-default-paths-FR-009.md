---
req_id: FR-009
change_type: verify
files:
  - src/cli/mod.rs
  - src/mcp/mod.rs
tests:
  - src/mcp/mod.rs::tests::vault_server_constructs
docs:
  - spec/TRACE.md
pr: ""
commit: 2cd84ab
author: Copilot
timestamp: "2026-03-01T06:31:00Z"
---

Fixed default vault and index path constants in the global CLI flags and MCP server test.

Previously the global `--vault` default was `vault.zip` and `--index` was `.vault-index.json`.
Corrected to `git-secret-vault.zip` and `.git-secret-vault.index.json` respectively,
matching the spec (FR-009 AC2) and all other per-command `--vault`/`--index` defaults.

Also updated `VaultServer::new(...)` unit test assertions in `src/mcp/mod.rs`.

All 198 tests pass after the fix.
