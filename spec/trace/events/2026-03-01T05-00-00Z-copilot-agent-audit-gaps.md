---
timestamp: 2026-03-01T05:00:00Z
req_ids:
  - FR-005
  - FR-007
  - FR-012
  - FR-014
  - FR-016
  - FR-020
  - FR-026
  - FR-028
  - SEC-002
  - SEC-012
event: gap_fix
author: Copilot
---

Deep requirements audit: identified and fixed multiple gaps.

## Changes implemented

### FR-005 / SEC-002 – Password policy enforcement
- `validate_password_strength` was marked `#[allow(dead_code)]` and never called.
- Now called in `init.rs` and `passwd.rs` after obtaining a new password.
- The `#[allow(dead_code)]` annotation removed. Weak/short passwords now rejected at init and passwd.

### FR-016 / SEC-012 – `--verbose` flag threading
- `--verbose` was declared globally but never forwarded to any command.
- All `run()` functions now accept `verbose: bool`.
- `lock`, `verify`, and `doctor` emit additional output when `--verbose` is set.

### FR-012 / FR-020 – `diff --tool` flag
- `DiffArgs` now has `tool: Option<String>` (`--tool` flag).
- When `--tool` is set (or `$DIFF_TOOL` env var), the external tool is invoked with vault and local versions as temp file arguments.

### FR-014 / FR-026 – `doctor` keyring check
- Added keyring availability probe to `doctor` (check #6).
- Reports whether the system keyring backend is accessible with remediation guidance.

### FR-007 / FR-028 – `harden` pre-push hook
- Added `PRE_PUSH_SCRIPT` constant for a git pre-push guardrail.
- `harden --hooks` now installs both `pre-commit` and `pre-push` hooks.

## Remaining known gaps (require significant new code, deferred)

- **NFR-017 (MCP server)**: No MCP server implementation. Would require a full new server layer (>200 lines).
- **FR-010/FR-021 pattern matching**: lock and rm accept only exact paths, no glob support.
- **FR-011 editor merge**: interactive editor merge for text conflict in unlock not implemented.
- **FR-015 local state file**: separate gitignored per-file fingerprint store not implemented.
- **FR-015 config**: no include/ignore patterns or keyring namespace options in config.
- **NFR-006 release signing**: release.yml computes checksums but does not sign artifacts with GPG/cosign.
- **FR-009 keyring save at init**: init does not offer to save password to keyring during init flow.
