# Traceability Matrix

| Requirement | Implementation | Verification | Decisions | Notes |
|------------|---------------|-------------|-----------|------|

| FR-001 |  |  |  | Legacy migration scaffold |
| FR-002 | src/vault/format.rs |  | ADR-0002 | Vault format and compatibility |
| FR-003 | src/vault/index.rs, src/cli/{init,lock,status}.rs | cargo test (36 unit tests pass) |  | Metadata minimization and index (`.git-secret-vault.index.json`) — **Done** |
| FR-004 | src/vault/manifest.rs, src/vault/format.rs, src/fs/mod.rs | cargo test |  | Encrypted manifest, determinism, atomicity — In Progress |
| FR-005 | src/crypto/mod.rs |  |  | Password policy and input handling |
| FR-006 | src/fs/mod.rs, src/cli/unlock.rs | cargo test |  | Filesystem extraction and deletion safety — In Progress |
| FR-007 |  |  |  | Git hardening and drift controls |
| FR-008 | src/cli/mod.rs, src/cli/{init,lock,unlock,status}.rs |  |  | Required CLI command set |
| FR-009 | src/cli/init.rs | scripts/manual-test-sandbox.sh |  | Init workflow behavior (`git-secret-vault.zip` + `.git-secret-vault.index.json`) — In Progress |
| FR-010 | src/cli/lock.rs, src/vault/format.rs | cargo test (47 tests pass) |  | Lock workflow: no-arg lock of all tracked entries, `--remove` plaintext cleanup, `--check` drift — **Done** |
| FR-011 | src/cli/unlock.rs, src/fs/mod.rs | cargo test (47 tests pass) |  | Unlock conflict policies: `--force`, `--keep-local`, `--keep-both`, `--no-prompt`, atomic writes — **Done** |
| FR-012 | src/cli/status.rs |  |  | Status and diff behavior — In Progress |
| FR-013 |  |  |  | Remove, password rotation, keyring |
| FR-014 |  |  |  | Verify, clean, doctor, compat, harden |
| FR-015 |  |  |  | Config and local state model |
| FR-016 |  |  |  | Output safety, CI, UX, exit codes |
| FR-017 |  |  |  | Test/release quality requirements |
| FR-018 |  |  | ADR-0002 | Documentation and locked decisions |
| FR-019 | src/cli/status.rs, src/vault/index.rs | cargo test (47 tests pass) |  | Status: summary mode (no password) + authenticated hash-verification mode (`--password-stdin`) — **Done** |
| FR-020 |  |  |  | Diff behavior (split) |
| FR-021 | src/cli/rm.rs | cargo test (80 unit tests pass) |  | Remove vault entries with optional local plaintext deletion — **Done** |
| FR-022 | src/cli/passwd.rs | cargo test (80 unit tests pass) |  | Re-encrypt vault with new password, atomic rewrite, --rotate checklist — **Done** |
| FR-023 |  |  |  | Keyring behavior (split) |
| FR-024 | src/cli/verify.rs | cargo test (80 unit tests pass) |  | Validate vault integrity per-entry with hash verification and --json output — **Done** |
| FR-025 | src/cli/clean.rs | cargo test (80 unit tests pass) |  | Remove tracked plaintext files safely with per-file prompt and --force flag — **Done** |
| FR-026 | src/cli/doctor.rs | cargo test (80 unit tests pass) |  | Diagnose environment: vault/index existence, JSON validity, write access, unzip on PATH — **Done** |
| FR-027 |  |  |  | Compatibility-check behavior (split) |
| FR-028 | src/cli/harden.rs | cargo test (80 unit tests pass) |  | Update .gitignore with sensitive patterns; install pre-commit hook; --dry-run — **Done** |
| SEC-001 | src/vault/index.rs | cargo test (index no-filename assertion) |  | Metadata exposure default safety — **Done** |
| SEC-002 | src/crypto/mod.rs (validate_password_strength) |  |  | Password policy minimums |
| SEC-003 |  |  |  | Password policy controls |
| SEC-004 | src/crypto/mod.rs (get_password env-var branch) |  |  | Env password leakage warning |
| SEC-005 | src/crypto/mod.rs |  |  | Memory hygiene best-effort — **Done** |
| SEC-006 | src/fs/mod.rs | cargo test (safe_join tests) |  | Path traversal prevention — **Done** |
| SEC-007 | src/cli/unlock.rs, src/vault/format.rs |  |  | Symlink default deny — **Done** |
| SEC-008 |  |  |  | Post-lock plaintext removal |
| SEC-009 |  |  |  | Shred warning semantics |
| SEC-010 | src/cli/status.rs, src/cli/lock.rs, src/cli/unlock.rs |  |  | Secret output redaction — **Done** |
| SEC-011 | src/crypto/mod.rs |  |  | Password output redaction — **Done** |
| SEC-012 | src/cli/mod.rs |  |  | Logging verbosity controls — **Done** |
| NFR-001 | src/vault/format.rs, src/vault/manifest.rs | cargo test (determinism test) |  | Deterministic update policy — **Done** |
| NFR-002 |  |  |  | Determinism without crypto weakening |
| NFR-003 | src/fs/mod.rs | cargo test (atomic_write test) |  | Atomic write IO policy — **Done** |
| NFR-004 |  |  |  | Shell completion UX |
| NFR-005 |  |  |  | Editor/pager UX integration |
| NFR-006 |  |  |  | Signed release artifacts |
| NFR-007 |  |  |  | SBOM release artifact |
| NFR-008 |  |  |  | Reproducible build documentation |
| NFR-009 |  |  |  | Cross-platform CI matrix |
| NFR-010 |  |  |  | Golden path integration tests |
| NFR-011 |  |  |  | Corruption-path tests |
| NFR-012 |  |  |  | Security-path tests |
| NFR-013 |  |  |  | Determinism test coverage |
| NFR-014 | scripts/mock-keyring.sh, scripts/run-with-keyring.sh, scripts/manual-test-sandbox.sh, scripts/manual-sandbox-shell.sh, scripts/manual-keyring-smoke.sh | bash -n scripts/mock-keyring.sh scripts/run-with-keyring.sh scripts/manual-test-sandbox.sh scripts/manual-sandbox-shell.sh scripts/manual-keyring-smoke.sh; scripts/manual-keyring-smoke.sh |  | Mock keyring backend for local integration tests with store/lookup/list/purge coverage |
| NFR-015 |  |  |  | Test-first implementation policy |
| NFR-016 | src/cli/mod.rs, src/cli/status.rs | scripts/manual-test-sandbox.sh |  | AI-agent automation CLI profile (deterministic JSON, non-interactive, stable exits) |
| NFR-017 | src/cli/mod.rs |  |  | MCP 2025-11-25 server adapter pattern (CLI-first core + MCP tool interface) |

<!--
Populate rows where obvious. Leave unknown cells empty.
This file is a navigational matrix, not immutable history.
Immutable history lives under spec/trace/events/ and spec/trace/claims/.
-->
