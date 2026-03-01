# Traceability Matrix

| Requirement | Implementation | Verification | Decisions | Notes |
|------------|---------------|-------------|-----------|------|

| FR-001 | spec/requirements/, spec/requirements/index.md |  |  | Legacy migration scaffold — **Done** |
| FR-002 | src/vault/format.rs |  | ADR-0002 | Vault format and compatibility — **Done** |
| FR-003 | src/vault/index.rs, src/cli/{init,lock,status}.rs | cargo test (36 unit tests pass) |  | Metadata minimization and index (`.git-secret-vault.index.json`) — **Done** |
| FR-004 | src/vault/manifest.rs, src/vault/format.rs, src/fs/mod.rs | cargo test |  | Encrypted manifest, determinism, atomicity — In Progress |
| FR-005 | src/crypto/mod.rs, src/cli/{lock,unlock,init,passwd}.rs | cargo test --lib (validate_password_strength enforced at init and passwd) |  | Password policy, source chain (stdin→env→keyring→prompt), weak-password rejection enforced at new-password creation — **Done** |
| FR-006 | src/fs/mod.rs, src/cli/unlock.rs | cargo test |  | Filesystem extraction and deletion safety — **Done** |
| FR-007 | src/cli/harden.rs |  |  | Git hardening and drift controls — **Done** (pre-commit + pre-push hooks) |
| FR-008 | src/cli/mod.rs, src/cli/{init,lock,unlock,status,diff,rm,passwd,keyring,verify,clean,doctor,compat,harden,completions,policy,config_cmd}.rs | All commands present and `ls` alias wired | 2026-03-01 | Required CLI command set — **Done** |
| FR-009 | src/cli/init.rs | scripts/manual-test-sandbox.sh |  | Init workflow behavior (`git-secret-vault.zip` + `.git-secret-vault.index.json`) — In Progress |
| FR-010 | src/cli/lock.rs, src/vault/format.rs | cargo test (47 tests pass) |  | Lock workflow: no-arg lock of all tracked entries, `--remove` plaintext cleanup, `--check` drift — **Done** |
| FR-011 | src/cli/unlock.rs, src/fs/mod.rs | cargo test (47 tests pass) |  | Unlock conflict policies: `--force`, `--keep-local`, `--keep-both`, `--no-prompt`, atomic writes — **Done** |
| FR-012 | src/cli/status.rs, src/cli/diff.rs | cargo test (--fail-if-dirty, pager, no-prompt tests pass) |  | Status --fail-if-dirty CI drift gating, $PAGER support, diff --tool flag with external tool invocation — **Done** |
| FR-013 | src/cli/rm.rs, src/cli/passwd.rs, src/cli/keyring_cmd.rs, src/cli/{lock,unlock,init}.rs | cargo test --lib | | Remove entries, password rotation with stale-keyring refresh, keyring save/status/delete/list/purge, --no-keyring/--require-keyring — **Done** |
| FR-014 | src/cli/verify.rs, src/cli/clean.rs, src/cli/doctor.rs, src/cli/compat.rs, src/cli/harden.rs | cargo test |  | Verify, clean, doctor (incl. keyring availability check), compat, harden — **Done** |
| FR-015 | src/config.rs, src/cli/config_cmd.rs |  |  | Config and local state model |
| FR-016 | src/cli/mod.rs, src/cli/doctor.rs, docs/exit-codes.md | cargo test |  | Output safety, CI, UX, exit codes; --quiet and --verbose supported consistently across all commands — **Done** |
| FR-017 | tests/golden_path.rs (lock_is_deterministic), tests/security.rs (keyring_entry_new_does_not_panic) | cargo test --test golden_path, cargo test --test security |  | Test/release quality requirements — **Done** |
| FR-018 | README.md, docs/format-spec.md |  | ADR-0002 | Documentation and locked decisions — **Done** |
| FR-019 | src/cli/status.rs, src/vault/index.rs | cargo test (47 tests pass) |  | Status: summary mode (no password) + authenticated hash-verification mode (`--password-stdin`) — **Done** |
| FR-020 | src/cli/diff.rs | cargo test |  | Diff behavior: unified diff for text, binary summary, --json output, --tool external diff invocation, $DIFF_TOOL env var, exit 1 on differences — **Done** |
| FR-021 | src/cli/rm.rs | cargo test (80 unit tests pass) |  | Remove vault entries with optional local plaintext deletion — **Done** |
| FR-022 | src/cli/passwd.rs | cargo test (80 unit tests pass) |  | Re-encrypt vault with new password, atomic rewrite, --rotate checklist — **Done** |
| FR-023 | src/cli/keyring_cmd.rs | cargo test (unit tests pass) |  | Keyring behavior (split) — **Done** |
| FR-024 | src/cli/verify.rs | cargo test (80 unit tests pass) |  | Validate vault integrity per-entry with hash verification and --json output — **Done** |
| FR-025 | src/cli/clean.rs | cargo test (80 unit tests pass) |  | Remove tracked plaintext files safely with per-file prompt and --force flag — **Done** |
| FR-026 | src/cli/doctor.rs | cargo test |  | Diagnose environment: vault/index existence, JSON validity, write access, unzip on PATH, keyring availability — **Done** |
| FR-027 | src/cli/compat.rs | cargo test |  | Compatibility-check behavior — **Done** |
| FR-028 | src/cli/harden.rs | cargo test |  | Update .gitignore with sensitive patterns; install pre-commit + pre-push hooks; --dry-run — **Done** |
| SEC-001 | src/vault/index.rs | cargo test (index no-filename assertion) |  | Metadata exposure default safety — **Done** |
| SEC-002 | src/crypto/mod.rs (validate_password_strength called at init + passwd) | cargo test --lib (validate_password_strength tests, password_too_short_is_rejected) |  | Password policy minimums — **Done** |
| SEC-003 | src/cli/policy.rs |  |  | Password policy controls — **Done** |
| SEC-004 | src/crypto/mod.rs (get_password env-var branch) | cargo test (VAULT_PASSWORD warning logic) |  | Env password leakage warning — **Done** |
| SEC-005 | src/crypto/mod.rs |  |  | Memory hygiene best-effort — **Done** |
| SEC-006 | src/fs/mod.rs | cargo test (safe_join tests) |  | Path traversal prevention — **Done** |
| SEC-007 | src/cli/unlock.rs, src/vault/format.rs |  |  | Symlink default deny — **Done** |
| SEC-008 |  |  |  | Post-lock plaintext removal |
| SEC-009 | src/cli/lock.rs |  |  | Shred warning semantics |
| SEC-010 | src/cli/status.rs, src/cli/lock.rs, src/cli/unlock.rs |  |  | Secret output redaction — **Done** |
| SEC-011 | src/crypto/mod.rs |  |  | Password output redaction — **Done** |
| SEC-012 | src/cli/mod.rs, src/main.rs | --quiet (all commands) + --verbose (all commands, meaningful output in lock/verify/doctor) — cargo test |  | Logging verbosity controls — **Done** |
| NFR-001 | src/vault/format.rs, src/vault/manifest.rs | cargo test (determinism test) |  | Deterministic update policy — **Done** |
| NFR-002 | src/vault/format.rs, src/vault/manifest.rs | Per-entry IVs are random (crypto-safe); manifest ordering is deterministic via BTreeMap |  | Determinism without crypto weakening — **Done** |
| NFR-003 | src/fs/mod.rs | cargo test (atomic_write test) |  | Atomic write IO policy — **Done** |
| NFR-004 | src/cli/completions.rs |  |  | Shell completion UX — **Done** |
| NFR-005 | src/cli/status.rs, src/cli/diff.rs | cargo test (pager tests pass) |  | $PAGER respected in status and diff human-readable output — **Done** |
| NFR-006 | .github/workflows/release.yml |  |  | Signed release artifacts (macOS binaries are Developer ID signed via imported certificate secrets in CI) — **Done** |
| NFR-007 | .github/workflows/release.yml |  |  | SBOM release artifact — **Done** |
| NFR-008 | docs/reproducible-build.md |  |  | Reproducible build documentation |
| NFR-009 | .github/workflows/ci.yml |  |  | Cross-platform CI matrix |
| NFR-010 | tests/golden_path.rs | cargo test --test golden_path |  | Golden path integration tests |
| NFR-011 | tests/corruption.rs | cargo test --test corruption |  | Corruption-path tests |
| NFR-012 | tests/security.rs | cargo test --test security |  | Security-path tests |
| NFR-013 |  |  |  | Determinism test coverage |
| NFR-014 | scripts/mock-keyring.sh, scripts/run-with-keyring.sh, scripts/manual-test-sandbox.sh, scripts/manual-sandbox-shell.sh, scripts/manual-keyring-smoke.sh | bash -n scripts/mock-keyring.sh scripts/run-with-keyring.sh scripts/manual-test-sandbox.sh scripts/manual-sandbox-shell.sh scripts/manual-keyring-smoke.sh; scripts/manual-keyring-smoke.sh |  | Mock keyring backend for local integration tests with store/lookup/list/purge coverage |
| NFR-015 | spec/AGENT.md | Test-first policy followed throughout; documented in spec/AGENT.md |  | Test-first implementation policy — **Done** |
| NFR-016 | src/cli/mod.rs, src/cli/status.rs | scripts/manual-test-sandbox.sh |  | AI-agent automation CLI profile (deterministic JSON, non-interactive, stable exits) |
| NFR-017 | src/cli/mod.rs |  |  | MCP 2025-11-25 server adapter pattern (CLI-first core + MCP tool interface) |
| NFR-018 | .github/workflows/release.yml, packaging/homebrew/git-secret-vault.rb, scripts/update-homebrew-formula.py | push-to-main trigger; publish-homebrew job; formula update script |  | Direct-push, per-architecture GitHub Homebrew tap release automation — **Done** |
| NFR-019 | .github/workflows/release.yml, Cargo.toml |  |  | cargo-dist release packaging and publication — Proposed |

<!--
Populate rows where obvious. Leave unknown cells empty.
This file is a navigational matrix, not immutable history.
Immutable history lives under spec/trace/events/ and spec/trace/claims/.
-->
