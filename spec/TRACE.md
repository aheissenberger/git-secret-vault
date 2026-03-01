# Traceability Matrix

| Requirement | Implementation | Verification | Decisions | Notes |
|------------|---------------|-------------|-----------|------|

| FR-001 |  |  |  | Legacy migration scaffold |
| FR-002 |  |  |  | Vault format and compatibility |
| FR-003 |  |  |  | Metadata minimization and index |
| FR-004 |  |  |  | Encrypted manifest, determinism, atomicity |
| FR-005 |  |  |  | Password policy and input handling |
| FR-006 |  |  |  | Filesystem extraction and deletion safety |
| FR-007 |  |  |  | Git hardening and drift controls |
| FR-008 |  |  |  | Required CLI command set |
| FR-009 |  |  |  | Init workflow behavior |
| FR-010 |  |  |  | Lock workflow behavior |
| FR-011 |  |  |  | Unlock workflow and conflicts |
| FR-012 |  |  |  | Status and diff behavior |
| FR-013 |  |  |  | Remove, password rotation, keyring |
| FR-014 |  |  |  | Verify, clean, doctor, compat, harden |
| FR-015 |  |  |  | Config and local state model |
| FR-016 |  |  |  | Output safety, CI, UX, exit codes |
| FR-017 |  |  |  | Test/release quality requirements |
| FR-018 |  |  | ADR-0002 | Documentation and locked decisions |
| FR-019 |  |  |  | Status behavior (split) |
| FR-020 |  |  |  | Diff behavior (split) |
| FR-021 |  |  |  | Remove behavior (split) |
| FR-022 |  |  |  | Password rotation behavior (split) |
| FR-023 |  |  |  | Keyring behavior (split) |
| FR-024 |  |  |  | Verify behavior (split) |
| FR-025 |  |  |  | Clean behavior (split) |
| FR-026 |  |  |  | Doctor behavior (split) |
| FR-027 |  |  |  | Compatibility-check behavior (split) |
| FR-028 |  |  |  | Harden behavior (split) |
| SEC-001 |  |  |  | Metadata exposure default safety |
| SEC-002 |  |  |  | Password policy minimums |
| SEC-003 |  |  |  | Password policy controls |
| SEC-004 |  |  |  | Env password leakage warning |
| SEC-005 |  |  |  | Memory hygiene best-effort |
| SEC-006 |  |  |  | Path traversal prevention |
| SEC-007 |  |  |  | Symlink default deny |
| SEC-008 |  |  |  | Post-lock plaintext removal |
| SEC-009 |  |  |  | Shred warning semantics |
| SEC-010 |  |  |  | Secret output redaction |
| SEC-011 |  |  |  | Password output redaction |
| SEC-012 |  |  |  | Logging verbosity controls |
| NFR-001 |  |  |  | Deterministic update policy |
| NFR-002 |  |  |  | Determinism without crypto weakening |
| NFR-003 |  |  |  | Atomic write IO policy |
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
| NFR-014 |  |  |  | Keyring integration tests |

<!--
Populate rows where obvious. Leave unknown cells empty.
This file is a navigational matrix, not immutable history.
Immutable history lives under spec/trace/events/ and spec/trace/claims/.
-->
