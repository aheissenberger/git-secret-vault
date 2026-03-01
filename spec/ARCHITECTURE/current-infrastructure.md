# Current Infrastructure

## System Context

- Primary runtime: Rust (GitSecretVault CLI implementation)
- Supporting runtime: Node.js 25.x (spec-ledger scripts)
- Repository model: requirement-first spec-ledger under `spec/` with append-only trace history

## Boundaries

- Public APIs: GitSecretVault CLI commands (init/lock/unlock/status/diff/rm/passwd/keyring/verify/clean/doctor/compat/harden)
- Internal modules: vault format handling, manifest/index handling, keyring adapters, filesystem safety checks, conflict resolution flows
- External dependencies: OS credential stores (macOS Keychain, Linux Secret Service-compatible providers, Windows Credential Manager)

## Ownership Map

- Platform: CLI runtime/tooling and repository automation
- Product: command UX, configuration model, and workflow behavior
- Security: password handling, metadata minimization, extraction safety, repository guardrails

## Operational Constraints

- Append-only trace events and claims
- Requirement-first changes
- ADR update for significant architecture decisions
- Vault artifacts must remain standards-compatible encrypted ZIP files decryptable by common compatible unzip tools
- Default behavior must avoid revealing secret filenames/paths without password access
