# Current Infrastructure

## System Context

- Primary runtime: Rust (GitSecretVault CLI implementation)
- Supporting runtime: Node.js 25.x (spec-ledger scripts)
- Repository model: requirement-first spec-ledger under `spec/` with append-only trace history

## Vault Storage

The vault uses a **dual-profile** model:

**Authoritative profile** (primary, Git-tracked):

| Path | Description |
|------|-------------|
| `blobs/<sha256>.enc` | XChaCha20-Poly1305 AEAD ciphertext; 24-byte random nonce prepended |
| `index/events.jsonl` | Append-only JSONL event log; one JSON object per line |
| `index/snapshot.json` | Canonical sorted state; regenerated from events |
| `vault.meta.json` | Crypto suite, KDF params (`argon2id`), key IDs; no file paths stored |

**Interchange profile** (export/import only, not authoritative):

| Path | Description |
|------|-------------|
| `vault.zip` | AES-256 AE-2 encrypted ZIP; produced by `export`, consumed by `import` |

## Boundaries

- Public APIs: GitSecretVault CLI commands (init/lock/unlock/status/diff/rm/passwd/keyring/verify/clean/doctor/compat/harden/export/import)
- Internal modules: BlobStore, EventLog, SnapshotManager, VaultMeta, ZipExporter, ZipImporter, keyring adapters, filesystem safety checks, conflict resolution flows
- External dependencies: OS credential stores (macOS Keychain, Linux Secret Service-compatible providers, Windows Credential Manager)

## Ownership Map

- Platform: CLI runtime/tooling and repository automation
- Product: command UX, configuration model, and workflow behavior
- Security: password handling, metadata minimization, extraction safety, repository guardrails

## Operational Constraints

- Append-only trace events and claims
- Requirement-first changes
- ADR update for significant architecture decisions
- Authoritative vault state is the `blobs/` + `index/` + `vault.meta.json` tree; `vault.zip` is interchange-only and never authoritative
- `vault.meta.json` must not store file paths or secret names (no-paths guarantee)
- Default behavior must avoid revealing secret filenames/paths without password access
- Blob filenames are content addresses (SHA-256 of plaintext) and reveal no path information
