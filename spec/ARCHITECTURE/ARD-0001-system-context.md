# ARD-0001 System Context

## Status

Accepted

## Purpose

Provide a stable architecture baseline so agents can reason about GitSecretVault implementation and process constraints without reverse-engineering details.

## Runtime and Toolchain

- Primary language/runtime: Rust toolchain (stable)
- Supporting runtime: Node.js 25.x for spec-ledger validation and generation scripts
- Package manager usage: minimal; scripts execute directly via shebang

## Topology

- CLI source under `src/`
- Requirement source of truth under `spec/requirements/`
- Trace history under `spec/trace/events/`
- Ownership claims under `spec/trace/claims/`
- Architecture references under `spec/ARCHITECTURE/`
- Decision records under `spec/DECISIONS/`

## Storage Architecture (Dual-Profile)

The vault uses two storage profiles with distinct roles:

**Authoritative profile** — the primary on-disk representation, optimised for Git diff-friendliness and conflict minimisation:

```
blobs/<sha256-of-plaintext>.enc   — XChaCha20-Poly1305 AEAD ciphertext (24-byte nonce prepended)
index/events.jsonl                — append-only event log (one JSON object per line)
index/snapshot.json               — canonical sorted state snapshot
vault.meta.json                   — vault-level metadata (crypto suite, KDF params, key IDs)
```

**Interchange profile** — used exclusively for export/import, never authoritative:

```
vault.zip                         — AES-256 AE-2 encrypted ZIP for cross-tool sharing
```

## Core Components

| Component        | Role                                                                 |
|------------------|----------------------------------------------------------------------|
| BlobStore        | Stores and retrieves content-addressed encrypted blobs under `blobs/` |
| EventLog         | Appends and reads `index/events.jsonl` (add/update/remove/rotate ops) |
| SnapshotManager  | Regenerates `index/snapshot.json` from the event log on demand       |
| VaultMeta        | Reads and writes `vault.meta.json`; enforces no-paths guarantee      |
| ZipExporter      | Produces `vault.zip` interchange packages from authoritative state   |
| ZipImporter      | Ingests `vault.zip` packages and writes into authoritative profile   |

## Data Flows

### Lock (plaintext → vault)

1. Plaintext bytes hashed (SHA-256) → content address.
2. BlobStore encrypts with XChaCha20-Poly1305; random 24-byte nonce prepended; written to `blobs/<hash>.enc`.
3. EventLog appends `{"op":"add|update","entry_id":"<uuid>","content_hash":"<sha256>","key_id":"<uuid>","timestamp":"..."}`.
4. SnapshotManager regenerates `index/snapshot.json`.

### Unlock (vault → plaintext)

1. SnapshotManager reads `index/snapshot.json` to resolve current `content_hash` for the requested entry.
2. BlobStore reads `blobs/<content_hash>.enc`; strips 24-byte nonce; decrypts with XChaCha20-Poly1305.
3. Plaintext bytes written to destination path.

### Export (vault → ZIP)

1. ZipExporter reads snapshot + blobs; re-encrypts each blob under AES-256 AE-2; writes `vault.zip`.

### Import (ZIP → vault)

1. ZipImporter decrypts `vault.zip`; converts each entry to a blob; appends events; regenerates snapshot.

## Interface Boundaries

- Requirement records define expected behavior and acceptance criteria
- ADRs define architecture-level constraints and decisions
- Trace events/claims define immutable proposal, implementation, and ownership history

## Linked ADRs

- spec/DECISIONS/ADR-0001-template.md
- spec/DECISIONS/ADR-0002-git-secret-vault-safety-and-compatibility.md

## Requirement Links

- FR-001
- FR-002
- FR-003
- FR-004
- FR-005
- FR-006
- FR-007
- FR-008
- FR-009
- FR-010
- FR-011
- FR-012
- FR-013
- FR-014
- FR-015
- FR-016
- FR-017
- FR-018
- FR-019
- FR-020
- FR-021
- FR-022
- FR-023
- FR-024
- FR-025
- FR-026
- FR-027
- FR-028
- SEC-001
- SEC-002
- SEC-003
- SEC-004
- SEC-005
- SEC-006
- SEC-007
- SEC-008
- SEC-009
- SEC-010
- SEC-011
- SEC-012
- NFR-001
- NFR-002
- NFR-003
- NFR-004
- NFR-005
- NFR-006
- NFR-007
- NFR-008
- NFR-009
- NFR-010
- NFR-011
- NFR-012
- NFR-013
- NFR-014
