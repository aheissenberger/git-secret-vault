# ADR-0003 Dual-Profile Vault Architecture

## Status

Accepted

> **Supersedes ADR-0002** (GitSecretVault Safety and Compatibility Constraints)

## Context

The original ZIP-only vault format (ADR-0002) works well for single-user, single-machine workflows but breaks down in multi-agent and multi-branch repository environments:

- A monolithic encrypted ZIP archive is an opaque binary blob to Git. Any change to any secret rewrites the entire archive, producing merge conflicts that cannot be resolved automatically.
- Append-only audit trails are impossible when the whole container is rewritten on every mutation.
- Deterministic re-encryption of the ZIP means two agents encrypting the same plaintext at the same time still produce different ciphertexts, guaranteeing conflicts.
- Recovery requires decrypting and repacking the entire archive even when only one entry changed.

These shortcomings make the ZIP-only format untenable as the authoritative store for repository-native secret management.

## Decision

Replace the ZIP-only format with a **dual-profile vault architecture**:

### Profile 1 — Authoritative format (merge-optimized, repository-native)

The authoritative vault lives directly in the repository as a set of small, independently diffable files:

- **`blobs/<content-hash>.enc`** — One file per secret. Each blob is AEAD-encrypted with XChaCha20-Poly1305 (192-bit random nonce prepended to the ciphertext). The filename is the hex-encoded BLAKE3 content hash of the ciphertext, making blobs content-addressable and collision-free.
- **`index/events.jsonl`** — Append-only event log. Each line is a JSON object with fields: `timestamp` (RFC 3339, normalized to UTC), `entry_id` (stable opaque identifier), `content_hash` (references a blob), `key_id` (identifies the encryption key), and `op` (one of `add`, `update`, `remove`, `rotate`). No plaintext paths appear in this file.
- **`index/snapshot.json`** — Canonical sorted state derived deterministically from the event log. Periodically regenerated to bound recovery time. Sorted by `entry_id`; all keys within each object are lexicographically sorted.
- **`vault.meta.json`** — Vault-level metadata: format version, KDF parameters (Argon2id, with explicit `m`, `t`, `p` cost factors), crypto suite identifier, and active key IDs. Contains **no plaintext paths**.

### Profile 2 — Interchange format (tool-optimized, NOT authoritative)

- **`vault.zip`** — AES-256 ZIP (AE-2 profile) export for broad standard-tool access (7-Zip, bsdtar, WinZip, Keka, Windows Explorer). This file is **export-only** and is never the merge authority. It is regenerated from the authoritative profile on demand.

### Cryptographic constraints

- AEAD primitive: XChaCha20-Poly1305 exclusively. Deterministic encryption is never used for secret blobs.
- KDF: Argon2id with tunable cost parameters stored in `vault.meta.json`.
- Nonce: 192-bit random, prepended to each blob ciphertext.

### Serialization constraints

- All JSON files use stable canonical serialization: lexicographically sorted keys, normalized ISO 8601 timestamps.
- The snapshot is fully deterministic given the event log and must be reproducible by any compliant implementation.

## Consequences

**Breaking change — no backward compatibility with ADR-0002 ZIP-only vaults.**

Positive:

- Per-file blobs localize Git conflicts: changing one secret produces a diff in exactly one blob file and one appended line in `events.jsonl`, leaving all other blobs untouched.
- Append-only JSONL metadata is highly Git-mergeable and provides a tamper-evident audit trail.
- Canonical snapshots keep recovery fast and deterministic without replaying the full event log every time.
- Plaintext filenames are absent from all outer metadata, preserving the metadata-minimization posture of ADR-0002.
- ZIP export preserves the "open with standard tools" workflow for operators who need it.
- XChaCha20-Poly1305 with random nonces eliminates deterministic ciphertext, removing a class of conflicts and ciphertext-reuse risks.

Negative:

- Existing ZIP-only vaults must be migrated; there is no transparent upgrade path.
- The repository now contains more files (one per secret blob), which increases clone size for large vaults.
- ZIP export is a derived artifact and must be explicitly regenerated; it can drift from the authoritative store if not regenerated after mutations.

Neutral:

- Operators who relied on the ZIP as the primary interface must update their workflows to treat ZIP as export-only.
- The snapshot file is generated output and should be treated accordingly in code review.

## Alternatives Considered

- **Single ZIP (status quo, ADR-0002):** Rejected. Opaque binary, Git-unmergeable, full rewrite on every change, no audit trail.
- **Single JSONL without separate blobs:** Rejected. Embedding ciphertext inline in JSONL inflates the event log, makes blobs non-content-addressable, and couples metadata and ciphertext lifetimes.
- **Git object store as blob backend:** Considered. Adds implementation complexity and ties the vault format to Git internals, harming portability to non-Git environments.
- **Age/SOPS-style per-file encryption without index:** Considered. Loses the unified entry namespace, audit log, and snapshot recovery; harder to implement key rotation across all entries atomically.

## Requirement Links

- FR-002
- FR-003
- FR-005
- FR-006
- FR-007
- FR-018

## Trace Links

- spec/trace/events/2026-03-01T12-20-01Z-copilot-agent-FR-018.md
