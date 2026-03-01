# GitSecretVault Format Specification

Version: 2.0 | Status: Stable

---

## 1. Overview

GitSecretVault uses a **dual-profile** storage model:

| Profile | Role | Authoritative? |
|---------|------|----------------|
| **Authoritative** (`blobs/` + `index/` + `vault.meta.json`) | Primary on-disk representation; Git-tracked | ✅ Yes |
| **Interchange** (`vault.zip`) | Cross-tool export/import only | ❌ No |

The authoritative profile is designed for Git workflows: each secret maps to a single content-addressed file, so independent edits to different secrets produce non-conflicting diffs. The interchange ZIP provides compatibility with external tools and offline transfer.

---

## 2. Authoritative Format

The vault root contains:

```
blobs/
  <sha256-of-plaintext>.enc   — one file per unique plaintext content
index/
  events.jsonl                — append-only event log
  snapshot.json               — current canonical state
vault.meta.json               — vault-level metadata
```

No file paths or secret names appear outside of encrypted blobs.

---

## 3. Blob Format

**Location**: `blobs/<sha256-of-plaintext>.enc`

**File name**: lowercase hex SHA-256 digest of the plaintext bytes. Acts as a content address; identical plaintexts share one blob.

**Layout**:

```
| Bytes 0–23   | 24-byte XChaCha20-Poly1305 nonce (random, unique per encryption) |
| Bytes 24–end | XChaCha20-Poly1305 AEAD ciphertext + 16-byte Poly1305 tag        |
```

- Algorithm: XChaCha20-Poly1305 (IETF variant, 24-byte nonce)
- The nonce is generated fresh with a CSPRNG on every encryption, even for re-encryption of the same plaintext.
- The AEAD tag (16 bytes) is appended by the cipher and covers the full ciphertext.
- The associated data (AD) field is the raw `entry_id` UUID bytes (16 bytes).
- Key derivation is described in Section 8.

---

## 4. Event Log Schema

**Location**: `index/events.jsonl`

Each line is a self-contained JSON object. Lines are appended; existing lines are never modified or deleted.

**Record fields**:

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | RFC 3339 string (UTC) | Wall-clock time of the operation |
| `op` | string | One of: `add`, `update`, `remove`, `rotate` |
| `entry_id` | UUID v4 string | Stable identifier for the logical secret entry |
| `content_hash` | SHA-256 hex string | Digest of plaintext; names the blob file. Omitted for `remove`. |
| `key_id` | UUID v4 string | Identifier of the wrapping key used. Omitted for `remove`. |

**Example records**:

```jsonl
{"timestamp":"2026-03-01T10:00:00Z","op":"add","entry_id":"a1b2c3d4-...","content_hash":"e3b0c44298fc...","key_id":"k1k2k3k4-..."}
{"timestamp":"2026-03-01T11:00:00Z","op":"update","entry_id":"a1b2c3d4-...","content_hash":"9f86d081884c...","key_id":"k1k2k3k4-..."}
{"timestamp":"2026-03-01T12:00:00Z","op":"remove","entry_id":"a1b2c3d4-..."}
{"timestamp":"2026-03-01T13:00:00Z","op":"rotate","entry_id":"a1b2c3d4-...","content_hash":"9f86d081884c...","key_id":"k9k8k7k6-..."}
```

**Op semantics**:

- `add` — first time an entry is stored.
- `update` — plaintext changed; new blob recorded, old blob may be pruned.
- `remove` — entry deleted; subsequent snapshot omits it.
- `rotate` — same plaintext, new key; a new blob is produced.

---

## 5. Snapshot Schema

**Location**: `index/snapshot.json`

The snapshot is the canonical current state derived by replaying the event log. It is regenerated in full whenever the event log is modified; it is not authoritative on its own.

```json
{
  "version": 1,
  "generated_at": "2026-03-01T13:00:00Z",
  "entries": [
    {
      "entry_id": "a1b2c3d4-...",
      "content_hash": "9f86d081884c...",
      "key_id": "k1k2k3k4-..."
    }
  ]
}
```

**Fields**:

| Field | Description |
|-------|-------------|
| `version` | Schema version; currently `1` |
| `generated_at` | RFC 3339 UTC timestamp of the most recent regeneration |
| `entries` | Array of active entries, sorted ascending by `entry_id` |

Removed entries do not appear. Entries are sorted by `entry_id` for deterministic diffs.

---

## 6. Vault Metadata Schema

**Location**: `vault.meta.json`

Plain JSON. Contains no file paths or secret names.

```json
{
  "version": 1,
  "crypto_suite": "xchacha20-poly1305",
  "kdf": "argon2id",
  "kdf_params": {
    "m_cost": 65536,
    "t_cost": 3,
    "p_cost": 4
  },
  "key_ids": ["k1k2k3k4-...", "k9k8k7k6-..."]
}
```

**Fields**:

| Field | Description |
|-------|-------------|
| `version` | Metadata schema version; currently `1` |
| `crypto_suite` | AEAD algorithm used for blobs |
| `kdf` | Key derivation function identifier |
| `kdf_params` | KDF tuning parameters (see Section 8) |
| `key_ids` | All key UUIDs ever active; last element is current |

---

## 7. Interchange Format

**File**: `vault.zip`

Used exclusively for `export` and `import` operations. Not stored in the repository. Not authoritative.

- Container: ZIP archive (PKZIP/Info-ZIP compatible)
- Entry encryption: AES-256 AE-2 (WinZip AES extension)
- Key derivation for ZIP entries: PBKDF2-HMAC-SHA1, iterations per AE-2 spec (key-size dependent)
- Each blob in the authoritative profile becomes one ZIP entry; the entry name is the content hash.
- A `vault.meta.json` entry is included for receiver-side KDF configuration.
- A `snapshot.json` entry is included so importers can reconstruct the event log.

**Compatibility**: the interchange ZIP can be extracted with:
- `unzip -P <password> vault.zip` (unzip 6.0+ with AES support compiled in)
- 7-Zip 19+
- Python: `pyzipper` library (standard `zipfile` does not support AES)

---

## 8. Key Derivation

Password-based key derivation uses **Argon2id** with the following default parameters:

| Parameter | Value | Meaning |
|-----------|-------|---------|
| `m_cost` | 65536 | Memory: 64 MiB |
| `t_cost` | 3 | Iterations |
| `p_cost` | 4 | Parallelism |
| Output length | 32 bytes | 256-bit key for XChaCha20-Poly1305 |
| Salt | 16 bytes random | Stored in `vault.meta.json` under the relevant key record |

Parameters are stored in `vault.meta.json` under `kdf_params` so readers can reproduce derivation without hard-coding values.

---

## 9. Merge Behavior

The authoritative layout is designed to minimise Git merge conflicts:

- Each unique plaintext produces exactly one blob file. Independent secrets never share a file.
- The event log (`events.jsonl`) is append-only; concurrent branches each append without touching existing lines. A merge produces a union of both branches' appended lines, which is always resolvable.
- The snapshot (`snapshot.json`) is regenerated deterministically from the merged event log, so it can always be rebuilt after a conflict is resolved.
- `vault.meta.json` is small and rarely changes; key rotation is the primary source of changes to this file.

The result: two developers locking different secrets on separate branches produce zero merge conflicts in `blobs/` and a trivially auto-mergeable `events.jsonl`.

---

## 10. Versioning

The `version` field in `vault.meta.json` and `snapshot.json` allows future format evolution.

- Minor additions (new optional fields) are backwards compatible within the same version.
- Breaking changes increment the version and require an explicit `migrate` command.
- Readers encountering an unknown version must reject the vault with a clear error rather than silently mis-interpreting data.
