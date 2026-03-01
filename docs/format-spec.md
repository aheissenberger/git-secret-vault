# GitSecretVault Format Specification

Version: 1.0 | Status: Stable

## Overview

The vault is a standard ZIP file using AES-256 encryption (ZIP 2.x AES extension, also called WinZip AES). Each entry is independently encrypted.

## Files

| File | Description |
|------|-------------|
| `git-secret-vault.zip` | Encrypted vault archive |
| `.git-secret-vault.index.json` | Unencrypted outer index |

## Outer Index Schema

`.git-secret-vault.index.json` is plain JSON:

```json
{
  "uuid": "<vault-uuid-v4>",
  "format_version": 1,
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-01T00:00:00Z",
  "entry_count": 3,
  "integrity_marker": "<sha256-hex-of-manifest-bytes>"
}
```

The `integrity_marker` is a SHA-256 of the plaintext manifest JSON bytes, providing tamper detection without decryption.

## Vault Archive Structure

Inside `git-secret-vault.zip`, each ZIP entry is AES-256 encrypted. Entry names are the canonical relative path of the secret file (e.g., `secrets/api.key`).

One special entry is always present: `manifest.json` (encrypted).

## Manifest Schema

The decrypted `manifest.json`:

```json
{
  "uuid": "<vault-uuid-v4>",
  "format_version": 1,
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-01T00:00:00Z",
  "entries": [
    {
      "path": "secrets/api.key",
      "size": 128,
      "mtime": "2026-01-01T00:00:00Z",
      "sha256": "<sha256-hex>",
      "mode": 420
    }
  ]
}
```

Entries are sorted by `path` (lexicographic, ascending) for determinism.

## Encryption Profile

- Algorithm: AES-256-CTR (ZIP AES extension)
- Key derivation: PBKDF2-HMAC-SHA1, 1000 iterations (ZIP AES spec default)
- Salt: 16 bytes random per entry
- Authentication: 10-byte HMAC-SHA1 verification value per entry (per ZIP AES spec)

## Determinism Policy

Repeated `lock` calls with the same inputs produce structurally equivalent manifests:
- Entry order: sorted by path (BTreeMap)
- Timestamps: taken from source file mtime, not wall clock
- Cryptographic IVs: intentionally random per entry (required for security; not deterministic)

## Versioning

The `format_version` field allows future format evolution. Version 1 is the current and only stable version.

Upgrade policy: minor additions (new optional manifest fields) are backwards compatible. Breaking changes increment the version and require an explicit migration command.

## Compatibility

The vault ZIP can be extracted without this tool using:
- `unzip -P <password> git-secret-vault.zip` (unzip 6.0+ with AES support)
- 7-Zip 19+
- Python: `pyzipper` library

Note: The standard Python `zipfile` module does not support AES encryption.
