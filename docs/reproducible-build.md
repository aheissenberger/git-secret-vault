# Reproducible Build Notes

## Overview

`git-secret-vault` aims for reproducible builds within a single platform and toolchain version. Full cross-platform bit-for-bit reproducibility is constrained by the Rust toolchain, system libraries, and zip timestamp behavior.

## Building from source

```bash
# Pin toolchain via rust-toolchain.toml (already present)
cargo build --release

# Verify binary hash matches published checksum
sha256sum target/release/git-secret-vault
```

## Known entropy sources

| Source | Impact | Mitigation |
|--------|--------|-----------|
| Zip entry timestamps | Vault archive mtime fields | Normalised to file mtime; `manifest.json` uses deterministic ordering |
| Per-entry AES IV | Intentional; required for security | Each encrypt call uses a fresh random IV — this is correct |
| Rust compiler version | Binary layout may differ | Pin with `rust-toolchain.toml` |
| System library versions (libz, etc.) | Minor | Use the devcontainer image for reproducible CI builds |

## Vault-level determinism

The encrypted manifest and entry order inside `git-secret-vault.zip` are deterministic across repeated `lock` calls for the same inputs:
- Entries are sorted by canonical path (`BTreeMap` ordering)
- Timestamps are taken from the source file's mtime, not wall clock
- The outer index integrity marker is a SHA-256 of the manifest bytes (before encryption)

Cryptographic IVs are intentionally random per-entry and are **not** deterministic — this is required for security and does not violate the determinism policy (NFR-001, NFR-002).

## CI reproducibility

The GitHub Actions workflow pins:
- `actions/checkout@v4`
- `dtolnay/rust-toolchain@stable` (consider `@<version>` for stricter pinning)
- `actions/cache@v4`

For maximum reproducibility, pin the Rust toolchain to a specific version in `rust-toolchain.toml`.

## Release signing (macOS Developer ID)

The release workflow signs macOS binaries with a Developer ID certificate imported from GitHub Actions secrets.

### 1) Export a Developer ID identity to `.p12`

On a macOS machine with the signing identity installed:

```bash
# List available code-signing identities and copy the exact Developer ID name
security find-identity -v -p codesigning

# Export identities from login keychain to PKCS#12 (set a strong export password)
security export \
	-k ~/Library/Keychains/login.keychain-db \
	-t identities \
	-f pkcs12 \
	-P "${P12_EXPORT_PASSWORD}" \
	-o developer-id-signing.p12
```

### 2) Base64 encode the certificate for GitHub secrets

```bash
# macOS / BSD base64
base64 -i developer-id-signing.p12 | tr -d '\n' > developer-id-signing.p12.b64

# Linux GNU base64 alternative
# base64 -w 0 developer-id-signing.p12 > developer-id-signing.p12.b64
```

### 3) Configure repository secrets

Create these repository or environment secrets in GitHub:

- `MACOS_CERTIFICATE_P12_BASE64`: content of `developer-id-signing.p12.b64`
- `MACOS_CERTIFICATE_PASSWORD`: password used as `P12_EXPORT_PASSWORD`
- `MACOS_KEYCHAIN_PASSWORD`: temporary keychain password used during CI import
- `MACOS_SIGNING_IDENTITY`: exact identity name, for example `Developer ID Application: Example Org (TEAMID)`

### 4) Validate on a release run

On the macOS build jobs, verify logs include successful output from:

- `codesign --verify --verbose=2 <binary>`
- `codesign --display --verbose=2 <binary>`

If signing fails, check identity string exactness and ensure the exported `.p12` includes private key material.

### Troubleshooting common signing failures

- **Identity mismatch (`codesign: no identity found`)**
	- Re-run `security find-identity -v -p codesigning` on the source Mac.
	- Ensure `MACOS_SIGNING_IDENTITY` exactly matches the full identity string.

- **Certificate imports but signing still fails (no private key)**
	- Re-export with `-t identities` (not cert-only export).
	- Confirm the `.p12` was exported from a keychain entry that includes the private key.

- **Keychain access errors (`User interaction is not allowed`)**
	- Verify `MACOS_KEYCHAIN_PASSWORD` is set and non-empty.
	- Ensure workflow runs `security unlock-keychain` and `security set-key-partition-list` before `codesign`.

- **Malformed base64 secret / decode failure**
	- Regenerate `developer-id-signing.p12.b64` and ensure it is a single line.
	- Confirm `MACOS_CERTIFICATE_P12_BASE64` contains the full value without truncation.

## Artifact verification with cosign

All release binaries are signed with cosign keyless signing via GitHub OIDC. No private key is stored — signatures are anchored to the GitHub Actions OIDC token and recorded in Sigstore's transparency log (Rekor).

To verify a downloaded binary:

```bash
cosign verify-blob \
  --bundle git-secret-vault.sigstore.json \
	--certificate-identity-regexp "https://github.com/aheissenberger/git-secret-vault/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  git-secret-vault
```
