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
