# Homebrew Tap

GitSecretVault is distributed via a GitHub-hosted Homebrew tap.

## Tap repository convention

The tap repository is named `homebrew-tools` and lives under the same
GitHub account as this project:

```
aheissenberger/homebrew-tools
```

Homebrew resolves `brew tap aheissenberger/tools` to that repository automatically.

## Installation

```sh
brew tap aheissenberger/tools
brew install git-secret-vault
```

## Required secret

The release workflow pushes updated formula files to the tap repository.  To
enable this, create a GitHub Actions secret named `HOMEBREW_TAP_TOKEN` in the
**source** repository (this repo) containing a GitHub Personal Access Token (PAT)
with **repo write** access to `aheissenberger/homebrew-tools`.

The workflow step that pushes to the tap is gated on `env.HOMEBREW_TAP_TOKEN != ''`,
so CI passes safely even when the secret is not yet configured.

## Supported architectures

| Target triple | Platform |
|---|---|
| `aarch64-apple-darwin` | macOS (Apple Silicon) |
| `x86_64-apple-darwin` | macOS (Intel) |
| `x86_64-unknown-linux-gnu` | Linux (x86-64) |

## How it works

1. A push to `main` triggers the `release` workflow.
2. The `build` job cross-compiles binaries for all three Homebrew targets.
3. The `publish-homebrew` job downloads the artifacts, computes SHA256 checksums,
   updates `packaging/homebrew/git-secret-vault.rb` via
   `scripts/update-homebrew-formula.py`, and pushes the result to the tap repo
   using the GitHub REST API (`PUT /repos/.../contents/...`).
4. Re-running the workflow for the same commit is safe: the `PUT` call is
   idempotent and any transient failure produces a workflow warning rather than
   an error.
