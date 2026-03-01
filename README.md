# git-secret-vault

Encrypted secret vault for git repositories. Lock secrets into an AES-encrypted ZIP, commit the vault file, never commit plaintext.

## Features
- AES-256 encrypted ZIP vault (compatible with unzip, 7-Zip, Python zipfile with AES support)
- Deterministic, atomic vault updates
- Password, environment variable, or keyring credential sources
- Git-safe: commit the vault, .gitignore the plaintext
- CI-friendly: --password-stdin, --fail-if-dirty, --json output
- Cross-platform: Linux, macOS, Windows

## Quickstart

```bash
# 1. Initialize a vault in your repo
git-secret-vault init

# 2. Lock a secret file into the vault
git-secret-vault lock .env

# 3. Commit the vault (not the plaintext)
git add git-secret-vault.zip .git-secret-vault.index.json
git commit -m "chore: add encrypted vault"

# 4. Unlock on another machine (enter password when prompted)
git-secret-vault unlock .env

# 5. Check vault status
git-secret-vault status
```

## Installation

```bash
cargo install --path .
```

## Commands

| Command | Description |
|---------|-------------|
| `init` | Create a new vault |
| `lock [files...]` | Encrypt files into vault |
| `unlock [files...]` | Decrypt files from vault |
| `status` / `ls` | Show vault status |
| `diff` | Show diff between vault and local files |
| `rm <files...>` | Remove entries from vault |
| `passwd` | Change vault password |
| `verify` | Validate vault integrity |
| `clean` | Remove unlocked plaintext safely |
| `doctor` | Diagnose environment |
| `harden` | Update .gitignore and install git hooks |
| `compat` | Check encryption compatibility |
| `policy show/set` | Manage password policy |
| `config show/set/init` | Manage repo config |
| `keyring save/status/delete/list/purge` | Manage keyring credentials |
| `completions <shell>` | Generate shell completions |

## CI Integration

```yaml
- name: Verify vault is up to date
  run: git-secret-vault status --fail-if-dirty --password-stdin
  env:
    VAULT_PASSWORD: ${{ secrets.VAULT_PASSWORD }}
```

## Hardening (git hooks)

```bash
# Add .gitignore patterns + install pre-commit hook
git-secret-vault harden --hooks
```

The pre-commit hook runs `git-secret-vault lock --check` to prevent committing stale vault state.

## Keyring

```bash
# Save password to system keyring (macOS Keychain, Windows Credential Manager, Linux Secret Service)
git-secret-vault keyring save

# Check keyring status
git-secret-vault keyring status
```

## Threat Model

**What is protected:**
- Plaintext secret content (encrypted at rest in the vault ZIP)
- Entry filenames are not stored in the outer index (SEC-001)
- Passwords are zeroed from memory after use (best-effort)

**What is NOT protected:**
- Vault existence (the .zip file is committed)
- Entry count (stored in outer index)
- File sizes and timestamps (stored in encrypted manifest, not outer index)
- Adversaries with full filesystem access (key management is out of scope)

**Limitations:**
- `--shred` is best-effort: not guaranteed on SSDs or copy-on-write filesystems
- Memory hygiene is best-effort in Rust (no mlock, pages may be swapped)
- Keyring security depends on platform keyring implementation

## Metadata Disclosure Statement

The outer index (`.git-secret-vault.index.json`) committed to git reveals:
- Vault UUID
- Format version
- Last-updated timestamp
- Entry count (number of secrets)

It does NOT reveal entry names, paths, sizes, or content. This is by design (SEC-001).

## Shell Completions

```bash
# Bash
git-secret-vault completions bash >> ~/.bash_completion

# Zsh
git-secret-vault completions zsh > ~/.zfunc/_git-secret-vault

# Fish
git-secret-vault completions fish > ~/.config/fish/completions/git-secret-vault.fish
```
