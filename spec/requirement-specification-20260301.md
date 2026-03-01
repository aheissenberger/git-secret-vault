# Requirements Specification: SafeZipVault CLI (Max-Safety, Always-Decryptable ZIP)

> ⚠️ **Note**: This document exists for historical reasons and should not be used by AI agents for code generation or implementation decisions. It may contain outdated information, superseded design choices, or constraints that are no longer relevant. Please refer to the current implementation and active design documentation instead.

## 1. Purpose

Build a cross-platform CLI tool that enables developers to **store secret files (e.g., `.env`, JSON credentials, PEM keys)** in a repository by committing a **single encrypted ZIP archive** (“vault”). The vault MUST remain **decryptable/extractable with common unzip tools** (no proprietary container), while the CLI optimizes for **maximum safety**: minimizing metadata leakage, preventing footguns, and providing strong operational guardrails.

The UX and command set should be broadly comparable to `lockenv` (init → lock → commit → unlock; status/diff/conflict; passwd; keyring support).

> Design constraint: **“Unzip should always work.”** The produced vault MUST be a standards-compatible encrypted ZIP that can be decrypted by widely available unzip tools (e.g., 7-Zip / common platform tools that support AES ZIP). The CLI must also implement encryption/decryption internally for consistent behavior across platforms.

---

## 2. Goals and Non-Goals

### 2.1 Goals

* **Encrypted ZIP vault file** is safe to commit and is **decryptable with common unzip tools**.
* **Max safety defaults**:

  * Avoid accidental plaintext commits
  * Prevent unsafe extraction behaviors (zip-slip, symlinks)
  * Strong conflict handling
  * Clear CI modes and drift detection
* **Mandatory OS credential storage**:

  * macOS Keychain
  * Linux Secret Service compatible keyrings (GNOME Keyring / KWallet)
  * Windows Credential Manager
* Deterministic vault updates to reduce Git churn.

### 2.2 Non-Goals

* Not an enterprise secret manager (no server, no policy engine, no audit backend).
* Not providing per-user cryptographic access control (shared password model is baseline; rotation supported; advanced recipient encryption may be future work).
* Not protecting secrets once unlocked on a compromised machine or CI runner.

---

## 3. Terminology

* **Vault**: Encrypted ZIP archive committed to VCS (default: `.safezipvault.zip`).
* **Working secrets**: Plaintext files in working directory (e.g., `.env`, `config/keys.json`).
* **Tracked entry**: A path listed in the vault index/manifest.
* **Index**: A minimal, non-secret metadata file stored alongside the vault for safety UX (optional but recommended) without exposing file names.
* **Keyring**: OS credential store.

---

## 4. Threat Model and Security Posture

### 4.1 Protects Against

* Accidental commit of plaintext secrets.
* Repository leak without vault password.
* Lost/stolen developer machine where vault password is not accessible.

### 4.2 Does NOT Protect Against

* Malware/attacker on a developer machine after `unlock`.
* Secrets exfiltration via CI logs/artifacts if misconfigured.
* An attacker with the vault password.

### 4.3 Safety Priorities

1. Prevent plaintext exposure and accidental commits.
2. Prevent unsafe extraction and path attacks.
3. Minimize metadata leakage by default, while preserving “unzip works” constraint.
4. Provide operational controls for rotation and drift detection.

---

## 5. Vault Format and Compatibility

### 5.1 Vault Format

**FR-VLT-1**: Vault MUST be a standards-compatible **encrypted ZIP archive** using a broadly supported encryption profile (AES-based preferred).
**FR-VLT-2**: The CLI MUST implement encryption/decryption internally and MUST NOT depend on external zip/unzip tooling for core operations.
**FR-VLT-3**: The vault MUST be decryptable using common unzip tools that support the chosen encryption profile (document the compatibility list).

### 5.2 Compatibility Verification

**FR-VLT-4**: Provide `compat check` command that:

* Reports the vault encryption profile and expected compatible tools.
* Optionally performs a local self-test by creating a tiny sample vault and decrypting it with the CLI.
* Clearly warns if the platform’s default extractor is likely incompatible.

### 5.3 Minimal Metadata Exposure Strategy (Max Safety + Unzip Always Works)

Because encrypted ZIP still may expose some structure depending on tooling, the tool MUST:

* **Encrypt all secret file contents** and the **full manifest** inside the vault.
* Store only a **minimal outer index** (outside the vault, separate file) that contains:

  * vault UUID
  * format version
  * last updated timestamp
  * entry count
  * overall vault hash / integrity marker (non-secret)
  * NO filenames or paths

**SEC-META-1**: Default configuration MUST NOT expose filenames/paths without password.
**FR-IDX-1**: Provide `.safezipvault.index` (name configurable) as the minimal non-secret index.

> Note: Users can still unzip with a password and see filenames after decryption—this is acceptable and consistent with “unzip works.” The safety requirement is to avoid revealing names/paths without password.

### 5.4 Encrypted Manifest (Inside Vault)

**FR-MAN-1**: Inside the vault, store `manifest.json` encrypted like any other entry.
**FR-MAN-2**: Manifest includes:

* format version
* vault UUID
* encryption profile identifier
* created/updated timestamps
* list of entries with:

  * relative path (POSIX style internal canonical)
  * size
  * mtime
  * sha256 hash
  * permissions (POSIX mode if applicable)
  * entry type (regular file only by default)

### 5.5 Determinism

**NFR-DET-1**: Vault updates SHOULD be deterministic:

* stable entry ordering
* normalized timestamps (or deterministic timestamp policy)
* consistent compression settings
  **NFR-DET-2**: Determinism must not weaken security (no reuse of unsafe IVs or similar; encryption must remain sound).

### 5.6 Atomicity

**NFR-IO-1**: All vault writes MUST be atomic:

* write to temp
* fsync best-effort
* rename

---

## 6. Password, Policy, and Secrets Handling

### 6.1 Password Policy

**SEC-PASS-1**: Tool MUST enforce a configurable minimum password policy:

* default min length (e.g., 14+)
* reject common weak passwords (basic checks)
* encourage passphrases
  **SEC-PASS-2**: Provide `policy show` and `policy set` (config file) to adjust.

### 6.2 Password Inputs

**FR-PASS-1**: Password sources priority:

1. `--password-stdin` (CI safe)
2. env var (explicit opt-in)
3. OS keyring (if enabled)
4. interactive prompt

**SEC-PASS-3**: If env var mode is used, tool MUST print a warning about leakage via process env / logs.
**FR-CI-1**: Provide `--no-prompt` to fail fast if no password source is available.

### 6.3 Memory Hygiene

**SEC-MEM-1**: Best-effort secret buffer clearing in memory MUST be implemented and documented (acknowledge limitations by language/runtime).

---

## 7. Filesystem Safety (Zip-Slip / Symlinks / Permissions)

### 7.1 Path Safety

**SEC-FS-1**: Tool MUST prevent path traversal on unlock:

* reject absolute paths
* reject `..` segments
* canonicalize and validate output path is inside repo root (or configured output root)

### 7.2 Symlink Policy

**SEC-FS-2**: Default: tool MUST NOT store or restore symlinks.
**FR-FS-1**: Optional feature gate `--allow-symlinks`:

* store symlink target as data, not as a zip symlink entry (portable)
* restore symlink only if explicitly enabled, with warnings

### 7.3 Permissions

**FR-FS-2**: On POSIX, store and restore file mode (e.g., 0600 default for secrets unless overridden).
**FR-FS-3**: On Windows, document limitations; ensure files are created with best-effort restricted access.

### 7.4 Safe Deletion

**SEC-DEL-1**: `--remove` deletes plaintext after locking.
**SEC-DEL-2**: Provide `--shred` as best-effort only, with clear warning that secure delete is not guaranteed on modern filesystems/SSDs.

---

## 8. Repository Integration and Guardrails (Max Safety)

### 8.1 Hardening Command

**FR-GIT-1**: Provide `harden` command that:

* adds working secret patterns to `.gitignore`
* ensures vault file is NOT ignored
* optionally installs hooks (or prints scripts) to:

  * pre-commit: block committing tracked secret files in plaintext
  * pre-push: ensure `status` is clean (no drift)

### 8.2 Drift Detection

**FR-DRIFT-1**: `status` MUST show:

* modified locally but not locked (dirty)
* missing locally
* vault-only
* conflicts / divergent versions

**FR-DRIFT-2**: Provide `lock --check` / `status --fail-if-dirty` for CI and hooks.

---

## 9. CLI Commands and Behavior

### 9.1 Command Set

The CLI MUST implement at least:

* `init`
* `lock [path…]`
* `unlock [path…]`
* `status` (alias `ls`)
* `diff`
* `rm [path…]`
* `passwd`
* `keyring save|status|delete|list|purge`
* `verify`
* `clean`
* `doctor`
* `compat check`
* `harden`

### 9.2 `init`

**FR-INIT-1**: Create vault + index if not present.
**FR-INIT-2**: Prompt for password (confirm) unless provided via stdin or env.
**FR-INIT-3**: Generate vault UUID and store in encrypted manifest; store UUID + minimal info in index.
**FR-INIT-4**: Offer to save to keyring (opt-in).
**FR-INIT-5**: Option `--vault <path>` and `--index <path>`.

### 9.3 `lock [path…]`

**FR-LOCK-1**: Encrypt selected files into vault and update encrypted manifest.
**FR-LOCK-2**: If no args: lock all tracked entries.
**FR-LOCK-3**: Accept patterns; on Windows, support globbing consistently (either internal globbing or documented shell behavior).
**FR-LOCK-4**: `--remove` deletes plaintext after successful lock.
**FR-LOCK-5**: `--check` verifies no tracked files differ from vault; exits non-zero on drift (no changes made).
**FR-LOCK-6**: Vault rewrite MUST be atomic.

### 9.4 `unlock [path…]`

**FR-UNLOCK-1**: Decrypt selected entries into working directory; if none specified, unlock all tracked.
**FR-UNLOCK-2**: Conflict detection if local exists and differs.

**FR-UNLOCK-3**: Interactive conflict resolution options:

* keep local
* overwrite with vault
* keep both (`<name>.from-vault`)
* skip
* merge in `$EDITOR` for text files (conflict markers)

**FR-UNLOCK-4**: Non-interactive flags:

* `--force` (overwrite)
* `--keep-local`
* `--keep-both`
* `--no-prompt` (fail if conflict)

**FR-UNLOCK-5**: Unlock writes MUST be atomic per file.

### 9.5 `status` / `ls`

**FR-STATUS-1**: Must work without password (max safety UX) using index + local file hashing policy:

* It MUST at minimum show whether tracked files are present locally and whether they have changed since last known lock/unlock operation recorded in local state file.
* If password available, it SHOULD optionally verify against vault hashes (enhanced mode).

**FR-STATUS-2**: Provide `--json` output.

> Implementation note: To avoid revealing filenames without password, `status` without password can still show counts and “dirty” state. When password exists, it can show per-file details.

### 9.6 `diff`

**FR-DIFF-1**: Requires password.
**FR-DIFF-2**: Text diff for text-like files; binary summary for others.
**FR-DIFF-3**: Support `--tool` and respect standard env vars (`GIT_DIFF_TOOL`, `$PAGER`).
**FR-DIFF-4**: Provide `--json` summary mode.

### 9.7 `rm [path…]`

**FR-RM-1**: Remove entries from vault and manifest; patterns supported.
**FR-RM-2**: `--remove-local` to delete plaintext (otherwise do not touch local).
**FR-RM-3**: Must be atomic.

### 9.8 `passwd`

**FR-PASSWD-1**: Re-encrypt vault contents with new password safely (atomic).
**FR-PASSWD-2**: Keyring handling:

* detect stale password
* prompt for refresh
* optionally update saved password
  **FR-PASSWD-3**: Provide `--rotate` mode that outputs a rotation checklist for teams.

### 9.9 `keyring …`

**FR-KR-1**: `save` stores password in OS keyring scoped by:

* tool namespace
* vault UUID
* optional repo remote fingerprint (configurable)

**FR-KR-2**: `status` indicates availability and lock state.
**FR-KR-3**: `delete` removes entry for current vault.
**FR-KR-4**: `list` lists tool-managed entries (no secrets).
**FR-KR-5**: `purge` removes stale entries (missing vault file / invalid).
**FR-KR-6**: Support flags:

* `--no-keyring`
* `--require-keyring`
* optional `--keyring-ttl` (app-level TTL)

### 9.10 `verify`

**FR-VERIFY-1**: Validate vault integrity:

* can decrypt manifest
* verify entry hashes
* detect corruption
  **FR-VERIFY-2**: Provide `--json`.

### 9.11 `clean`

**FR-CLEAN-1**: Remove unlocked plaintext tracked files (with confirmation).
**FR-CLEAN-2**: `--force` for CI.
**FR-CLEAN-3**: Never deletes untracked files.

### 9.12 `doctor`

**FR-DOCTOR-1**: Diagnose environment:

* keyring availability
* filesystem permissions
* vault/index validity
* unzip compatibility expectations
* recommended remediation steps

### 9.13 `compat check`

(See FR-VLT-4)

### 9.14 `harden`

(See FR-GIT-1)

---

## 10. Configuration

### 10.1 Config File

**FR-CFG-1**: Support repo-level config file (e.g., `.safezipvault.toml`) with:

* vault path
* index path
* tracked include patterns
* ignore patterns (never lock)
* conflict policy default
* diff tool
* password policy settings
* keyring namespace options
* status privacy mode (“summary-only without password” default)

### 10.2 Local State File

**FR-STATE-1**: Maintain a local-only state file (gitignored) to support passwordless `status` without leaking paths:

* store per-file fingerprints keyed by a stable opaque ID (not plaintext paths)
* store last lock timestamp
* never store secrets

---

## 11. Output, Automation, and UX

### 11.1 Machine-readable Output

**FR-OUT-1**: All query commands (`status`, `verify`, `doctor`, `compat`) MUST support `--json`.

### 11.2 Logging Safety

**SEC-LOG-1**: Default output MUST avoid printing secret contents.
**SEC-LOG-2**: Command output MUST never print passwords.
**SEC-LOG-3**: Provide `--quiet` and `--verbose`.

### 11.3 Shell UX

**NFR-UX-1**: Provide shell completions for bash/zsh/fish and PowerShell.
**NFR-UX-2**: Respect `$PAGER`, `$EDITOR`.

---

## 12. CI / Automation Requirements

**FR-CI-1**: Provide `--password-stdin` suitable for CI secret injection.
**FR-CI-2**: Provide `status --fail-if-dirty` and `lock --check`.
**FR-CI-3**: Provide a minimal example for GitHub Actions/GitLab CI in documentation.

---

## 13. Error Handling and Exit Codes

| Code | Symbol         | Meaning                           |
| ---: | -------------- | --------------------------------- |
|    0 | OK             | Success                           |
|    2 | E_USAGE        | Invalid args                      |
|   10 | E_NO_VAULT     | Vault missing                     |
|   11 | E_BAD_PASSWORD | Password invalid                  |
|   12 | E_KEYRING      | Keyring error/unavailable         |
|   13 | E_CONFLICT     | Conflicts unresolved              |
|   14 | E_IO           | I/O failure                       |
|   15 | E_CORRUPT      | Vault corrupt / manifest mismatch |
|   16 | E_UNSUPPORTED  | Unsupported format/encryption     |

**FR-ERR-1**: Error messages MUST include actionable remediation hints.

---

## 14. Testing Requirements

**TEST-1**: Cross-platform CI matrix for macOS/Linux/Windows.
**TEST-2**: Golden-path tests: init/lock/unlock/rm/passwd.
**TEST-3**: Corruption tests: truncated vault, bad password, wrong index.
**TEST-4**: Security tests: zip-slip paths, symlink handling, permissions.
**TEST-5**: Determinism tests: repeated lock yields stable archive ordering (within allowed entropy constraints).
**TEST-6**: Keyring tests: save/retrieve/delete/list/purge + stale detection.

---

## 15. Release, Supply Chain, and Compliance

**NFR-REL-1**: Provide signed release artifacts and checksums.
**NFR-REL-2**: Provide SBOM (recommended).
**NFR-REL-3**: Document reproducible build steps where feasible.

---

## 16. Documentation Deliverables

* README:

  * Quickstart (init → lock → commit → unlock)
  * Hardening (`harden`) and recommended hooks
  * Keyring setup & troubleshooting
  * CI examples using `--password-stdin`
  * Threat model and explicit limitations
  * Metadata disclosure statement (“filenames not visible without password by default; visible after decrypt/unzip”)
* Format Spec:

  * vault encryption profile
  * manifest schema + versioning rules
  * index schema
  * upgrade policy

---

## 17. Design Decisions Locked In

1. **Max safety defaults**: encrypted manifest; no filenames/paths revealed without password.
2. **Unzip always works**: vault is encrypted ZIP compatible with common unzip tools; compatibility documented and checkable.
3. **Keyring mandatory**: macOS/Linux/Windows keyring support required and tested.
4. **Strong guardrails**: `harden`, drift checks, safe extraction policies, atomic operations, JSON outputs.

---

If you want, I can also produce:

* a full `--help` CLI reference for every command,
* the TOML config schema + JSON schema for manifest/index,
* and a “pre-commit / pre-push hook bundle” that matches these safety defaults.
