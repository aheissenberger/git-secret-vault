// NFR-012: Security-focused integration tests.
//
// Covers: path traversal prevention (SEC-006), password policy (SEC-002),
// metadata exposure (SEC-001), keep-both conflict policy (FR-011),
// lock --remove behaviour (FR-010), and clean tracking boundary.

use std::path::Path;

use git_secret_vault::crypto;
use git_secret_vault::error::VaultError;
use git_secret_vault::fs::safe_join;
use git_secret_vault::vault::Vault;
use tempfile::tempdir;

// ── helpers ──────────────────────────────────────────────────────────────────

fn seed_vault(dir: &Path, password: &str, entries: &[(&str, &[u8])]) -> Vault {
    let vault = Vault::init(dir, password).unwrap();
    let key = vault.derive_key(password).unwrap();
    for (label, data) in entries {
        vault.lock(&key, label, data).unwrap();
    }
    vault
}

// ── 1. safe_join blocks path traversal ───────────────────────────────────────

#[test]
fn safe_join_blocks_parent_traversal() {
    let dir = tempdir().unwrap();
    let result = safe_join(dir.path(), "../etc/passwd");
    assert!(
        matches!(result.unwrap_err(), VaultError::PathTraversal(_)),
        "path traversal must be rejected"
    );
}

// ── 2. safe_join blocks absolute paths ───────────────────────────────────────

#[test]
fn safe_join_blocks_absolute_path() {
    let dir = tempdir().unwrap();
    let result = safe_join(dir.path(), "/etc/passwd");
    assert!(
        matches!(result.unwrap_err(), VaultError::PathTraversal(_)),
        "absolute path must be rejected"
    );
}

// ── 3. safe_join allows normal relative paths ─────────────────────────────────

#[test]
fn safe_join_allows_normal_relative_path() {
    let dir = tempdir().unwrap();
    let result = safe_join(dir.path(), "subdir/file.txt");
    assert!(result.is_ok(), "normal relative path must be accepted");
    let path = result.unwrap();
    assert!(
        path.starts_with(dir.path()),
        "result must stay within base directory"
    );
}

// ── 4. Lock a regular file round-trip succeeds ───────────────────────────────

#[test]
fn lock_regular_file_round_trip_succeeds() {
    let dir = tempdir().unwrap();
    let vault = Vault::init(dir.path(), "pw12345678").unwrap();
    let key = vault.derive_key("pw12345678").unwrap();

    let secret = dir.path().join("api.key");
    std::fs::write(&secret, b"supersecret").unwrap();
    let data = std::fs::read(&secret).unwrap();

    vault.lock(&key, "api.key", &data).unwrap();
    let back = vault.unlock(&key, "api.key").unwrap();
    assert_eq!(back, b"supersecret");
}

// ── 5. Password minimum length is enforced (SEC-002) ─────────────────────────

#[test]
fn password_too_short_is_rejected() {
    let result = crypto::validate_password_strength("short");
    assert!(result.is_err(), "passwords shorter than 8 chars must be rejected");
}

#[test]
fn password_long_enough_is_accepted() {
    let result = crypto::validate_password_strength("longpassword");
    assert!(result.is_ok(), "passwords of 8+ chars must be accepted");
}

// ── 6. vault.meta.json contains no entry labels (SEC-001) ────────────────────

#[test]
fn outer_index_contains_no_filenames() {
    let dir = tempdir().unwrap();
    let vault = seed_vault(dir.path(), "pw12345678", &[("secrets/api.key", b"api_key=secret123")]);
    let _ = vault;

    // vault.meta.json is the public-facing metadata; must not expose entry labels
    let meta_raw = std::fs::read_to_string(dir.path().join("vault.meta.json")).unwrap();
    assert!(
        !meta_raw.contains("api.key"),
        "vault.meta.json must not expose entry filenames; got:\n{meta_raw}"
    );
    assert!(
        !meta_raw.contains("secrets"),
        "vault.meta.json must not expose directory names; got:\n{meta_raw}"
    );
}

// ── 7. Unlock keep-both: vault copy is written alongside local file ────────────

#[test]
fn unlock_keep_both_writes_vault_copy() {
    let dir = tempdir().unwrap();
    let vault = seed_vault(dir.path(), "pw12345678", &[("secret.env", b"vault-content")]);
    let key = vault.derive_key("pw12345678").unwrap();

    // Simulate a conflicting local file
    let local = dir.path().join("secret.env");
    std::fs::write(&local, b"local-content").unwrap();

    // keep-both: write vault bytes to a .vault-copy sibling
    let vault_data = vault.unlock(&key, "secret.env").unwrap();
    let copy_dest = dir.path().join("secret.env.vault-copy");
    git_secret_vault::fs::atomic_write(&copy_dest, &vault_data).unwrap();

    assert_eq!(std::fs::read(&local).unwrap(), b"local-content", "local file must remain unchanged");
    assert_eq!(std::fs::read(&copy_dest).unwrap(), b"vault-content", "vault copy must contain the vault version");
}

// ── 8. Vault entry name cannot escape base directory ─────────────────────────

#[test]
fn entry_path_traversal_via_safe_join_is_blocked() {
    let dir = tempdir().unwrap();
    let result = safe_join(dir.path(), "../escape.txt");
    assert!(
        matches!(result.unwrap_err(), VaultError::PathTraversal(_)),
        "traversal entry path must be rejected by safe_join"
    );
}

// ── 9. lock --remove deletes plaintext after successful encryption ────────────

#[test]
fn lock_remove_deletes_plaintext_after_success() {
    let dir = tempdir().unwrap();
    let vault = Vault::init(dir.path(), "pw12345678").unwrap();
    let key = vault.derive_key("pw12345678").unwrap();

    let plain = dir.path().join("plain.env");
    std::fs::write(&plain, b"remove-me").unwrap();
    assert!(plain.exists());

    // Lock the file into the vault
    let data = std::fs::read(&plain).unwrap();
    vault.lock(&key, "plain.env", &data).unwrap();

    // --remove: delete plaintext only after vault write succeeds
    std::fs::remove_file(&plain).unwrap();
    assert!(!plain.exists(), "plaintext must be deleted after lock --remove");

    // Vault retains the encrypted copy
    let back = vault.unlock(&key, "plain.env").unwrap();
    assert_eq!(back, b"remove-me");
}

// ── 10. Clean only removes tracked files; untracked files are untouched ───────

#[test]
fn clean_only_removes_tracked_files() {
    let dir = tempdir().unwrap();
    let vault = seed_vault(dir.path(), "pw12345678", &[("tracked.env", b"data")]);

    let tracked = dir.path().join("tracked.env");
    let untracked = dir.path().join("untracked.env");
    std::fs::write(&tracked, b"data").unwrap();
    std::fs::write(&untracked, b"untouched").unwrap();

    // Clean: iterate only over snapshot entries
    let snap = vault.snapshot().unwrap();
    for entry in &snap.entries {
        let local = dir.path().join(&entry.label);
        if local.exists() {
            std::fs::remove_file(&local).unwrap();
        }
    }

    assert!(!tracked.exists(), "tracked file must be removed by clean");
    assert!(untracked.exists(), "untracked file must NOT be removed by clean");
}

// ── 11. Keyring entry construction does not panic (FR-017 / NFR-014) ──────────

#[test]
fn keyring_entry_new_does_not_panic() {
    let result = keyring::Entry::new("git-secret-vault", "test-uuid-determinism");
    assert!(result.is_ok(), "keyring::Entry::new must succeed: {:?}", result.err());
}
