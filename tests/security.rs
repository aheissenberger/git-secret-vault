// NFR-012: Security-focused integration tests.
//
// Covers: path traversal prevention (SEC-006), password policy (SEC-002).

use git_secret_vault::crypto;
use git_secret_vault::error::VaultError;
use git_secret_vault::fs::safe_join;
use git_secret_vault::vault::Vault;
use tempfile::tempdir;

const PASSWORD: &str = "correct-horse-battery-staple-42!";

// ── helpers ─────────────────────────────────────────────────────────────────

fn make_vault(dir: &std::path::Path) -> Vault {
    Vault::init(dir, PASSWORD).unwrap()
}

// ── 1. safe_join blocks path traversal ───────────────────────────────────────

#[test]
fn safe_join_blocks_parent_traversal() {
    let dir = tempdir().unwrap();
    let result = safe_join(dir.path(), "../etc/passwd");
    assert!(
        matches!(result.unwrap_err(), VaultError::PathTraversal(_)),
        "expected PathTraversal error"
    );
}

#[test]
fn safe_join_blocks_absolute_path() {
    let dir = tempdir().unwrap();
    let result = safe_join(dir.path(), "/etc/passwd");
    assert!(
        matches!(result.unwrap_err(), VaultError::PathTraversal(_)),
        "expected PathTraversal error for absolute path"
    );
}

#[test]
fn safe_join_allows_normal_relative_paths() {
    let dir = tempdir().unwrap();
    let result = safe_join(dir.path(), "subdir/file.txt");
    assert!(result.is_ok(), "expected Ok for safe relative path");
    assert!(result.unwrap().starts_with(dir.path()));
}

// ── 2. password policy enforcement ───────────────────────────────────────────

#[test]
fn short_password_fails_validation() {
    // Passwords shorter than 8 characters should fail.
    let result = crypto::validate_password_strength("short");
    assert!(result.is_err(), "expected error for short password");
}

#[test]
fn empty_password_fails_validation() {
    let result = crypto::validate_password_strength("");
    assert!(result.is_err(), "expected error for empty password");
}

#[test]
fn strong_password_passes_validation() {
    let result = crypto::validate_password_strength("correct-horse-battery-staple-42!");
    assert!(result.is_ok(), "expected Ok for strong password");
}

#[test]
fn vault_init_rejects_weak_password() {
    let dir = tempdir().unwrap();
    let vault_dir = dir.path().join("vault");
    let result = Vault::init(&vault_dir, "weak");
    assert!(result.is_err(), "expected error for weak password at init");
}

// ── 3. lock and unlock round-trip ─────────────────────────────────────────────

#[test]
fn lock_unlock_round_trip() {
    let dir = tempdir().unwrap();
    let vault_dir = dir.path().join("vault");
    let vault = make_vault(&vault_dir);

    let key = vault.derive_key(PASSWORD).unwrap();
    let plaintext = b"DB_PASSWORD=super-secret-value";
    vault.lock(&key, ".env", plaintext).unwrap();

    let recovered = vault.unlock(&key, ".env").unwrap();
    assert_eq!(recovered, plaintext);
}

// ── 4. key rotation re-encrypts all blobs ────────────────────────────────────

#[test]
fn rotate_key_re_encrypts() {
    let dir = tempdir().unwrap();
    let vault_dir = dir.path().join("vault");
    let vault = make_vault(&vault_dir);

    let old_key = vault.derive_key(PASSWORD).unwrap();
    vault.lock(&old_key, ".env", b"rotate-me-please").unwrap();

    let new_key = [77u8; 32];
    vault.rotate_key(&old_key, &new_key, "new-key-2").unwrap();

    // Old key should no longer work.
    let result = vault.unlock(&old_key, ".env");
    assert!(result.is_err(), "old key should not decrypt after rotation");

    // New key should work.
    let data = vault.unlock(&new_key, ".env").unwrap();
    assert_eq!(data, b"rotate-me-please");
}

// ── 5. remove entry removes from snapshot ─────────────────────────────────────

#[test]
fn remove_entry_drops_from_snapshot() {
    let dir = tempdir().unwrap();
    let vault_dir = dir.path().join("vault");
    let vault = make_vault(&vault_dir);

    let key = vault.derive_key(PASSWORD).unwrap();
    vault.lock(&key, ".env", b"secret").unwrap();
    vault.lock(&key, "config.toml", b"config").unwrap();

    vault.remove(&key, ".env").unwrap();

    let snap = vault.snapshot().unwrap();
    assert_eq!(snap.entries.len(), 1);
    assert_eq!(snap.entries[0].label, "config.toml");
}

// ── 6. wrong key causes decryption failure ────────────────────────────────────

#[test]
fn wrong_key_fails_decryption() {
    let dir = tempdir().unwrap();
    let vault_dir = dir.path().join("vault");
    let vault = make_vault(&vault_dir);

    let key = vault.derive_key(PASSWORD).unwrap();
    vault.lock(&key, ".env", b"sensitive").unwrap();

    let wrong_key = [0u8; 32];
    let result = vault.unlock(&wrong_key, ".env");
    assert!(result.is_err(), "expected decryption failure with wrong key");
}
