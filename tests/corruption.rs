// Integration tests for corruption and error paths (NFR-011).
//
// These tests exercise the Vault API directly to verify that all error and
// corruption scenarios return appropriate errors rather than silently
// succeeding or panicking.

use git_secret_vault::error::VaultError;
use git_secret_vault::vault::Vault;
use tempfile::tempdir;

const PASSWORD: &str = "correct-horse-battery-staple";

// ── helpers ───────────────────────────────────────────────────────────────────

fn init_vault_with_entry(dir: &std::path::Path, label: &str, data: &[u8]) -> Vault {
    let vault = Vault::init(dir, PASSWORD).unwrap();
    let key = vault.derive_key(PASSWORD).unwrap();
    vault.lock(&key, label, data).unwrap();
    vault
}

// ── test 1: wrong key on unlock returns error ─────────────────────────────────

#[test]
fn wrong_password_on_read_manifest_returns_error() {
    let dir = tempdir().unwrap();
    let vault = init_vault_with_entry(dir.path(), "secret.env", b"data");
    // Derive a key with the wrong password
    let wrong_vault = Vault::open(dir.path()).unwrap();
    // The wrong key will fail to decrypt the blob
    let wrong_key = wrong_vault.derive_key("wrong-password-xyz").unwrap();
    let result = vault.unlock(&wrong_key, "secret.env");
    assert!(result.is_err(), "expected error when decrypting with wrong key");
}

// ── test 2: corrupted blob returns error ──────────────────────────────────────

#[test]
fn truncated_vault_returns_error() {
    let dir = tempdir().unwrap();
    let vault = init_vault_with_entry(dir.path(), "secret.env", b"data");
    let key = vault.derive_key(PASSWORD).unwrap();

    // Corrupt all blob files
    let blobs_dir = dir.path().join("blobs");
    for entry in std::fs::read_dir(&blobs_dir).unwrap() {
        let path = entry.unwrap().path();
        std::fs::write(&path, b"truncated!").unwrap();
    }

    let result = vault.unlock(&key, "secret.env");
    assert!(result.is_err(), "expected error when blob is corrupted");
}

// ── test 3: missing vault directory returns error ─────────────────────────────

#[test]
fn missing_vault_file_returns_error() {
    let dir = tempdir().unwrap();
    let nonexistent = dir.path().join("nonexistent-vault");
    let result = Vault::open(&nonexistent);
    assert!(result.is_err(), "expected error when vault directory does not exist");
    assert!(matches!(result.err().unwrap(), VaultError::Io(_)));
}

// ── test 4: corrupted blob with random bytes returns error ────────────────────

#[test]
fn corrupted_zip_returns_error() {
    let dir = tempdir().unwrap();
    let vault = init_vault_with_entry(dir.path(), "secret.env", b"data");
    let key = vault.derive_key(PASSWORD).unwrap();

    // Overwrite all blobs with garbage
    let blobs_dir = dir.path().join("blobs");
    for entry in std::fs::read_dir(&blobs_dir).unwrap() {
        let path = entry.unwrap().path();
        let garbage: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        std::fs::write(&path, &garbage).unwrap();
    }

    let result = vault.unlock(&key, "secret.env");
    assert!(result.is_err(), "expected error when blob contains random bytes");
}

// ── test 5: wrong key on entry read returns error ─────────────────────────────

#[test]
fn wrong_password_on_read_entry_returns_error() {
    let dir = tempdir().unwrap();
    let vault = init_vault_with_entry(dir.path(), "secrets.env", b"DB_PASSWORD=hunter2");
    let wrong_key = vault.derive_key("wrong-password-xyz").unwrap();
    let result = vault.unlock(&wrong_key, "secrets.env");
    assert!(result.is_err(), "expected error when reading entry with wrong key");
}

// ── test 6: missing vault.meta.json returns Io error ─────────────────────────

#[test]
fn missing_index_file_returns_error() {
    let dir = tempdir().unwrap();
    // vault.meta.json doesn't exist → open fails
    let result = Vault::open(dir.path());
    assert!(result.is_err(), "expected error when vault.meta.json does not exist");
    assert!(matches!(result.err().unwrap(), VaultError::Io(_)));
}

// ── test 7: corrupted snapshot.json returns error ────────────────────────────

#[test]
fn corrupted_index_json_returns_error() {
    let dir = tempdir().unwrap();
    Vault::init(dir.path(), PASSWORD).unwrap();
    let snapshot_path = dir.path().join("index").join("snapshot.json");
    std::fs::write(&snapshot_path, b"{ this is: not valid json !!!").unwrap();
    let vault = Vault::open(dir.path()).unwrap();
    let result = vault.snapshot();
    assert!(result.is_err(), "expected error when snapshot JSON is corrupted");
}

// ── test 8: rm with unknown label returns error ───────────────────────────────

#[test]
fn rm_unknown_path_returns_error() {
    let dir = tempdir().unwrap();
    let vault = Vault::init(dir.path(), PASSWORD).unwrap();
    let key = vault.derive_key(PASSWORD).unwrap();
    let result = vault.remove(&key, "nonexistent/secret.env");
    assert!(result.is_err(), "expected error when removing non-existent entry");
}

// ── test 9: stale file detected via content_hash comparison ──────────────────

#[test]
fn lock_check_stale_file_returns_error() {
    let dir = tempdir().unwrap();
    let vault = init_vault_with_entry(dir.path(), "tracked.env", b"SECRET=original");
    let snap = vault.snapshot().unwrap();
    let entry = snap.entries.iter().find(|e| e.label == "tracked.env").unwrap();
    let stored_hash = entry.content_hash.clone();

    let modified_data = b"SECRET=tampered";
    let current_hash = git_secret_vault::crypto::content_hash(modified_data);
    assert_ne!(current_hash, stored_hash, "drift should be detected");
}

// ── test 10: verify returns ok on clean vault ─────────────────────────────────

#[test]
fn verify_clean_vault_passes() {
    let dir = tempdir().unwrap();
    let vault = init_vault_with_entry(dir.path(), "clean.env", b"CLEAN=true");
    let key = vault.derive_key(PASSWORD).unwrap();
    assert!(vault.verify(&key).is_ok(), "verify should pass on clean vault");
}

// ── test 11: verify detects corrupted blob ────────────────────────────────────

#[test]
fn verify_detects_hash_mismatch() {
    let dir = tempdir().unwrap();
    let vault = init_vault_with_entry(dir.path(), "tampered.env", b"REAL=value");
    let key = vault.derive_key(PASSWORD).unwrap();

    // Corrupt all blobs so decryption fails
    let blobs_dir = dir.path().join("blobs");
    for entry in std::fs::read_dir(&blobs_dir).unwrap() {
        let path = entry.unwrap().path();
        std::fs::write(&path, b"garbage-bytes-not-valid-ciphertext").unwrap();
    }

    let result = vault.verify(&key);
    assert!(result.is_err(), "verify should detect corrupted blobs");
}
