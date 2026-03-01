// Integration tests for corruption and error paths (NFR-011).

use git_secret_vault::error::VaultError;
use git_secret_vault::vault::Vault;
use tempfile::tempdir;

const PASSWORD: &str = "correct-horse-battery-staple-42!";
const WRONG_PASSWORD: &str = "wrong-password-xyz-but-long-enough!!";

// ── helpers ──────────────────────────────────────────────────────────────────

fn make_vault(dir: &std::path::Path) -> Vault {
    Vault::init(dir, PASSWORD).unwrap()
}

// ── test 1: wrong password causes decryption failure ─────────────────────

#[test]
fn wrong_password_causes_decrypt_failure() {
    let dir = tempdir().unwrap();
    let vault_dir = dir.path().join("vault");
    let vault = make_vault(&vault_dir);

    let good_key = vault.derive_key(PASSWORD).unwrap();
    vault.lock(&good_key, ".env", b"secret-data").unwrap();

    // Derive key with wrong password — derive_key itself succeeds (KDF),
    // but decryption of the blob will fail.
    let bad_key = vault.derive_key(WRONG_PASSWORD).unwrap();
    let result = vault.unlock(&bad_key, ".env");
    assert!(
        result.is_err(),
        "expected error when unlocking with wrong password"
    );
}

// ── test 2: missing vault directory ──────────────────────────────────────

#[test]
fn missing_vault_directory_returns_not_found() {
    let dir = tempdir().unwrap();
    let vault_dir = dir.path().join("nonexistent");

    let result = Vault::open(&vault_dir);
    assert!(
        result.is_err(),
        "expected error when vault directory does not exist"
    );
    assert!(matches!(result.err().unwrap(), VaultError::VaultNotFound(_)));
}

// ── test 3: init twice returns VaultExists ────────────────────────────────

#[test]
fn init_twice_returns_vault_exists() {
    let dir = tempdir().unwrap();
    let vault_dir = dir.path().join("vault");
    Vault::init(&vault_dir, PASSWORD).unwrap();

    let result = Vault::init(&vault_dir, PASSWORD);
    assert!(
        result.is_err(),
        "expected error when initialising vault that already exists"
    );
    assert!(matches!(result.err().unwrap(), VaultError::VaultExists(_)));
}

// ── test 4: corrupted blob file returns error ──────────────────────────────

#[test]
fn corrupted_blob_returns_error() {
    let dir = tempdir().unwrap();
    let vault_dir = dir.path().join("vault");
    let vault = make_vault(&vault_dir);

    let key = vault.derive_key(PASSWORD).unwrap();
    vault.lock(&key, ".env", b"secret-data").unwrap();

    let snap = vault.snapshot().unwrap();
    let entry = &snap.entries[0];
    let blob_path = vault_dir.join("blobs").join(format!("{}.enc", entry.content_hash));

    // Corrupt the blob file.
    std::fs::write(&blob_path, b"corrupted!").unwrap();

    let result = vault.unlock(&key, ".env");
    assert!(
        result.is_err(),
        "expected error when blob is corrupted"
    );
}

// ── test 5: unlock non-existent entry returns error ───────────────────────

#[test]
fn unlock_nonexistent_entry_returns_error() {
    let dir = tempdir().unwrap();
    let vault_dir = dir.path().join("vault");
    let vault = make_vault(&vault_dir);

    let key = vault.derive_key(PASSWORD).unwrap();
    let result = vault.unlock(&key, "does-not-exist");
    assert!(
        result.is_err(),
        "expected error when entry does not exist"
    );
}

// ── test 6: remove non-existent entry returns error ───────────────────────

#[test]
fn remove_nonexistent_entry_returns_error() {
    let dir = tempdir().unwrap();
    let vault_dir = dir.path().join("vault");
    let vault = make_vault(&vault_dir);

    let key = vault.derive_key(PASSWORD).unwrap();
    let result = vault.remove(&key, "does-not-exist");
    assert!(
        result.is_err(),
        "expected error when removing non-existent entry"
    );
}

// ── test 7: truncated blob file returns error ──────────────────────────────

#[test]
fn truncated_blob_returns_error() {
    let dir = tempdir().unwrap();
    let vault_dir = dir.path().join("vault");
    let vault = make_vault(&vault_dir);

    let key = vault.derive_key(PASSWORD).unwrap();
    vault.lock(&key, "secrets.txt", b"some very important secret").unwrap();

    let snap = vault.snapshot().unwrap();
    let entry = &snap.entries[0];
    let blob_path = vault_dir.join("blobs").join(format!("{}.enc", entry.content_hash));

    // Truncate to 5 bytes.
    std::fs::write(&blob_path, b"trunc").unwrap();

    let result = vault.unlock(&key, "secrets.txt");
    assert!(result.is_err(), "expected error for truncated blob");
}

// ── test 8: verify catches hash mismatch ──────────────────────────────────

#[test]
fn verify_detects_corrupted_blob() {
    let dir = tempdir().unwrap();
    let vault_dir = dir.path().join("vault");
    let vault = make_vault(&vault_dir);

    let key = vault.derive_key(PASSWORD).unwrap();
    vault.lock(&key, ".env", b"original-data").unwrap();

    let snap = vault.snapshot().unwrap();
    let entry = &snap.entries[0];
    let blob_path = vault_dir.join("blobs").join(format!("{}.enc", entry.content_hash));

    // Overwrite blob with different encrypted data for a different plaintext.
    // This will either fail decryption (AEAD tag mismatch) or produce wrong hash.
    let corrupt_data = vec![0xAAu8; 64];
    std::fs::write(&blob_path, &corrupt_data).unwrap();

    let result = vault.verify(&key);
    assert!(result.is_err(), "expected verify to fail with corrupted blob");
}
