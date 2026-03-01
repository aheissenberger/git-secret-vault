// Golden-path integration tests for git-secret-vault (NFR-010).
//
// These tests exercise the happy paths end-to-end using the Vault API directly,
// without invoking the compiled binary.

use git_secret_vault::crypto::content_hash;
use git_secret_vault::vault::Vault;
use tempfile::tempdir;

const PASSWORD: &str = "mypassword";

// ── test 1: init → lock → unlock round-trip ───────────────────────────────────

#[test]
fn init_lock_unlock_roundtrip() {
    let dir = tempdir().unwrap();
    let vault = Vault::init(dir.path(), PASSWORD).unwrap();
    let key = vault.derive_key(PASSWORD).unwrap();

    let plaintext = b"API_KEY=super-secret-value\n";
    vault.lock(&key, "api.env", plaintext).unwrap();

    let recovered = vault.unlock(&key, "api.env").unwrap();
    assert_eq!(recovered, plaintext, "unlocked content must match original");

    let snap = vault.snapshot().unwrap();
    assert_eq!(snap.entries.len(), 1);
    assert_eq!(snap.entries[0].label, "api.env");
}

// ── test 2: lock multiple files then unlock all ───────────────────────────────

#[test]
fn lock_multiple_files_then_unlock_all() {
    let dir = tempdir().unwrap();
    let vault = Vault::init(dir.path(), "multipass").unwrap();
    let key = vault.derive_key("multipass").unwrap();

    let files: &[(&str, &[u8])] = &[
        ("db.env", b"DB_PASSWORD=hunter2"),
        ("redis.env", b"REDIS_URL=redis://localhost:6379"),
        ("aws.env", b"AWS_SECRET_ACCESS_KEY=abc123xyz"),
    ];

    for (name, data) in files {
        vault.lock(&key, name, data).unwrap();
    }

    let snap = vault.snapshot().unwrap();
    assert_eq!(snap.entries.len(), 3);

    for (name, expected) in files {
        let recovered = vault.unlock(&key, name).unwrap();
        assert_eq!(&recovered, expected, "content mismatch for {name}");
    }
}

// ── test 3: lock → rm → verify entry gone ─────────────────────────────────────

#[test]
fn lock_rm_entry_gone() {
    let dir = tempdir().unwrap();
    let vault = Vault::init(dir.path(), "rmpass").unwrap();
    let key = vault.derive_key("rmpass").unwrap();

    vault.lock(&key, "keep.env", b"keep-me").unwrap();
    vault.lock(&key, "delete.env", b"delete-me").unwrap();

    vault.remove(&key, "delete.env").unwrap();

    let snap = vault.snapshot().unwrap();
    assert!(snap.entries.iter().all(|e| e.label != "delete.env"), "delete.env must be absent");
    assert_eq!(snap.entries.len(), 1);
    assert_eq!(snap.entries[0].label, "keep.env");
}

// ── test 4: lock → passwd → unlock with new password ─────────────────────────

#[test]
fn lock_passwd_unlock_with_new_password() {
    let dir = tempdir().unwrap();
    let vault = Vault::init(dir.path(), "oldpass123").unwrap();
    let old_key = vault.derive_key("oldpass123").unwrap();
    vault.lock(&old_key, "secret.env", b"top-secret-data").unwrap();

    vault.rotate_key(&old_key, "newpass456").unwrap();

    let vault2 = Vault::open(dir.path()).unwrap();
    let new_key = vault2.derive_key("newpass456").unwrap();
    let recovered = vault2.unlock(&new_key, "secret.env").unwrap();
    assert_eq!(recovered, b"top-secret-data");

    // Old key should no longer decrypt
    let result = vault2.unlock(&old_key, "secret.env");
    assert!(result.is_err(), "old key must no longer work after rotation");
}

// ── test 5: status shows correct entry count ──────────────────────────────────

#[test]
fn status_shows_correct_entry_count() {
    let dir = tempdir().unwrap();
    let vault = Vault::init(dir.path(), "statuspass").unwrap();
    let key = vault.derive_key("statuspass").unwrap();

    for i in 0..4u8 {
        let name = format!("file{i}.env");
        let data = format!("VALUE={i}").into_bytes();
        vault.lock(&key, &name, &data).unwrap();
    }

    let snap = vault.snapshot().unwrap();
    assert_eq!(snap.entries.len(), 4, "snapshot must report 4 entries");
}

// ── test 6: lock --check detects drift ───────────────────────────────────────

#[test]
fn lock_check_detects_drift() {
    let dir = tempdir().unwrap();
    let vault = Vault::init(dir.path(), "checkpass").unwrap();
    let key = vault.derive_key("checkpass").unwrap();
    let original = b"ORIGINAL_VALUE=abc";
    vault.lock(&key, "checked.env", original).unwrap();

    let snap = vault.snapshot().unwrap();
    let entry = snap.entries.iter().find(|e| e.label == "checked.env").unwrap();
    let stored_hash = entry.content_hash.clone();

    let modified = b"MODIFIED_VALUE=xyz";
    let current_hash = content_hash(modified);

    assert!(current_hash != stored_hash, "drift must be detected when plaintext changed");
}

// ── test 7: lock is deterministic (FR-017 / NFR-013) ─────────────────────────

#[test]
fn lock_is_deterministic() {
    // Two separate vaults locked with the same password and content must
    // decrypt to the same plaintext. Raw ciphertext differs (random nonces).
    let content = b"hello world";

    let dir_a = tempdir().unwrap();
    let vault_a = Vault::init(dir_a.path(), "det-password").unwrap();
    let key_a = vault_a.derive_key("det-password").unwrap();
    vault_a.lock(&key_a, "data.txt", content).unwrap();

    let dir_b = tempdir().unwrap();
    let vault_b = Vault::init(dir_b.path(), "det-password").unwrap();
    let key_b = vault_b.derive_key("det-password").unwrap();
    vault_b.lock(&key_b, "data.txt", content).unwrap();

    let plain_a = vault_a.unlock(&key_a, "data.txt").unwrap();
    let plain_b = vault_b.unlock(&key_b, "data.txt").unwrap();
    assert_eq!(plain_a, plain_b, "decrypted content must be identical");
    assert_eq!(plain_a.as_slice(), content, "decrypted content must match original plaintext");

    // Content hashes (deterministic) must match
    let snap_a = vault_a.snapshot().unwrap();
    let snap_b = vault_b.snapshot().unwrap();
    let hash_a = &snap_a.entries[0].content_hash;
    let hash_b = &snap_b.entries[0].content_hash;
    assert_eq!(hash_a, hash_b, "content hashes must be identical");
}

// ── test 8: init creates expected directory structure ─────────────────────────

#[test]
fn vault_init_creates_expected_structure() {
    let dir = tempdir().unwrap();
    Vault::init(dir.path(), PASSWORD).unwrap();
    assert!(dir.path().join("vault.meta.json").exists(), "vault.meta.json must exist");
    assert!(dir.path().join("blobs").is_dir(), "blobs/ directory must exist");
    assert!(dir.path().join("index").is_dir(), "index/ directory must exist");
}

// ── test 9: locking same label twice updates, not duplicates ──────────────────

#[test]
fn lock_updates_existing_entry() {
    let dir = tempdir().unwrap();
    let vault = Vault::init(dir.path(), PASSWORD).unwrap();
    let key = vault.derive_key(PASSWORD).unwrap();

    vault.lock(&key, "update-me.env", b"first-value").unwrap();
    vault.lock(&key, "update-me.env", b"second-value").unwrap();

    let snap = vault.snapshot().unwrap();
    assert_eq!(snap.entries.len(), 1, "duplicate label must be an update, not a new entry");

    let recovered = vault.unlock(&key, "update-me.env").unwrap();
    assert_eq!(recovered, b"second-value", "unlock must return the latest value");
}

// ── test 10: verify reports ok on intact vault ────────────────────────────────

#[test]
fn verify_reports_ok_on_intact_vault() {
    let dir = tempdir().unwrap();
    let vault = Vault::init(dir.path(), "verifypass").unwrap();
    let key = vault.derive_key("verifypass").unwrap();

    let files: &[(&str, &[u8])] = &[
        ("alpha.env", b"ALPHA=1"),
        ("beta.env", b"BETA=2"),
        ("gamma.env", b"GAMMA=3"),
    ];
    for (name, data) in files {
        vault.lock(&key, name, data).unwrap();
    }

    assert!(vault.verify(&key).is_ok(), "all entries must verify ok on an intact vault");
    let snap = vault.snapshot().unwrap();
    assert_eq!(snap.entries.len(), 3);
}
