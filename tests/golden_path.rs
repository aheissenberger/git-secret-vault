// Golden-path integration tests for git-secret-vault (NFR-010).
//
// These tests exercise the happy paths end-to-end using the library APIs
// directly, without invoking the compiled binary.

use git_secret_vault::vault::Vault;
use tempfile::tempdir;

const PASSWORD: &str = "correct-horse-battery-staple-42!";

// ── helpers ──────────────────────────────────────────────────────────────────

fn make_vault(dir: &std::path::Path) -> Vault {
    let vault_dir = dir.join("vault");
    Vault::init(&vault_dir, PASSWORD).unwrap()
}

// ── 1. Init creates the expected directory structure ──────────────────────────

#[test]
fn init_creates_directory_structure() {
    let dir = tempdir().unwrap();
    let vault_dir = dir.path().join("vault");
    Vault::init(&vault_dir, PASSWORD).unwrap();

    assert!(vault_dir.join("vault.meta.json").exists(), "meta file missing");
    assert!(vault_dir.join("blobs").is_dir(), "blobs dir missing");
    assert!(vault_dir.join("index").is_dir(), "index dir missing");
    assert!(vault_dir.join("index").join("snapshot.json").exists(), "snapshot missing");
}

// ── 2. Lock one entry and unlock it ──────────────────────────────────────────

#[test]
fn lock_and_unlock_single_entry() {
    let dir = tempdir().unwrap();
    let vault = make_vault(dir.path());
    let key = vault.derive_key(PASSWORD).unwrap();

    let plaintext = b"DATABASE_URL=postgres://localhost/mydb\nSECRET_KEY=abc123\n";
    vault.lock(&key, ".env", plaintext).unwrap();

    let recovered = vault.unlock(&key, ".env").unwrap();
    assert_eq!(recovered, plaintext);
}

// ── 3. Lock multiple entries and unlock each ──────────────────────────────────

#[test]
fn lock_and_unlock_multiple_entries() {
    let dir = tempdir().unwrap();
    let vault = make_vault(dir.path());
    let key = vault.derive_key(PASSWORD).unwrap();

    let entries = [
        (".env", b"SECRET=value1" as &[u8]),
        ("config/db.toml", b"password = \"secret\""),
        ("keys/api.key", b"sk-abc123def456"),
    ];

    for (label, data) in &entries {
        vault.lock(&key, label, data).unwrap();
    }

    for (label, expected) in &entries {
        let recovered = vault.unlock(&key, label).unwrap();
        assert_eq!(recovered, *expected, "mismatch for {label}");
    }
}

// ── 4. Snapshot reflects locked entries ──────────────────────────────────────

#[test]
fn snapshot_contains_locked_entries() {
    let dir = tempdir().unwrap();
    let vault = make_vault(dir.path());
    let key = vault.derive_key(PASSWORD).unwrap();

    vault.lock(&key, ".env", b"A=1").unwrap();
    vault.lock(&key, "secrets.toml", b"B=2").unwrap();

    let snap = vault.snapshot().unwrap();
    assert_eq!(snap.entries.len(), 2);

    let labels: Vec<&str> = snap.entries.iter().map(|e| e.label.as_str()).collect();
    assert!(labels.contains(&".env"), "snapshot missing .env");
    assert!(labels.contains(&"secrets.toml"), "snapshot missing secrets.toml");
}

// ── 5. Update (lock same label twice) replaces the entry ──────────────────────

#[test]
fn update_replaces_entry_in_snapshot() {
    let dir = tempdir().unwrap();
    let vault = make_vault(dir.path());
    let key = vault.derive_key(PASSWORD).unwrap();

    vault.lock(&key, ".env", b"version-1").unwrap();
    vault.lock(&key, ".env", b"version-2").unwrap();

    let snap = vault.snapshot().unwrap();
    assert_eq!(snap.entries.len(), 1, "expected exactly 1 entry after update");

    let recovered = vault.unlock(&key, ".env").unwrap();
    assert_eq!(recovered, b"version-2");
}

// ── 6. Remove entry drops it from snapshot ────────────────────────────────────

#[test]
fn remove_drops_entry_from_snapshot() {
    let dir = tempdir().unwrap();
    let vault = make_vault(dir.path());
    let key = vault.derive_key(PASSWORD).unwrap();

    vault.lock(&key, ".env", b"to-be-deleted").unwrap();
    vault.lock(&key, "keep.toml", b"keep-this").unwrap();

    vault.remove(&key, ".env").unwrap();

    let snap = vault.snapshot().unwrap();
    assert_eq!(snap.entries.len(), 1);
    assert_eq!(snap.entries[0].label, "keep.toml");
}

// ── 7. Verify passes for intact vault ─────────────────────────────────────────

#[test]
fn verify_passes_for_intact_vault() {
    let dir = tempdir().unwrap();
    let vault = make_vault(dir.path());
    let key = vault.derive_key(PASSWORD).unwrap();

    vault.lock(&key, ".env", b"check-integrity").unwrap();

    assert!(vault.verify(&key).is_ok(), "verify should pass for intact vault");
}

// ── 8. Key rotation re-encrypts and allows unlock with new key ──────────────────

#[test]
fn key_rotation_allows_unlock_with_new_key() {
    let dir = tempdir().unwrap();
    let vault = make_vault(dir.path());
    let old_key = vault.derive_key(PASSWORD).unwrap();

    vault.lock(&old_key, ".env", b"rotatable-secret").unwrap();
    vault.lock(&old_key, "config.toml", b"config-data").unwrap();

    let new_key = [55u8; 32];
    vault.rotate_key(&old_key, &new_key, "rotated-key-id").unwrap();

    let env_data = vault.unlock(&new_key, ".env").unwrap();
    assert_eq!(env_data, b"rotatable-secret");

    let config_data = vault.unlock(&new_key, "config.toml").unwrap();
    assert_eq!(config_data, b"config-data");
}

// ── 9. Open existing vault persists across init ───────────────────────────────

#[test]
fn open_existing_vault_reads_meta() {
    let dir = tempdir().unwrap();
    let vault_dir = dir.path().join("vault");
    {
        let vault = Vault::init(&vault_dir, PASSWORD).unwrap();
        let key = vault.derive_key(PASSWORD).unwrap();
        vault.lock(&key, ".env", b"persistent").unwrap();
    }

    // Re-open the vault.
    let vault2 = Vault::open(&vault_dir).unwrap();
    let key2 = vault2.derive_key(PASSWORD).unwrap();
    let recovered = vault2.unlock(&key2, ".env").unwrap();
    assert_eq!(recovered, b"persistent");
}

// ── 10. Store idempotent for same content ──────────────────────────────────────

#[test]
fn lock_same_content_twice_is_idempotent() {
    let dir = tempdir().unwrap();
    let vault = make_vault(dir.path());
    let key = vault.derive_key(PASSWORD).unwrap();

    vault.lock(&key, "a.txt", b"same-content").unwrap();
    vault.lock(&key, "a.txt", b"same-content").unwrap();

    let snap = vault.snapshot().unwrap();
    assert_eq!(snap.entries.len(), 1);

    let recovered = vault.unlock(&key, "a.txt").unwrap();
    assert_eq!(recovered, b"same-content");
}
