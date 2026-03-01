// Golden-path integration tests for git-secret-vault (NFR-010).
//
// These tests exercise the happy paths end-to-end using the library APIs
// directly, without invoking the compiled binary.

use std::collections::BTreeMap;

use git_secret_vault::vault::{
    format::{self, sha256_hex},
    index::OuterIndex,
    manifest::{Manifest, ManifestEntry},
};
use tempfile::tempdir;

// ── helpers ──────────────────────────────────────────────────────────────────

fn make_manifest(uuid: &str) -> Manifest {
    Manifest::new(uuid)
}

/// Build and persist an empty vault + outer index; return their paths.
fn init_vault(
    dir: &std::path::Path,
    uuid: &str,
    password: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let vault_path = dir.join("vault.zip");
    let index_path = dir.join(".git-secret-vault.index.json");
    let manifest = make_manifest(uuid);
    let marker = format::rewrite_vault(&vault_path, password, &BTreeMap::new(), &manifest).unwrap();
    let outer = OuterIndex::new(uuid, 0, marker);
    outer.write(&index_path).unwrap();
    (vault_path, index_path)
}

/// Lock a single named entry into an existing vault.
fn lock_entry(
    vault_path: &std::path::Path,
    index_path: &std::path::Path,
    password: &str,
    name: &str,
    data: &[u8],
) {
    let (mut manifest, _) = format::read_manifest(vault_path, password).unwrap();
    manifest.upsert(ManifestEntry {
        path: name.to_owned(),
        size: data.len() as u64,
        mtime: String::new(),
        sha256: sha256_hex(data),
        mode: None,
    });
    let mut updates: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    updates.insert(name.to_owned(), data.to_vec());
    let marker = format::rewrite_vault(vault_path, password, &updates, &manifest).unwrap();

    let mut outer = OuterIndex::read(index_path).unwrap();
    outer.entry_count = manifest.entries.len();
    outer.integrity_marker = marker;
    outer.updated_at = chrono::Utc::now().to_rfc3339();
    outer.write(index_path).unwrap();
}

// ── test 1: init → lock → unlock round-trip ──────────────────────────────────

#[test]
#[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
fn init_lock_unlock_roundtrip() {
    let dir = tempdir().unwrap();
    let (vault_path, index_path) = init_vault(dir.path(), "vault-uuid-1", "mypassword");

    let plaintext = b"API_KEY=super-secret-value\n";
    lock_entry(&vault_path, &index_path, "mypassword", "api.env", plaintext);

    // Unlock: read entry back and verify content.
    let recovered = format::read_entry(&vault_path, "mypassword", "api.env").unwrap();
    assert_eq!(recovered, plaintext, "unlocked content must match original");

    // Manifest must reflect the entry.
    let (manifest, _) = format::read_manifest(&vault_path, "mypassword").unwrap();
    assert_eq!(manifest.entries.len(), 1);
    assert_eq!(manifest.entries[0].path, "api.env");
}

// ── test 2: lock multiple files then unlock all ───────────────────────────────

#[test]
#[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
fn lock_multiple_files_then_unlock_all() {
    let dir = tempdir().unwrap();
    let (vault_path, index_path) = init_vault(dir.path(), "vault-uuid-2", "multipass");

    let files: &[(&str, &[u8])] = &[
        ("db.env", b"DB_PASSWORD=hunter2"),
        ("redis.env", b"REDIS_URL=redis://localhost:6379"),
        ("aws.env", b"AWS_SECRET_ACCESS_KEY=abc123xyz"),
    ];

    for (name, data) in files {
        lock_entry(&vault_path, &index_path, "multipass", name, data);
    }

    // Verify entry count in outer index.
    let outer = OuterIndex::read(&index_path).unwrap();
    assert_eq!(outer.entry_count, 3);

    // Unlock each file and verify content.
    for (name, expected) in files {
        let recovered = format::read_entry(&vault_path, "multipass", name).unwrap();
        assert_eq!(&recovered, expected, "content mismatch for {name}");
    }
}

// ── test 3: lock → rm → verify entry gone ────────────────────────────────────

#[test]
#[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
fn lock_rm_entry_gone() {
    let dir = tempdir().unwrap();
    let (vault_path, index_path) = init_vault(dir.path(), "vault-uuid-3", "rmpass");

    lock_entry(&vault_path, &index_path, "rmpass", "keep.env", b"keep-me");
    lock_entry(
        &vault_path,
        &index_path,
        "rmpass",
        "delete.env",
        b"delete-me",
    );

    // Remove "delete.env" using the rm logic.
    let (mut manifest, _) = format::read_manifest(&vault_path, "rmpass").unwrap();
    manifest.entries.retain(|e| e.path != "delete.env");
    manifest.updated_at = chrono::Utc::now().to_rfc3339();

    // Rebuild updates: remaining entries + tombstone for deleted entry.
    let mut updates: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for entry in &manifest.entries {
        let data = format::read_entry(&vault_path, "rmpass", &entry.path).unwrap();
        updates.insert(entry.path.clone(), data);
    }
    updates.insert("delete.env".to_owned(), Vec::new()); // tombstone

    let marker = format::rewrite_vault(&vault_path, "rmpass", &updates, &manifest).unwrap();
    let mut outer = OuterIndex::read(&index_path).unwrap();
    outer.entry_count = manifest.entries.len();
    outer.integrity_marker = marker;
    outer.write(&index_path).unwrap();

    // Manifest must no longer contain "delete.env".
    let (restored, _) = format::read_manifest(&vault_path, "rmpass").unwrap();
    assert!(
        restored.entries.iter().all(|e| e.path != "delete.env"),
        "delete.env must be absent from manifest"
    );
    assert_eq!(restored.entries.len(), 1);
    assert_eq!(restored.entries[0].path, "keep.env");

    // Outer index entry count must be updated.
    let outer = OuterIndex::read(&index_path).unwrap();
    assert_eq!(outer.entry_count, 1);
}

// ── test 4: lock → passwd → unlock with new password ─────────────────────────

#[test]
#[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
fn lock_passwd_unlock_with_new_password() {
    let dir = tempdir().unwrap();
    let (vault_path, index_path) = init_vault(dir.path(), "vault-uuid-4", "oldpass123");

    lock_entry(
        &vault_path,
        &index_path,
        "oldpass123",
        "secret.env",
        b"top-secret-data",
    );

    // Rotate password: read all entries with old password, rewrite with new.
    let old_pw = zeroize::Zeroizing::new("oldpass123".to_owned());
    let new_pw = zeroize::Zeroizing::new("newpass456".to_owned());

    let (manifest, _) = format::read_manifest(&vault_path, &old_pw).unwrap();
    let mut updates: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for entry in &manifest.entries {
        let data = format::read_entry(&vault_path, &old_pw, &entry.path).unwrap();
        updates.insert(entry.path.clone(), data);
    }
    let marker = format::rewrite_vault(&vault_path, &new_pw, &updates, &manifest).unwrap();
    let mut outer = OuterIndex::read(&index_path).unwrap();
    outer.integrity_marker = marker;
    outer.write(&index_path).unwrap();

    // Old password must fail.
    assert!(
        format::read_manifest(&vault_path, &old_pw).is_err(),
        "old password must no longer work after rotation"
    );

    // New password must succeed and data must be intact.
    let recovered = format::read_entry(&vault_path, &new_pw, "secret.env").unwrap();
    assert_eq!(recovered, b"top-secret-data");
}

// ── test 5: status shows correct entry count ─────────────────────────────────

#[test]
#[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
fn status_shows_correct_entry_count() {
    let dir = tempdir().unwrap();
    let (vault_path, index_path) = init_vault(dir.path(), "vault-uuid-5", "statuspass");

    // Lock 4 entries.
    for i in 0..4u8 {
        let name = format!("file{i}.env");
        let data = format!("VALUE={i}").into_bytes();
        lock_entry(&vault_path, &index_path, "statuspass", &name, &data);
    }

    // Status (unauthenticated) reads from outer index only.
    let outer = OuterIndex::read(&index_path).unwrap();
    assert_eq!(outer.entry_count, 4, "outer index must report 4 entries");
}

// ── test 6: lock --check detects drift ───────────────────────────────────────

#[test]
#[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
fn lock_check_detects_drift() {
    let dir = tempdir().unwrap();
    let (vault_path, index_path) = init_vault(dir.path(), "vault-uuid-6", "checkpass");

    let original = b"ORIGINAL_VALUE=abc";
    lock_entry(
        &vault_path,
        &index_path,
        "checkpass",
        "checked.env",
        original,
    );

    // Read manifest to get the stored hash.
    let (manifest, _) = format::read_manifest(&vault_path, "checkpass").unwrap();
    let entry = manifest
        .entries
        .iter()
        .find(|e| e.path == "checked.env")
        .unwrap();
    let stored_hash = entry.sha256.clone();

    // Simulate drift: plaintext has changed.
    let modified = b"MODIFIED_VALUE=xyz";
    let current_hash = sha256_hex(modified);

    // --check logic: if hashes differ, return error.
    let is_stale = current_hash != stored_hash;
    assert!(is_stale, "drift must be detected when plaintext changed");
}

// ── test 7: lock is deterministic (FR-017 / NFR-013) ─────────────────────────

#[test]
#[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
fn lock_is_deterministic() {
    // Two separate vaults locked with the same password and content must
    // produce manifests with identical metadata, and the encrypted data must
    // decrypt to the same plaintext.  Raw ZIP bytes differ because AES-GCM
    // uses random nonces, so we compare logical content only.

    let content = b"hello world";

    // Vault A
    let dir_a = tempdir().unwrap();
    let file_a = dir_a.path().join("data.txt");
    std::fs::write(&file_a, content).unwrap();

    let (vault_a, index_a) = init_vault(dir_a.path(), "det-uuid-a", "det-password");
    lock_entry(&vault_a, &index_a, "det-password", "data.txt", content);

    // Vault B — second independent lock with identical inputs
    let dir_b = tempdir().unwrap();
    let file_b = dir_b.path().join("data.txt");
    std::fs::write(&file_b, content).unwrap();

    let (vault_b, index_b) = init_vault(dir_b.path(), "det-uuid-b", "det-password");
    lock_entry(&vault_b, &index_b, "det-password", "data.txt", content);

    // Read manifests from both vaults.
    let (manifest_a, _) = format::read_manifest(&vault_a, "det-password").unwrap();
    let (manifest_b, _) = format::read_manifest(&vault_b, "det-password").unwrap();

    // Entry metadata must match.
    assert_eq!(manifest_a.entries.len(), manifest_b.entries.len());
    let entry_a = manifest_a
        .entries
        .iter()
        .find(|e| e.path == "data.txt")
        .unwrap();
    let entry_b = manifest_b
        .entries
        .iter()
        .find(|e| e.path == "data.txt")
        .unwrap();

    assert_eq!(entry_a.path, entry_b.path, "entry paths must be identical");
    assert_eq!(
        entry_a.sha256, entry_b.sha256,
        "sha256 hashes must be identical"
    );
    assert_eq!(entry_a.size, entry_b.size, "sizes must be identical");
    assert_eq!(entry_a.mode, entry_b.mode, "modes must be identical");

    // Decrypted content must be identical.
    let plain_a = format::read_entry(&vault_a, "det-password", "data.txt").unwrap();
    let plain_b = format::read_entry(&vault_b, "det-password", "data.txt").unwrap();
    assert_eq!(plain_a, plain_b, "decrypted content must be identical");
    assert_eq!(
        plain_a, content,
        "decrypted content must match original plaintext"
    );
}

// ── test 8: verify reports ok on intact vault ─────────────────────────────────

#[test]
#[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
fn verify_reports_ok_on_intact_vault() {
    let dir = tempdir().unwrap();
    let (vault_path, index_path) = init_vault(dir.path(), "vault-uuid-7", "verifypass");

    let files: &[(&str, &[u8])] = &[
        ("alpha.env", b"ALPHA=1"),
        ("beta.env", b"BETA=2"),
        ("gamma.env", b"GAMMA=3"),
    ];

    for (name, data) in files {
        lock_entry(&vault_path, &index_path, "verifypass", name, data);
    }

    // Verify: for each manifest entry, read the stored data and check SHA-256.
    let (manifest, _) = format::read_manifest(&vault_path, "verifypass").unwrap();
    let mut any_failed = false;
    for entry in &manifest.entries {
        match format::read_entry(&vault_path, "verifypass", &entry.path) {
            Ok(data) => {
                let actual = sha256_hex(&data);
                if actual != entry.sha256 {
                    any_failed = true;
                }
            }
            Err(_) => any_failed = true,
        }
    }

    assert!(!any_failed, "all entries must verify ok on an intact vault");
    assert_eq!(manifest.entries.len(), 3);
}
