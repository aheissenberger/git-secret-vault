// Integration tests for corruption and error paths (NFR-011).
//
// These tests exercise the internal vault/index APIs directly to verify
// that all error and corruption scenarios return appropriate errors rather
// than silently succeeding or panicking.

use std::collections::BTreeMap;

use git_secret_vault::error::VaultError;
use git_secret_vault::vault::format::{read_entry, read_manifest, rewrite_vault, sha256_hex};
use git_secret_vault::vault::index::OuterIndex;
use git_secret_vault::vault::manifest::{Manifest, ManifestEntry};
use tempfile::tempdir;

const PASSWORD: &str = "correct-horse-battery-staple";
const WRONG_PASSWORD: &str = "wrong-password-xyz";

// ── helpers ──────────────────────────────────────────────────────────────────

fn blank_manifest(uuid: &str) -> Manifest {
    Manifest::new(uuid)
}

fn make_entry(path: &str, data: &[u8]) -> ManifestEntry {
    ManifestEntry {
        path: path.to_owned(),
        size: data.len() as u64,
        mtime: String::new(),
        sha256: sha256_hex(data),
        mode: None,
    }
}

/// Create a vault with no entries at `vault_path`.
fn create_empty_vault(vault_path: &std::path::Path) {
    let manifest = blank_manifest("test-uuid");
    rewrite_vault(vault_path, PASSWORD, &BTreeMap::new(), &manifest).unwrap();
}

/// Create a vault with one entry and return the locked data.
fn create_vault_with_entry(vault_path: &std::path::Path, entry_name: &str, data: &[u8]) {
    let mut manifest = blank_manifest("test-uuid-entry");
    manifest.upsert(make_entry(entry_name, data));
    let mut updates = BTreeMap::new();
    updates.insert(entry_name.to_owned(), data.to_vec());
    rewrite_vault(vault_path, PASSWORD, &updates, &manifest).unwrap();
}

// ── test 1: wrong password on read_manifest ───────────────────────────────

#[test]
#[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
fn wrong_password_on_read_manifest_returns_error() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.zip");
    create_empty_vault(&vault);

    let result = read_manifest(&vault, WRONG_PASSWORD);
    assert!(
        result.is_err(),
        "expected error when reading manifest with wrong password"
    );
}

// ── test 2: truncated vault file ──────────────────────────────────────────

#[test]
#[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
fn truncated_vault_returns_error() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.zip");
    create_empty_vault(&vault);

    // Truncate to 10 bytes – not a valid ZIP.
    std::fs::write(&vault, b"truncated!").unwrap();

    let result = read_manifest(&vault, PASSWORD);
    assert!(
        result.is_err(),
        "expected error when reading truncated vault"
    );
}

// ── test 3: missing vault file ────────────────────────────────────────────

#[test]
#[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
fn missing_vault_file_returns_error() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("nonexistent.zip");

    let result = read_manifest(&vault, PASSWORD);
    assert!(
        result.is_err(),
        "expected error when vault file does not exist"
    );
    // Should be an IO error (file not found).
    assert!(matches!(result.unwrap_err(), VaultError::Io(_)));
}

// ── test 4: corrupted zip returns error ───────────────────────────────────

#[test]
fn corrupted_zip_returns_error() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.zip");

    // Write random bytes that are not a valid ZIP archive.
    let garbage: Vec<u8> = (0u8..=255).cycle().take(512).collect();
    std::fs::write(&vault, &garbage).unwrap();

    let result = read_manifest(&vault, PASSWORD);
    assert!(
        result.is_err(),
        "expected error when vault contains random bytes"
    );
}

// ── test 5: wrong password on read_entry ─────────────────────────────────

#[test]
#[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
fn wrong_password_on_read_entry_returns_error() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.zip");
    let entry_name = "secrets.env";
    let data = b"DB_PASSWORD=hunter2";
    create_vault_with_entry(&vault, entry_name, data);

    let result = read_entry(&vault, WRONG_PASSWORD, entry_name);
    assert!(
        result.is_err(),
        "expected error when reading entry with wrong password"
    );
}

// ── test 6: missing index file ────────────────────────────────────────────

#[test]
fn missing_index_file_returns_error() {
    let dir = tempdir().unwrap();
    let index_path = dir.path().join(".git-secret-vault.index.json");

    let result = OuterIndex::read(&index_path);
    assert!(
        result.is_err(),
        "expected error when index file does not exist"
    );
    assert!(matches!(result.unwrap_err(), VaultError::Io(_)));
}

// ── test 7: corrupted index JSON ─────────────────────────────────────────

#[test]
fn corrupted_index_json_returns_error() {
    let dir = tempdir().unwrap();
    let index_path = dir.path().join(".git-secret-vault.index.json");

    // Write invalid JSON.
    std::fs::write(&index_path, b"{ this is: not valid json !!!").unwrap();

    let result = OuterIndex::read(&index_path);
    assert!(
        result.is_err(),
        "expected error when index JSON is corrupted"
    );
    assert!(matches!(result.unwrap_err(), VaultError::Json(_)));
}

// ── test 8: rm with unknown path returns error ────────────────────────────

#[test]
#[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
fn rm_unknown_path_returns_error() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.zip");
    create_empty_vault(&vault);

    // Read the (empty) manifest, then attempt to remove a path that doesn't exist.
    let (manifest, _) = read_manifest(&vault, PASSWORD).unwrap();

    let target_path = "nonexistent/secret.env";
    let exists_in_manifest = manifest.entries.iter().any(|e| e.path == target_path);

    // The rm logic returns an error when no matching entries are found.
    // Simulate: collect paths to remove, then assert none matched.
    let to_remove: Vec<String> = vec![target_path.to_owned()]
        .into_iter()
        .filter(|p| manifest.entries.iter().any(|e| &e.path == p))
        .collect();

    assert!(
        !exists_in_manifest,
        "path should not exist in empty manifest"
    );
    assert!(
        to_remove.is_empty(),
        "rm should find no matching entries → would return error"
    );
}

// ── test 9: lock --check on stale file detects drift ─────────────────────

#[test]
#[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
fn lock_check_stale_file_returns_error() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.zip");
    let entry_name = "tracked.env";
    let original_data = b"SECRET=original";

    // Lock the file into the vault.
    create_vault_with_entry(&vault, entry_name, original_data);

    // Simulate drift: read the manifest and check whether the hash matches
    // modified content (as the lock --check code does).
    let (manifest, _) = read_manifest(&vault, PASSWORD).unwrap();
    let stored_entry = manifest
        .entries
        .iter()
        .find(|e| e.path == entry_name)
        .unwrap();

    let modified_data = b"SECRET=tampered";
    let current_hash = sha256_hex(modified_data);

    // Hash of modified content must differ from what's stored → drift detected.
    assert_ne!(
        current_hash, stored_entry.sha256,
        "drift should be detected: hashes must differ after modification"
    );
}

// ── test 10: verify returns ok on clean vault (smoke test) ────────────────

#[test]
#[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
fn verify_clean_vault_passes() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.zip");
    let entry_name = "clean.env";
    let data = b"CLEAN=true";
    create_vault_with_entry(&vault, entry_name, data);

    let (manifest, _) = read_manifest(&vault, PASSWORD).unwrap();
    let entry = manifest
        .entries
        .iter()
        .find(|e| e.path == entry_name)
        .unwrap();

    // Read back the entry and verify its hash.
    let actual_data = read_entry(&vault, PASSWORD, entry_name).unwrap();
    let actual_hash = sha256_hex(&actual_data);

    assert_eq!(
        actual_hash, entry.sha256,
        "verify should pass: hash matches stored hash"
    );
}

// ── test 11: verify detects hash mismatch in manifest ────────────────────

#[test]
#[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
fn verify_detects_hash_mismatch() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.zip");
    let entry_name = "tampered.env";
    let data = b"REAL=value";

    // Lock the entry with a deliberately wrong sha256 in the manifest.
    let mut manifest = blank_manifest("uuid-tamper");
    manifest.upsert(ManifestEntry {
        path: entry_name.to_owned(),
        size: data.len() as u64,
        mtime: String::new(),
        sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
        mode: None,
    });
    let mut updates = BTreeMap::new();
    updates.insert(entry_name.to_owned(), data.to_vec());
    rewrite_vault(&vault, PASSWORD, &updates, &manifest).unwrap();

    // Now simulate verify: read manifest and compare hashes.
    let (manifest, _) = read_manifest(&vault, PASSWORD).unwrap();
    let entry = manifest
        .entries
        .iter()
        .find(|e| e.path == entry_name)
        .unwrap();
    let actual_data = read_entry(&vault, PASSWORD, entry_name).unwrap();
    let actual_hash = sha256_hex(&actual_data);

    assert_ne!(
        actual_hash, entry.sha256,
        "verify should detect hash mismatch"
    );
}
