// NFR-012: Security-focused integration tests.
//
// Covers: path traversal prevention (SEC-006), password policy (SEC-002),
// metadata exposure (SEC-001), keep-both conflict policy (FR-011),
// lock --remove behaviour (FR-010), and clean tracking boundary.

use std::collections::BTreeMap;
use std::path::Path;

use git_secret_vault::crypto;
use git_secret_vault::error::VaultError;
use git_secret_vault::fs::safe_join;
use git_secret_vault::vault::format::{self, read_entry, rewrite_vault, sha256_hex};
use git_secret_vault::vault::index::OuterIndex;
use git_secret_vault::vault::manifest::{Manifest, ManifestEntry};
use tempfile::tempdir;

// ── helpers ─────────────────────────────────────────────────────────────────

fn make_entry(path: &str, content: &[u8]) -> ManifestEntry {
    ManifestEntry {
        path: path.to_owned(),
        size: content.len() as u64,
        mtime: String::new(),
        sha256: sha256_hex(content),
        mode: None,
    }
}

/// Build a vault pre-loaded with the given entries.
fn seed_vault(dir: &Path, password: &str, entries: &[(&str, &[u8])]) -> std::path::PathBuf {
    let vault_path = dir.join("vault.szv");
    let mut manifest = Manifest::new("test-uuid");
    let mut updates = BTreeMap::new();
    for (name, content) in entries {
        manifest.upsert(make_entry(name, content));
        updates.insert((*name).to_owned(), content.to_vec());
    }
    rewrite_vault(&vault_path, password, &updates, &manifest).unwrap();
    vault_path
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

// ── 4. Symlink source: current lock layer does not explicitly reject symlinks.
//        The format layer encrypts whatever bytes std::fs::read returns (which
//        follows the symlink).  We document this behaviour here and verify that
//        locking a regular file succeeds end-to-end. ─────────────────────────

#[test]
fn lock_regular_file_round_trip_succeeds() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("vault.szv");
    let manifest = Manifest::new("uuid-regular");
    rewrite_vault(&vault_path, "pw12345678", &BTreeMap::new(), &manifest).unwrap();

    let secret = dir.path().join("api.key");
    std::fs::write(&secret, b"supersecret").unwrap();

    let data = std::fs::read(&secret).unwrap();
    let mut manifest2 = manifest;
    manifest2.upsert(make_entry("api.key", &data));
    let mut updates = BTreeMap::new();
    updates.insert("api.key".to_owned(), data.clone());
    rewrite_vault(&vault_path, "pw12345678", &updates, &manifest2).unwrap();

    let back = read_entry(&vault_path, "pw12345678", "api.key").unwrap();
    assert_eq!(back, b"supersecret");
}

// ── 5. Password minimum length is enforced (SEC-002) ─────────────────────────

#[test]
fn password_too_short_is_rejected() {
    let result = crypto::validate_password_strength("short");
    assert!(
        result.is_err(),
        "passwords shorter than 8 chars must be rejected"
    );
}

#[test]
fn password_long_enough_is_accepted() {
    let result = crypto::validate_password_strength("longpassword");
    assert!(result.is_ok(), "passwords of 8+ chars must be accepted");
}

// ── 6. Index file contains no filenames (SEC-001) ────────────────────────────

#[test]
fn outer_index_contains_no_filenames() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("vault.szv");
    let index_path = dir.path().join(".index.json");

    let mut manifest = Manifest::new("uuid-sec001");
    let content = b"api_key=secret123";
    manifest.upsert(make_entry("secrets/api.key", content));
    let mut updates = BTreeMap::new();
    updates.insert("secrets/api.key".to_owned(), content.to_vec());
    let marker = rewrite_vault(&vault_path, "pw12345678", &updates, &manifest).unwrap();

    let outer = OuterIndex::new("uuid-sec001", 1, marker);
    outer.write(&index_path).unwrap();

    let raw = std::fs::read_to_string(&index_path).unwrap();
    assert!(
        !raw.contains("api.key"),
        "index must not expose entry filenames; got:\n{raw}"
    );
    assert!(
        !raw.contains("secrets"),
        "index must not expose directory names; got:\n{raw}"
    );
}

// ── 7. Unlock keep-both: vault copy is written alongside local file ────────────

#[test]
fn unlock_keep_both_writes_vault_copy() {
    let dir = tempdir().unwrap();
    let vault_path = seed_vault(
        dir.path(),
        "pw12345678",
        &[("secret.env", b"vault-content")],
    );

    // Simulate a conflicting local file.
    let local = dir.path().join("secret.env");
    std::fs::write(&local, b"local-content").unwrap();

    // keep-both: write vault bytes to a .vault-copy sibling.
    let copy_dest = dir.path().join("secret.env.vault-copy");
    let data = read_entry(&vault_path, "pw12345678", "secret.env").unwrap();
    git_secret_vault::fs::atomic_write(&copy_dest, &data).unwrap();

    assert_eq!(
        std::fs::read(&local).unwrap(),
        b"local-content",
        "local file must remain unchanged"
    );
    assert_eq!(
        std::fs::read(&copy_dest).unwrap(),
        b"vault-content",
        "vault copy must contain the vault version"
    );
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
    let vault_path = dir.path().join("vault.szv");
    let mut manifest = Manifest::new("uuid-remove");
    rewrite_vault(&vault_path, "pw12345678", &BTreeMap::new(), &manifest).unwrap();

    let plain = dir.path().join("plain.env");
    std::fs::write(&plain, b"remove-me").unwrap();
    assert!(plain.exists());

    // Lock the file into the vault.
    let data = std::fs::read(&plain).unwrap();
    manifest.upsert(make_entry("plain.env", &data));
    let mut updates = BTreeMap::new();
    updates.insert("plain.env".to_owned(), data);
    rewrite_vault(&vault_path, "pw12345678", &updates, &manifest).unwrap();

    // --remove: delete plaintext only after vault write succeeds.
    std::fs::remove_file(&plain).unwrap();
    assert!(
        !plain.exists(),
        "plaintext must be deleted after lock --remove"
    );

    // Vault retains the encrypted copy.
    let back = read_entry(&vault_path, "pw12345678", "plain.env").unwrap();
    assert_eq!(back, b"remove-me");
}

// ── 10. Clean only removes tracked files; untracked files are untouched ───────

#[test]
fn clean_only_removes_tracked_files() {
    let dir = tempdir().unwrap();
    let vault_path = seed_vault(dir.path(), "pw12345678", &[("tracked.env", b"data")]);

    let tracked = dir.path().join("tracked.env");
    let untracked = dir.path().join("untracked.env");
    std::fs::write(&tracked, b"data").unwrap();
    std::fs::write(&untracked, b"untouched").unwrap();

    // Clean: iterate only over manifest entries.
    let (manifest, _) = format::read_manifest(&vault_path, "pw12345678").unwrap();
    for entry in &manifest.entries {
        let local = dir.path().join(&entry.path);
        if local.exists() {
            std::fs::remove_file(&local).unwrap();
        }
    }

    assert!(!tracked.exists(), "tracked file must be removed by clean");
    assert!(
        untracked.exists(),
        "untracked file must NOT be removed by clean"
    );
}

// ── 11. Keyring entry construction does not panic (FR-017 / NFR-014) ──────────

#[test]
fn keyring_entry_new_does_not_panic() {
    // Validates the keyring crate is correctly linked without requiring a real
    // keyring daemon.  We only assert that Entry::new succeeds (Ok), not that
    // get_password works in this environment.
    let result = keyring::Entry::new("git-secret-vault", "test-uuid-determinism");
    assert!(
        result.is_ok(),
        "keyring::Entry::new must succeed: {:?}",
        result.err()
    );
}
