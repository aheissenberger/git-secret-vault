// Vault format layer (FR-002, ADR-0002).
//
// NOTE: The ZIP-based implementation has been removed. The blob-store format
// is being implemented in feat/vault-format. These stubs keep the CLI
// compiling until that branch is merged.

use std::collections::BTreeMap;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::{Result, VaultError};
use crate::vault::manifest::{Manifest, ManifestEntry};

/// Read the manifest from an existing vault directory.
/// TODO: replace with blob-store implementation once feat/vault-format is merged.
pub fn read_manifest(_vault_path: &Path, _password: &str) -> Result<(Manifest, Vec<u8>)> {
    Err(VaultError::NotImplemented)
}

/// Read a single named entry from the vault.
/// TODO: replace with blob-store implementation once feat/vault-format is merged.
pub fn read_entry(_vault_path: &Path, _password: &str, _name: &str) -> Result<Vec<u8>> {
    Err(VaultError::NotImplemented)
}

/// Rewrite the vault atomically with an updated set of entries.
/// TODO: replace with blob-store implementation once feat/vault-format is merged.
pub fn rewrite_vault(
    _vault_path: &Path,
    _password: &str,
    _updates: &BTreeMap<String, Vec<u8>>,
    _manifest: &Manifest,
) -> Result<String> {
    Err(VaultError::NotImplemented)
}

/// Compute SHA-256 of bytes; return lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}


/// Collect mtime of a file as RFC-3339 string (best-effort; empty on failure).
pub fn mtime_of(path: &Path) -> String {
    path.metadata()
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| chrono::DateTime::from_timestamp(d.as_secs() as i64, 0))
        })
        .flatten()
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default()
}

/// Collect POSIX mode bits from a file (None on non-POSIX).
#[cfg(unix)]
pub fn posix_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    path.metadata().ok().map(|m| m.permissions().mode())
}

#[cfg(not(unix))]
pub fn posix_mode(_path: &Path) -> Option<u32> {
    None
}

/// Build a ManifestEntry from a local file.
pub fn entry_from_file(canonical_path: &str, local_path: &Path, data: &[u8]) -> ManifestEntry {
    ManifestEntry {
        path: canonical_path.to_owned(),
        size: data.len() as u64,
        mtime: mtime_of(local_path),
        sha256: sha256_hex(data),
        mode: posix_mode(local_path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const PASSWORD: &str = "test-vault-password-1";
    const WRONG_PASSWORD: &str = "definitely-wrong";

    fn make_manifest(uuid: &str) -> Manifest {
        Manifest::new(uuid)
    }

    // --- sha256_hex ---

    #[test]
    fn sha256_hex_known_value() {
        // SHA-256 of empty bytes is well-known.
        let hash = sha256_hex(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hex_non_empty() {
        let h = sha256_hex(b"hello");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // --- vault round-trip ---

    #[test]
    #[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
    fn init_and_read_manifest_round_trip() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault.szv");
        let manifest = make_manifest("uuid-init");

        let updates = BTreeMap::new();
        let marker = rewrite_vault(&vault, PASSWORD, &updates, &manifest).unwrap();
        assert!(!marker.is_empty());

        let (restored, _) = read_manifest(&vault, PASSWORD).unwrap();
        assert_eq!(restored.vault_uuid, "uuid-init");
        assert!(restored.entries.is_empty());
    }

    #[test]
    #[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
    fn lock_single_entry_and_read_back() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("v.szv");

        let content = b"DB_PASSWORD=s3cr3t\n";
        let mut manifest = make_manifest("uuid-lock");
        manifest.upsert(ManifestEntry {
            path: "secrets.env".to_owned(),
            size: content.len() as u64,
            mtime: String::new(),
            sha256: sha256_hex(content),
            mode: None,
        });

        let mut updates = BTreeMap::new();
        updates.insert("secrets.env".to_owned(), content.to_vec());
        rewrite_vault(&vault, PASSWORD, &updates, &manifest).unwrap();

        let data = read_entry(&vault, PASSWORD, "secrets.env").unwrap();
        assert_eq!(data, content);
    }

    #[test]
    #[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
    fn wrong_password_on_read_manifest_returns_error() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("v.szv");
        let manifest = make_manifest("uuid-wrong-pw");
        rewrite_vault(&vault, PASSWORD, &BTreeMap::new(), &manifest).unwrap();

        let result = read_manifest(&vault, WRONG_PASSWORD);
        assert!(result.is_err(), "wrong password should produce an error");
    }

    #[test]
    #[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
    fn wrong_password_on_read_entry_returns_error() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("v.szv");
        let content = b"secret";
        let mut manifest = make_manifest("uuid-wp2");
        manifest.upsert(ManifestEntry {
            path: "f.env".to_owned(),
            size: content.len() as u64,
            mtime: String::new(),
            sha256: sha256_hex(content),
            mode: None,
        });
        let mut updates = BTreeMap::new();
        updates.insert("f.env".to_owned(), content.to_vec());
        rewrite_vault(&vault, PASSWORD, &updates, &manifest).unwrap();

        assert!(read_entry(&vault, WRONG_PASSWORD, "f.env").is_err());
    }

    #[test]
    #[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
    fn missing_entry_returns_error() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("v.szv");
        let manifest = make_manifest("uuid-miss");
        rewrite_vault(&vault, PASSWORD, &BTreeMap::new(), &manifest).unwrap();

        let result = read_entry(&vault, PASSWORD, "not-here.env");
        assert!(result.is_err());
    }

    #[test]
    #[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
    fn lock_multiple_entries_deterministic_order() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("v.szv");
        let mut manifest = make_manifest("uuid-det");

        let mut updates = BTreeMap::new();
        for name in ["z.env", "a.env", "m.env"] {
            let data = format!("content of {name}").into_bytes();
            manifest.upsert(ManifestEntry {
                path: name.to_owned(),
                size: data.len() as u64,
                mtime: String::new(),
                sha256: sha256_hex(&data),
                mode: None,
            });
            updates.insert(name.to_owned(), data);
        }

        let marker1 = rewrite_vault(&vault, PASSWORD, &updates, &manifest).unwrap();
        // Second write with same content must produce identical marker (NFR-001).
        let marker2 = rewrite_vault(&vault, PASSWORD, &updates, &manifest).unwrap();
        assert_eq!(marker1, marker2, "repeated lock must be deterministic");
    }

    #[test]
    #[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
    fn incremental_lock_carries_existing_entries() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("v.szv");

        // First lock: add a.env
        let mut manifest = make_manifest("uuid-incr");
        let mut updates = BTreeMap::new();
        updates.insert("a.env".to_owned(), b"aaa".to_vec());
        manifest.upsert(ManifestEntry {
            path: "a.env".to_owned(),
            size: 3,
            mtime: String::new(),
            sha256: sha256_hex(b"aaa"),
            mode: None,
        });
        rewrite_vault(&vault, PASSWORD, &updates, &manifest).unwrap();

        // Second lock: add b.env, carry a.env
        let mut updates2 = BTreeMap::new();
        updates2.insert("b.env".to_owned(), b"bbb".to_vec());
        manifest.upsert(ManifestEntry {
            path: "b.env".to_owned(),
            size: 3,
            mtime: String::new(),
            sha256: sha256_hex(b"bbb"),
            mode: None,
        });
        rewrite_vault(&vault, PASSWORD, &updates2, &manifest).unwrap();

        // Both entries must be readable.
        assert_eq!(read_entry(&vault, PASSWORD, "a.env").unwrap(), b"aaa");
        assert_eq!(read_entry(&vault, PASSWORD, "b.env").unwrap(), b"bbb");
    }

    // --- entry_from_file ---

    #[test]
    fn entry_from_file_computes_correct_hash() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("test.env");
        std::fs::write(&file, b"content").unwrap();
        let entry = entry_from_file("test.env", &file, b"content");
        assert_eq!(entry.path, "test.env");
        assert_eq!(entry.sha256, sha256_hex(b"content"));
        assert_eq!(entry.size, 7);
    }

    // --- mtime_of / posix_mode ---

    #[test]
    fn mtime_of_existing_file_returns_nonempty_string() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("t.txt");
        std::fs::write(&file, b"x").unwrap();
        let mtime = mtime_of(&file);
        // Should be a non-empty RFC-3339 string.
        assert!(
            !mtime.is_empty(),
            "mtime of existing file should not be empty"
        );
    }

    #[test]
    fn mtime_of_missing_file_returns_empty_string() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("no-such-file.txt");
        assert_eq!(mtime_of(&missing), "");
    }

    #[cfg(unix)]
    #[test]
    fn posix_mode_existing_file_returns_some() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("p.txt");
        std::fs::write(&file, b"y").unwrap();
        assert!(posix_mode(&file).is_some());
    }

    #[cfg(unix)]
    #[test]
    fn posix_mode_missing_file_returns_none() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("gone.txt");
        assert!(posix_mode(&missing).is_none());
    }

    #[test]
    fn read_manifest_nonexistent_vault_returns_error() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("nonexistent.szv");
        assert!(read_manifest(&vault, PASSWORD).is_err());
    }
}
