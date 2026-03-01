pub mod blob;
pub mod event_log;
pub mod format;
pub mod index;
pub mod manifest;
pub mod meta;
pub mod snapshot;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;
use crate::crypto::{self, generate_key_id};
use crate::error::{Result, VaultError};
use crate::vault::blob::{load_blob, store_blob};
use crate::vault::event_log::{Event, Op, append_event, read_events};
use crate::vault::meta::VaultMeta;
use crate::vault::snapshot::{Snapshot, rebuild_snapshot, save_snapshot, load_snapshot};

/// Labels file: index/labels.json — maps entry_id -> label (logical name).
/// This file is part of the authoritative format; it is NOT encrypted.
/// (Label encryption is a future enhancement tracked separately.)
fn labels_path(vault_dir: &Path) -> PathBuf { vault_dir.join("index").join("labels.json") }

fn load_labels(vault_dir: &Path) -> Result<BTreeMap<String, String>> {
    let path = labels_path(vault_dir);
    if !path.exists() { return Ok(BTreeMap::new()); }
    let data = std::fs::read(&path).map_err(VaultError::Io)?;
    serde_json::from_slice(&data).map_err(|e| VaultError::Other(format!("labels parse: {e}")))
}

fn save_labels(vault_dir: &Path, labels: &BTreeMap<String, String>) -> Result<()> {
    let path = labels_path(vault_dir);
    let data = serde_json::to_vec_pretty(labels)
        .map_err(|e| VaultError::Other(format!("labels serialize: {e}")))?;
    crate::fs::atomic_write(&path, &data)
}

pub struct Vault {
    pub dir: PathBuf,
    pub meta: VaultMeta,
}

impl Vault {
    pub fn init(vault_dir: &Path, password: &str) -> Result<Self> {
        if vault_dir.join("vault.meta.json").exists() {
            return Err(VaultError::Other("vault already exists".to_owned()));
        }
        std::fs::create_dir_all(vault_dir.join("blobs")).map_err(VaultError::Io)?;
        std::fs::create_dir_all(vault_dir.join("index")).map_err(VaultError::Io)?;
        let salt = crypto::generate_salt();
        let meta = VaultMeta::new(&salt);
        meta.save(vault_dir)?;
        // Derive key once to validate password (and warm up Argon2)
        let salt_bytes = meta.salt_bytes()?;
        let _ = crypto::derive_key(password.as_bytes(), &salt_bytes)?;
        Ok(Self { dir: vault_dir.to_path_buf(), meta })
    }

    pub fn open(vault_dir: &Path) -> Result<Self> {
        let meta = VaultMeta::load(vault_dir)?;
        Ok(Self { dir: vault_dir.to_path_buf(), meta })
    }

    pub fn derive_key(&self, password: &str) -> Result<Zeroizing<[u8; 32]>> {
        let salt = self.meta.salt_bytes()?;
        crypto::derive_key(password.as_bytes(), &salt)
    }

    pub fn lock(&self, key: &[u8; 32], label: &str, plaintext: &[u8]) -> Result<String> {
        let mut labels = load_labels(&self.dir)?;

        // Check if label already exists → update; else add
        let (entry_id, op) = if let Some((id, _)) = labels.iter().find(|(_, l)| l.as_str() == label) {
            (id.clone(), Op::Update)
        } else {
            (generate_key_id(), Op::Add)
        };

        let key_id = self.meta.key_ids.last()
            .ok_or_else(|| VaultError::Other("no key_id in meta".to_owned()))?
            .clone();

        let content_hash = store_blob(&self.dir, key, plaintext)?;
        let event = Event::now(op, entry_id.clone(), Some(content_hash), key_id);
        append_event(&self.dir, &event)?;

        labels.insert(entry_id.clone(), label.to_owned());
        save_labels(&self.dir, &labels)?;

        let all_events = read_events(&self.dir)?;
        let snapshot = rebuild_snapshot(&all_events, &labels);
        save_snapshot(&self.dir, &snapshot)?;
        Ok(entry_id)
    }

    pub fn unlock(&self, key: &[u8; 32], label: &str) -> Result<Vec<u8>> {
        let snapshot = load_snapshot(&self.dir)?;
        let entry = snapshot.find_by_label(label)
            .ok_or_else(|| VaultError::Other(format!("entry not found: {label}")))?;
        load_blob(&self.dir, key, &entry.content_hash)
    }

    pub fn remove(&self, key: &[u8; 32], label: &str) -> Result<()> {
        let mut labels = load_labels(&self.dir)?;
        let entry_id = labels.iter()
            .find(|(_, l)| l.as_str() == label)
            .map(|(id, _)| id.clone())
            .ok_or_else(|| VaultError::Other(format!("entry not found: {label}")))?;

        let key_id = self.meta.key_ids.last()
            .ok_or_else(|| VaultError::Other("no key_id in meta".to_owned()))?
            .clone();

        let event = Event::now(Op::Remove, entry_id.clone(), None, key_id);
        append_event(&self.dir, &event)?;

        labels.remove(&entry_id);
        save_labels(&self.dir, &labels)?;

        let all_events = read_events(&self.dir)?;
        let snapshot = rebuild_snapshot(&all_events, &labels);
        save_snapshot(&self.dir, &snapshot)?;
        let _ = key; // key accepted for API symmetry, not needed for remove
        Ok(())
    }

    pub fn snapshot(&self) -> Result<Snapshot> {
        load_snapshot(&self.dir)
    }

    pub fn verify(&self, key: &[u8; 32]) -> Result<()> {
        use crate::crypto::content_hash;
        let snapshot = load_snapshot(&self.dir)?;
        for entry in &snapshot.entries {
            let plaintext = load_blob(&self.dir, key, &entry.content_hash)?;
            let actual_hash = content_hash(&plaintext);
            if actual_hash != entry.content_hash {
                return Err(VaultError::Other(format!("hash mismatch for entry {}", entry.label)));
            }
        }
        Ok(())
    }

    pub fn rotate_key(&self, old_key: &[u8; 32], new_password: &str) -> Result<()> {
        use crate::crypto::{generate_salt, content_hash as chash};
        let snapshot = load_snapshot(&self.dir)?;

        // Generate new salt + derive new key
        let new_salt = generate_salt();
        let new_key_raw = crypto::derive_key(new_password.as_bytes(), &new_salt)?;
        let new_key: &[u8; 32] = &new_key_raw;
        let new_key_id = generate_key_id();

        // Re-encrypt all blobs
        for entry in &snapshot.entries {
            let plaintext = load_blob(&self.dir, old_key, &entry.content_hash)?;
            let new_hash = chash(&plaintext);
            let encrypted = crypto::encrypt_blob(new_key, &plaintext)?;
            let new_path = blob::blob_path(&self.dir, &new_hash);
            crate::fs::atomic_write(&new_path, &encrypted)?;
            let event = Event::now(Op::Rotate, entry.entry_id.clone(), Some(new_hash), new_key_id.clone());
            append_event(&self.dir, &event)?;
        }

        // Update meta with new salt and key_id
        let labels = load_labels(&self.dir)?;
        let all_events = read_events(&self.dir)?;
        let new_snapshot = rebuild_snapshot(&all_events, &labels);
        save_snapshot(&self.dir, &new_snapshot)?;

        let mut new_meta = self.meta.clone();
        new_meta.salt = hex::encode(new_salt);
        new_meta.key_ids.push(new_key_id);
        new_meta.save(&self.dir)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup() -> (TempDir, Vault) {
        let dir = TempDir::new().unwrap();
        let vault = Vault::init(dir.path(), "test-password").unwrap();
        (dir, vault)
    }

    #[test]
    fn test_init_creates_structure() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::init(dir.path(), "pass").unwrap();
        assert!(dir.path().join("vault.meta.json").exists());
        assert!(dir.path().join("blobs").is_dir());
        assert!(dir.path().join("index").is_dir());
        assert!(!vault.meta.key_ids.is_empty());
    }

    #[test]
    fn test_init_twice_fails() {
        let dir = TempDir::new().unwrap();
        Vault::init(dir.path(), "pass").unwrap();
        assert!(Vault::init(dir.path(), "pass").is_err());
    }

    #[test]
    fn test_open_roundtrip() {
        let dir = TempDir::new().unwrap();
        Vault::init(dir.path(), "pass").unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        assert_eq!(vault.meta.version, 1);
    }

    #[test]
    fn test_lock_and_unlock() {
        let (_dir, vault) = setup();
        let key = vault.derive_key("test-password").unwrap();
        vault.lock(&key, "my-secret", b"hello world").unwrap();
        let plaintext = vault.unlock(&key, "my-secret").unwrap();
        assert_eq!(plaintext, b"hello world");
    }

    #[test]
    fn test_lock_update_existing_label() {
        let (_dir, vault) = setup();
        let key = vault.derive_key("test-password").unwrap();
        vault.lock(&key, "sec", b"v1").unwrap();
        vault.lock(&key, "sec", b"v2").unwrap();
        let plaintext = vault.unlock(&key, "sec").unwrap();
        assert_eq!(plaintext, b"v2");
        // Only one entry in snapshot
        let snap = vault.snapshot().unwrap();
        assert_eq!(snap.entries.len(), 1);
    }

    #[test]
    fn test_remove() {
        let (_dir, vault) = setup();
        let key = vault.derive_key("test-password").unwrap();
        vault.lock(&key, "gone", b"data").unwrap();
        vault.remove(&key, "gone").unwrap();
        let snap = vault.snapshot().unwrap();
        assert!(snap.entries.is_empty());
    }

    #[test]
    fn test_remove_nonexistent_fails() {
        let (_dir, vault) = setup();
        let key = vault.derive_key("test-password").unwrap();
        assert!(vault.remove(&key, "nope").is_err());
    }

    #[test]
    fn test_verify_passes() {
        let (_dir, vault) = setup();
        let key = vault.derive_key("test-password").unwrap();
        vault.lock(&key, "s1", b"data1").unwrap();
        vault.lock(&key, "s2", b"data2").unwrap();
        assert!(vault.verify(&key).is_ok());
    }

    #[test]
    fn test_snapshot_lists_entries() {
        let (_dir, vault) = setup();
        let key = vault.derive_key("test-password").unwrap();
        vault.lock(&key, "a", b"aaa").unwrap();
        vault.lock(&key, "b", b"bbb").unwrap();
        let snap = vault.snapshot().unwrap();
        assert_eq!(snap.entries.len(), 2);
        assert!(snap.find_by_label("a").is_some());
        assert!(snap.find_by_label("b").is_some());
    }

    #[test]
    fn test_snapshot_rebuild_from_events() {
        use crate::vault::event_log::{Event, Op};
        use std::collections::BTreeMap;
        use crate::vault::snapshot::rebuild_snapshot;

        let mut labels = BTreeMap::new();
        labels.insert("id-1".to_owned(), "foo".to_owned());
        labels.insert("id-2".to_owned(), "bar".to_owned());

        let events = vec![
            Event { ts: "t1".into(), op: Op::Add, entry_id: "id-1".into(), content_hash: Some("h1".into()), key_id: "k1".into() },
            Event { ts: "t2".into(), op: Op::Add, entry_id: "id-2".into(), content_hash: Some("h2".into()), key_id: "k1".into() },
            Event { ts: "t3".into(), op: Op::Remove, entry_id: "id-2".into(), content_hash: None, key_id: "k1".into() },
        ];

        let snap = rebuild_snapshot(&events, &labels);
        assert_eq!(snap.entries.len(), 1);
        assert_eq!(snap.entries[0].label, "foo");
    }
}
