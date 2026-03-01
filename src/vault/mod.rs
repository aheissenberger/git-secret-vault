pub mod blob;
pub mod event_log;
pub mod meta;
pub mod snapshot;

use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::crypto;
use crate::error::{Result, VaultError};
use crate::vault::blob::{load_blob, store_blob, store_blob_force};
use crate::vault::event_log::{Event, Op, append_event, read_events};
use crate::vault::meta::VaultMeta;
use crate::vault::snapshot::{Snapshot, rebuild_snapshot, save_snapshot, load_snapshot};

pub struct Vault {
    pub dir: PathBuf,
    pub meta: VaultMeta,
}

impl Vault {
    pub fn init(vault_dir: &Path, password: &str) -> Result<Self> {
        if vault_dir.join("vault.meta.json").exists() {
            return Err(VaultError::VaultExists(vault_dir.display().to_string()));
        }
        std::fs::create_dir_all(vault_dir.join("blobs")).map_err(VaultError::Io)?;
        std::fs::create_dir_all(vault_dir.join("index")).map_err(VaultError::Io)?;

        let salt = crypto::generate_salt();
        let mut meta = VaultMeta::new(&salt);
        let key_id = crypto::generate_key_id();
        crypto::validate_password_strength(password)?;
        meta.key_ids.push(key_id);
        meta.save(vault_dir)?;

        let snap = rebuild_snapshot(&[]);
        save_snapshot(vault_dir, &snap)?;

        Ok(Self { dir: vault_dir.to_path_buf(), meta })
    }

    pub fn open(vault_dir: &Path) -> Result<Self> {
        let meta = VaultMeta::load(vault_dir)
            .map_err(|_| VaultError::VaultNotFound(vault_dir.display().to_string()))?;
        Ok(Self { dir: vault_dir.to_path_buf(), meta })
    }

    pub fn derive_key(&self, password: &str) -> Result<Zeroizing<[u8; 32]>> {
        let salt_bytes = hex::decode(&self.meta.salt)
            .map_err(|e| VaultError::Other(format!("invalid salt hex: {e}")))?;
        if salt_bytes.len() != 16 {
            return Err(VaultError::Other("salt must be 16 bytes".to_owned()));
        }
        let salt: [u8; 16] = salt_bytes.try_into().unwrap();
        crypto::derive_key(password.as_bytes(), &salt)
    }

    pub fn lock(&self, key: &[u8; 32], label: &str, plaintext: &[u8]) -> Result<String> {
        let events = read_events(&self.dir)?;
        let snap = rebuild_snapshot(&events);

        let key_id = self.meta.key_ids.last()
            .ok_or_else(|| VaultError::Other("no key_id in vault meta".to_owned()))?
            .clone();

        let existing = snap.entries.iter().find(|e| e.label == label);
        let (entry_id, op) = if let Some(entry) = existing {
            (entry.entry_id.clone(), Op::Update)
        } else {
            (crypto::generate_key_id(), Op::Add)
        };

        let content_hash = store_blob(&self.dir, key, plaintext)?;

        let event = Event {
            ts: chrono::Utc::now().to_rfc3339(),
            op,
            entry_id: entry_id.clone(),
            label: Some(label.to_owned()),
            content_hash: Some(content_hash),
            key_id,
        };
        append_event(&self.dir, &event)?;

        let new_events = read_events(&self.dir)?;
        let new_snap = rebuild_snapshot(&new_events);
        save_snapshot(&self.dir, &new_snap)?;

        Ok(entry_id)
    }

    pub fn unlock(&self, key: &[u8; 32], label: &str) -> Result<Vec<u8>> {
        let snap = load_snapshot(&self.dir)?;
        let entry = snap.entries.iter().find(|e| e.label == label)
            .ok_or_else(|| VaultError::Other(format!("entry not found: {label}")))?;
        load_blob(&self.dir, key, &entry.content_hash)
    }

    pub fn remove(&self, key: &[u8; 32], label: &str) -> Result<()> {
        let snap = load_snapshot(&self.dir)?;
        let entry = snap.entries.iter().find(|e| e.label == label)
            .ok_or_else(|| VaultError::Other(format!("entry not found: {label}")))?;

        let key_id = self.meta.key_ids.last()
            .ok_or_else(|| VaultError::Other("no key_id in vault meta".to_owned()))?
            .clone();

        let event = Event {
            ts: chrono::Utc::now().to_rfc3339(),
            op: Op::Remove,
            entry_id: entry.entry_id.clone(),
            label: None,
            content_hash: None,
            key_id,
        };
        append_event(&self.dir, &event)?;

        let _ = key;

        let new_events = read_events(&self.dir)?;
        let new_snap = rebuild_snapshot(&new_events);
        save_snapshot(&self.dir, &new_snap)?;
        Ok(())
    }

    pub fn snapshot(&self) -> Result<Snapshot> {
        load_snapshot(&self.dir)
    }

    pub fn verify(&self, key: &[u8; 32]) -> Result<()> {
        let snap = load_snapshot(&self.dir)?;
        for entry in &snap.entries {
            let data = load_blob(&self.dir, key, &entry.content_hash)?;
            let actual_hash = crypto::content_hash(&data);
            if actual_hash != entry.content_hash {
                return Err(VaultError::Other(format!(
                    "hash mismatch for entry {}: expected {}, got {}",
                    entry.label, entry.content_hash, actual_hash
                )));
            }
        }
        Ok(())
    }

    pub fn rotate_key(&self, old_key: &[u8; 32], new_key: &[u8; 32], new_key_id: &str) -> Result<()> {
        let snap = load_snapshot(&self.dir)?;
        for entry in &snap.entries {
            let plaintext = load_blob(&self.dir, old_key, &entry.content_hash)?;
            let new_hash = store_blob_force(&self.dir, new_key, &plaintext)?;
            let event = Event {
                ts: chrono::Utc::now().to_rfc3339(),
                op: Op::Rotate,
                entry_id: entry.entry_id.clone(),
                label: Some(entry.label.clone()),
                content_hash: Some(new_hash),
                key_id: new_key_id.to_owned(),
            };
            append_event(&self.dir, &event)?;
        }

        let mut meta = self.meta.clone();
        if !meta.key_ids.contains(&new_key_id.to_owned()) {
            meta.key_ids.push(new_key_id.to_owned());
        }
        meta.save(&self.dir)?;

        let new_events = read_events(&self.dir)?;
        let new_snap = rebuild_snapshot(&new_events);
        save_snapshot(&self.dir, &new_snap)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const TEST_PASSWORD: &str = "correct-horse-battery-staple-42!";

    fn setup_vault(dir: &std::path::Path) -> Vault {
        Vault::init(dir, TEST_PASSWORD).unwrap()
    }

    #[test]
    fn init_creates_directory_structure() {
        let dir = tempdir().unwrap();
        let vault_dir = dir.path().join("vault");
        Vault::init(&vault_dir, TEST_PASSWORD).unwrap();
        assert!(vault_dir.join("vault.meta.json").exists());
        assert!(vault_dir.join("blobs").is_dir());
        assert!(vault_dir.join("index").is_dir());
        assert!(vault_dir.join("index").join("snapshot.json").exists());
    }

    #[test]
    fn init_twice_fails() {
        let dir = tempdir().unwrap();
        let vault_dir = dir.path().join("vault");
        Vault::init(&vault_dir, TEST_PASSWORD).unwrap();
        assert!(Vault::init(&vault_dir, TEST_PASSWORD).is_err());
    }

    #[test]
    fn lock_and_unlock_round_trip() {
        let dir = tempdir().unwrap();
        let vault_dir = dir.path().join("vault");
        let vault = setup_vault(&vault_dir);
        let key = vault.derive_key(TEST_PASSWORD).unwrap();
        let plaintext = b"DB_PASSWORD=secret123";
        vault.lock(&key, ".env", plaintext).unwrap();
        let recovered = vault.unlock(&key, ".env").unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn lock_update_replaces_entry() {
        let dir = tempdir().unwrap();
        let vault_dir = dir.path().join("vault");
        let vault = setup_vault(&vault_dir);
        let key = vault.derive_key(TEST_PASSWORD).unwrap();
        vault.lock(&key, ".env", b"v1").unwrap();
        vault.lock(&key, ".env", b"v2").unwrap();
        let snap = vault.snapshot().unwrap();
        assert_eq!(snap.entries.len(), 1);
        let data = vault.unlock(&key, ".env").unwrap();
        assert_eq!(data, b"v2");
    }

    #[test]
    fn remove_drops_entry_from_snapshot() {
        let dir = tempdir().unwrap();
        let vault_dir = dir.path().join("vault");
        let vault = setup_vault(&vault_dir);
        let key = vault.derive_key(TEST_PASSWORD).unwrap();
        vault.lock(&key, ".env", b"secret").unwrap();
        vault.remove(&key, ".env").unwrap();
        let snap = vault.snapshot().unwrap();
        assert!(snap.entries.is_empty());
    }

    #[test]
    fn verify_passes_for_valid_vault() {
        let dir = tempdir().unwrap();
        let vault_dir = dir.path().join("vault");
        let vault = setup_vault(&vault_dir);
        let key = vault.derive_key(TEST_PASSWORD).unwrap();
        vault.lock(&key, ".env", b"data").unwrap();
        assert!(vault.verify(&key).is_ok());
    }

    #[test]
    fn rotate_key_re_encrypts_blobs() {
        let dir = tempdir().unwrap();
        let vault_dir = dir.path().join("vault");
        let vault = setup_vault(&vault_dir);
        let old_key = vault.derive_key(TEST_PASSWORD).unwrap();
        vault.lock(&old_key, ".env", b"rotate me").unwrap();

        let new_key = [99u8; 32];
        vault.rotate_key(&old_key, &new_key, "new-key-id").unwrap();

        let data = vault.unlock(&new_key, ".env").unwrap();
        assert_eq!(data, b"rotate me");
    }
}
