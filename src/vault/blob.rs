use std::path::{Path, PathBuf};
use crate::crypto::{content_hash, decrypt_blob, encrypt_blob};
use crate::error::{Result, VaultError};
use crate::fs::atomic_write;

pub fn blob_path(vault_dir: &Path, content_hash: &str) -> PathBuf {
    vault_dir.join("blobs").join(format!("{content_hash}.enc"))
}

pub fn store_blob(vault_dir: &Path, key: &[u8; 32], plaintext: &[u8]) -> Result<String> {
    let hash = content_hash(plaintext);
    let path = blob_path(vault_dir, &hash);
    if !path.exists() {
        let encrypted = encrypt_blob(key, plaintext)?;
        atomic_write(&path, &encrypted)?;
    }
    Ok(hash)
}

pub fn load_blob(vault_dir: &Path, key: &[u8; 32], content_hash: &str) -> Result<Vec<u8>> {
    let path = blob_path(vault_dir, content_hash);
    let data = std::fs::read(&path).map_err(VaultError::Io)?;
    decrypt_blob(key, &data)
}
