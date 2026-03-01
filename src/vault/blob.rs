use std::path::{Path, PathBuf};
use crate::crypto;
use crate::error::{Result, VaultError};

pub fn blob_path(vault_dir: &Path, content_hash: &str) -> PathBuf {
    vault_dir.join("blobs").join(format!("{content_hash}.enc"))
}

pub fn store_blob(vault_dir: &Path, key: &[u8; 32], plaintext: &[u8]) -> Result<String> {
    let hash = crypto::content_hash(plaintext);
    let path = blob_path(vault_dir, &hash);
    if !path.exists() {
        let encrypted = crypto::encrypt_blob(key, plaintext)?;
        std::fs::write(&path, &encrypted).map_err(VaultError::Io)?;
    }
    Ok(hash)
}

/// Like `store_blob`, but always re-encrypts even if a blob with the same
/// content hash already exists. Used during key rotation so that existing
/// blobs are re-encrypted under the new key.
pub fn store_blob_force(vault_dir: &Path, key: &[u8; 32], plaintext: &[u8]) -> Result<String> {
    let hash = crypto::content_hash(plaintext);
    let path = blob_path(vault_dir, &hash);
    let encrypted = crypto::encrypt_blob(key, plaintext)?;
    std::fs::write(&path, &encrypted).map_err(VaultError::Io)?;
    Ok(hash)
}

pub fn load_blob(vault_dir: &Path, key: &[u8; 32], content_hash: &str) -> Result<Vec<u8>> {
    let path = blob_path(vault_dir, content_hash);
    let data = std::fs::read(&path).map_err(VaultError::Io)?;
    crypto::decrypt_blob(key, &data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_key() -> [u8; 32] { [42u8; 32] }

    #[test]
    fn store_and_load_round_trip() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("blobs")).unwrap();
        let key = test_key();
        let plaintext = b"hello vault";
        let hash = store_blob(dir.path(), &key, plaintext).unwrap();
        let recovered = load_blob(dir.path(), &key, &hash).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn store_is_idempotent() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("blobs")).unwrap();
        let key = test_key();
        let plaintext = b"idempotent";
        let hash1 = store_blob(dir.path(), &key, plaintext).unwrap();
        let hash2 = store_blob(dir.path(), &key, plaintext).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("blobs")).unwrap();
        let key = test_key();
        let bad_key = [0u8; 32];
        let hash = store_blob(dir.path(), &key, b"secret").unwrap();
        assert!(load_blob(dir.path(), &bad_key, &hash).is_err());
    }
}
