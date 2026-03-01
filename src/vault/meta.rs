use std::path::Path;
use serde::{Deserialize, Serialize};
use crate::error::{Result, VaultError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMeta {
    pub version: u32,
    pub crypto_suite: String,
    pub kdf: String,
    pub kdf_params: KdfParams,
    pub key_ids: Vec<String>,
    pub salt: String,
}

impl VaultMeta {
    pub fn new(salt: &[u8]) -> Self {
        Self {
            version: 1,
            crypto_suite: "xchacha20-poly1305".to_owned(),
            kdf: "argon2id".to_owned(),
            kdf_params: KdfParams { m_cost: 65536, t_cost: 3, p_cost: 4 },
            key_ids: Vec::new(),
            salt: hex::encode(salt),
        }
    }

    pub fn load(vault_dir: &Path) -> Result<Self> {
        let path = vault_dir.join("vault.meta.json");
        let data = std::fs::read(&path).map_err(VaultError::Io)?;
        serde_json::from_slice(&data).map_err(VaultError::Json)
    }

    pub fn save(&self, vault_dir: &Path) -> Result<()> {
        let path = vault_dir.join("vault.meta.json");
        let tmp = vault_dir.join("vault.meta.json.tmp");
        let data = serde_json::to_vec_pretty(self).map_err(VaultError::Json)?;
        std::fs::write(&tmp, &data).map_err(VaultError::Io)?;
        std::fs::rename(&tmp, &path).map_err(VaultError::Io)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn new_sets_defaults() {
        let salt = [0u8; 16];
        let meta = VaultMeta::new(&salt);
        assert_eq!(meta.version, 1);
        assert_eq!(meta.crypto_suite, "xchacha20-poly1305");
        assert_eq!(meta.kdf, "argon2id");
        assert_eq!(meta.kdf_params.m_cost, 65536);
        assert_eq!(meta.kdf_params.t_cost, 3);
        assert_eq!(meta.kdf_params.p_cost, 4);
        assert!(meta.key_ids.is_empty());
        assert_eq!(meta.salt, "00000000000000000000000000000000");
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempdir().unwrap();
        let salt = [1u8; 16];
        let mut meta = VaultMeta::new(&salt);
        meta.key_ids.push("key-id-1".to_owned());
        meta.save(dir.path()).unwrap();
        let loaded = VaultMeta::load(dir.path()).unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.salt, meta.salt);
        assert_eq!(loaded.key_ids, vec!["key-id-1"]);
    }
}
