use std::path::Path;
use serde::{Deserialize, Serialize};
use crate::error::{Result, VaultError};
use crate::fs::atomic_write;

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
    pub salt: String, // hex-encoded 16-byte salt
}

impl VaultMeta {
    pub fn new(salt: &[u8; 16]) -> Self {
        Self {
            version: 1,
            crypto_suite: "xchacha20-poly1305".to_owned(),
            kdf: "argon2id".to_owned(),
            kdf_params: KdfParams { m_cost: 65536, t_cost: 3, p_cost: 4 },
            key_ids: vec![crate::crypto::generate_key_id()],
            salt: hex::encode(salt),
        }
    }

    pub fn salt_bytes(&self) -> Result<[u8; 16]> {
        let bytes = hex::decode(&self.salt)
            .map_err(|e| VaultError::Other(format!("invalid salt hex: {e}")))?;
        bytes.try_into().map_err(|_| VaultError::Other("salt must be 16 bytes".to_owned()))
    }

    pub fn load(vault_dir: &Path) -> Result<Self> {
        let path = vault_dir.join("vault.meta.json");
        let data = std::fs::read(&path).map_err(VaultError::Io)?;
        serde_json::from_slice(&data).map_err(|e| VaultError::Other(format!("meta parse: {e}")))
    }

    pub fn save(&self, vault_dir: &Path) -> Result<()> {
        let path = vault_dir.join("vault.meta.json");
        let data = serde_json::to_vec_pretty(self)
            .map_err(|e| VaultError::Other(format!("meta serialize: {e}")))?;
        atomic_write(&path, &data)
    }
}
