// Outer index: UUID, version, timestamp, entry count – no filenames (FR-003, SEC-001).

use std::path::Path;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::{Result, VaultError};
use crate::fs::atomic_write;

const FORMAT_VERSION: &str = "1";

#[derive(Debug, Serialize, Deserialize)]
pub struct OuterIndex {
    pub uuid: String,
    pub format_version: String,
    pub updated_at: String,
    pub entry_count: usize,
    /// SHA-256 hex of the manifest ciphertext – integrity marker only.
    pub integrity_marker: String,
}

impl OuterIndex {
    pub fn new(uuid: &str, entry_count: usize, integrity_marker: String) -> Self {
        Self {
            uuid: uuid.to_owned(),
            format_version: FORMAT_VERSION.to_owned(),
            updated_at: Utc::now().to_rfc3339(),
            entry_count,
            integrity_marker,
        }
    }

    pub fn read(path: &Path) -> Result<Self> {
        let data = std::fs::read(path).map_err(VaultError::Io)?;
        serde_json::from_slice(&data).map_err(VaultError::Json)
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_vec_pretty(self).map_err(VaultError::Json)?;
        atomic_write(path, &data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn new_index_has_expected_fields() {
        let idx = OuterIndex::new("my-uuid", 3, "abc123".to_owned());
        assert_eq!(idx.uuid, "my-uuid");
        assert_eq!(idx.format_version, "1");
        assert_eq!(idx.entry_count, 3);
        assert_eq!(idx.integrity_marker, "abc123");
    }

    #[test]
    fn write_read_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".git-secret-vault.index.json");

        let idx = OuterIndex::new("round-trip", 7, "marker42".to_owned());
        idx.write(&path).unwrap();

        let restored = OuterIndex::read(&path).unwrap();
        assert_eq!(restored.uuid, "round-trip");
        assert_eq!(restored.entry_count, 7);
        assert_eq!(restored.integrity_marker, "marker42");
        assert_eq!(restored.format_version, "1");
    }

    #[test]
    fn read_missing_file_returns_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent.index");
        assert!(OuterIndex::read(&path).is_err());
    }

    #[test]
    fn index_json_contains_no_filenames() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".idx");
        let idx = OuterIndex::new("u1", 2, "h1".to_owned());
        idx.write(&path).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        // Confirm none of these secret-like strings appear in the index.
        assert!(!raw.contains("secret"));
        assert!(!raw.contains(".env"));
        assert!(!raw.contains("password"));
        // Only expected fields present.
        assert!(raw.contains("uuid"));
        assert!(raw.contains("entry_count"));
        assert!(raw.contains("integrity_marker"));
    }
}
