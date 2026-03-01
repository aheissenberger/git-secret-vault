// Encrypted manifest stored as a ZIP entry inside the vault (FR-004).

use chrono::Utc;
use serde::{Deserialize, Serialize};

pub const MANIFEST_ENTRY_NAME: &str = "manifest.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Canonical relative path of the secret file.
    pub path: String,
    pub size: u64,
    pub mtime: String,
    pub sha256: String,
    /// POSIX mode bits (e.g. 0o600 = 384). None on non-POSIX systems.
    pub mode: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub vault_uuid: String,
    pub format_version: String,
    pub created_at: String,
    pub updated_at: String,
    pub entries: Vec<ManifestEntry>,
}

impl Manifest {
    pub fn new(vault_uuid: &str) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            vault_uuid: vault_uuid.to_owned(),
            format_version: "1".to_owned(),
            created_at: now.clone(),
            updated_at: now,
            entries: Vec::new(),
        }
    }

    pub fn to_json(&self) -> crate::error::Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(crate::error::VaultError::Json)
    }

    pub fn from_json(data: &[u8]) -> crate::error::Result<Self> {
        serde_json::from_slice(data).map_err(crate::error::VaultError::Json)
    }

    /// Update or insert an entry (keyed by path). Keeps entries sorted for
    /// determinism (NFR-001).
    pub fn upsert(&mut self, entry: ManifestEntry) {
        if let Some(existing) = self.entries.iter_mut().find(|e| e.path == entry.path) {
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
        self.entries.sort_by(|a, b| a.path.cmp(&b.path));
        self.updated_at = Utc::now().to_rfc3339();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(path: &str, sha256: &str) -> ManifestEntry {
        ManifestEntry {
            path: path.to_owned(),
            size: 42,
            mtime: "2026-01-01T00:00:00+00:00".to_owned(),
            sha256: sha256.to_owned(),
            mode: Some(0o600),
        }
    }

    #[test]
    fn new_manifest_has_empty_entries() {
        let m = Manifest::new("test-uuid");
        assert_eq!(m.vault_uuid, "test-uuid");
        assert_eq!(m.format_version, "1");
        assert!(m.entries.is_empty());
    }

    #[test]
    fn upsert_inserts_new_entry() {
        let mut m = Manifest::new("u1");
        m.upsert(make_entry("a.env", "aaa"));
        assert_eq!(m.entries.len(), 1);
        assert_eq!(m.entries[0].path, "a.env");
    }

    #[test]
    fn upsert_updates_existing_entry() {
        let mut m = Manifest::new("u1");
        m.upsert(make_entry("a.env", "old"));
        m.upsert(make_entry("a.env", "new"));
        assert_eq!(m.entries.len(), 1);
        assert_eq!(m.entries[0].sha256, "new");
    }

    #[test]
    fn upsert_keeps_entries_sorted() {
        let mut m = Manifest::new("u1");
        m.upsert(make_entry("z.env", "z"));
        m.upsert(make_entry("a.env", "a"));
        m.upsert(make_entry("m.env", "m"));
        let paths: Vec<_> = m.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["a.env", "m.env", "z.env"]);
    }

    #[test]
    fn json_round_trip() {
        let mut m = Manifest::new("round-trip-uuid");
        m.upsert(make_entry("secrets/db.env", "deadbeef"));
        let json = m.to_json().unwrap();
        let restored = Manifest::from_json(&json).unwrap();
        assert_eq!(restored.vault_uuid, "round-trip-uuid");
        assert_eq!(restored.entries.len(), 1);
        assert_eq!(restored.entries[0].path, "secrets/db.env");
        assert_eq!(restored.entries[0].sha256, "deadbeef");
    }

    #[test]
    fn from_json_rejects_invalid_json() {
        assert!(Manifest::from_json(b"not json").is_err());
    }
}
