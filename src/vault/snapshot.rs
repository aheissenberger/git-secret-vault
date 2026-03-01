use std::path::Path;
use serde::{Deserialize, Serialize};
use crate::error::{Result, VaultError};
use crate::fs::atomic_write;
use crate::vault::event_log::{Event, Op};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    pub entry_id: String,
    pub label: String,       // logical name (e.g. ".env"); stored in snapshot, not in vault.meta.json
    pub content_hash: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: u32,
    pub generated_at: String,
    pub entries: Vec<SnapshotEntry>,
}

impl Snapshot {
    pub fn find_by_label(&self, label: &str) -> Option<&SnapshotEntry> {
        self.entries.iter().find(|e| e.label == label)
    }
}

/// Replay events to build current state. Labels come from a separate label map
/// because events only store entry_id/content_hash/key_id (not labels).
/// Labels are tracked via an in-memory BTreeMap passed from the vault layer.
pub fn rebuild_snapshot(events: &[Event], labels: &std::collections::BTreeMap<String, String>) -> Snapshot {
    use std::collections::BTreeMap;
    // entry_id -> (content_hash, key_id)
    let mut state: BTreeMap<String, (String, String)> = BTreeMap::new();
    for ev in events {
        match ev.op {
            Op::Add | Op::Update | Op::Rotate => {
                if let Some(hash) = &ev.content_hash {
                    state.insert(ev.entry_id.clone(), (hash.clone(), ev.key_id.clone()));
                }
            }
            Op::Remove => { state.remove(&ev.entry_id); }
        }
    }
    let mut entries: Vec<SnapshotEntry> = state.into_iter()
        .filter_map(|(entry_id, (content_hash, key_id))| {
            labels.get(&entry_id).map(|label| SnapshotEntry {
                entry_id, label: label.clone(), content_hash, key_id,
            })
        })
        .collect();
    entries.sort_by(|a, b| a.entry_id.cmp(&b.entry_id));
    Snapshot { version: 1, generated_at: chrono::Utc::now().to_rfc3339(), entries }
}

pub fn save_snapshot(vault_dir: &Path, snapshot: &Snapshot) -> Result<()> {
    let path = vault_dir.join("index").join("snapshot.json");
    let data = serde_json::to_vec_pretty(snapshot)
        .map_err(|e| VaultError::Other(format!("snapshot serialize: {e}")))?;
    atomic_write(&path, &data)
}

pub fn load_snapshot(vault_dir: &Path) -> Result<Snapshot> {
    let path = vault_dir.join("index").join("snapshot.json");
    if !path.exists() {
        return Ok(Snapshot { version: 1, generated_at: String::new(), entries: vec![] });
    }
    let data = std::fs::read(&path).map_err(VaultError::Io)?;
    serde_json::from_slice(&data).map_err(|e| VaultError::Other(format!("snapshot parse: {e}")))
}
