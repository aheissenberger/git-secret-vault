use std::path::Path;
use serde::{Deserialize, Serialize};
use crate::error::{Result, VaultError};
use crate::vault::event_log::{Event, Op};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    pub entry_id: String,
    pub label: String,
    pub content_hash: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: u32,
    pub generated_at: String,
    pub entries: Vec<SnapshotEntry>,
}

fn snapshot_path(vault_dir: &Path) -> std::path::PathBuf {
    vault_dir.join("index").join("snapshot.json")
}

pub fn rebuild_snapshot(events: &[Event]) -> Snapshot {
    use std::collections::HashMap;

    struct EntryState {
        label: String,
        content_hash: String,
        key_id: String,
    }
    let mut state: HashMap<String, EntryState> = HashMap::new();

    for event in events {
        match event.op {
            Op::Add | Op::Update | Op::Rotate => {
                if let Some(hash) = &event.content_hash {
                    let existing_label = state.get(&event.entry_id)
                        .map(|s| s.label.clone())
                        .unwrap_or_default();
                    state.insert(event.entry_id.clone(), EntryState {
                        label: event.label.clone().unwrap_or(existing_label),
                        content_hash: hash.clone(),
                        key_id: event.key_id.clone(),
                    });
                }
            }
            Op::Remove => {
                state.remove(&event.entry_id);
            }
        }
    }

    let mut entries: Vec<SnapshotEntry> = state.into_iter().map(|(entry_id, s)| {
        SnapshotEntry {
            entry_id,
            label: s.label,
            content_hash: s.content_hash,
            key_id: s.key_id,
        }
    }).collect();
    entries.sort_by(|a, b| a.entry_id.cmp(&b.entry_id));

    Snapshot {
        version: 1,
        generated_at: chrono::Utc::now().to_rfc3339(),
        entries,
    }
}

pub fn save_snapshot(vault_dir: &Path, snapshot: &Snapshot) -> Result<()> {
    let path = snapshot_path(vault_dir);
    let tmp = vault_dir.join("index").join("snapshot.json.tmp");
    let data = serde_json::to_vec_pretty(snapshot).map_err(VaultError::Json)?;
    std::fs::write(&tmp, &data).map_err(VaultError::Io)?;
    std::fs::rename(&tmp, &path).map_err(VaultError::Io)?;
    Ok(())
}

pub fn load_snapshot(vault_dir: &Path) -> Result<Snapshot> {
    let path = snapshot_path(vault_dir);
    let data = std::fs::read(&path).map_err(VaultError::Io)?;
    serde_json::from_slice(&data).map_err(VaultError::Json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::event_log::{Event, Op};
    use tempfile::tempdir;

    fn setup(dir: &std::path::Path) {
        std::fs::create_dir_all(dir.join("index")).unwrap();
    }

    fn make_add_event(entry_id: &str, label: &str, hash: &str) -> Event {
        Event {
            ts: "2024-01-01T00:00:00Z".to_owned(),
            op: Op::Add,
            entry_id: entry_id.to_owned(),
            label: Some(label.to_owned()),
            content_hash: Some(hash.to_owned()),
            key_id: "key-1".to_owned(),
        }
    }

    fn make_remove_event(entry_id: &str) -> Event {
        Event {
            ts: "2024-01-01T01:00:00Z".to_owned(),
            op: Op::Remove,
            entry_id: entry_id.to_owned(),
            label: None,
            content_hash: None,
            key_id: "key-1".to_owned(),
        }
    }

    #[test]
    fn rebuild_snapshot_from_add_events() {
        let events = vec![
            make_add_event("id-1", ".env", "hash-1"),
            make_add_event("id-2", "secrets.toml", "hash-2"),
        ];
        let snap = rebuild_snapshot(&events);
        assert_eq!(snap.entries.len(), 2);
        assert_eq!(snap.entries[0].entry_id, "id-1");
        assert_eq!(snap.entries[0].label, ".env");
        assert_eq!(snap.entries[1].entry_id, "id-2");
    }

    #[test]
    fn rebuild_snapshot_remove_drops_entry() {
        let events = vec![
            make_add_event("id-1", ".env", "hash-1"),
            make_remove_event("id-1"),
        ];
        let snap = rebuild_snapshot(&events);
        assert!(snap.entries.is_empty());
    }

    #[test]
    fn save_and_load_snapshot() {
        let dir = tempdir().unwrap();
        setup(dir.path());
        let snap = Snapshot {
            version: 1,
            generated_at: "2024-01-01T00:00:00Z".to_owned(),
            entries: vec![SnapshotEntry {
                entry_id: "id-1".to_owned(),
                label: ".env".to_owned(),
                content_hash: "abc123".to_owned(),
                key_id: "key-1".to_owned(),
            }],
        };
        save_snapshot(dir.path(), &snap).unwrap();
        let loaded = load_snapshot(dir.path()).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].label, ".env");
    }
}
