use std::path::Path;
use serde::{Deserialize, Serialize};
use crate::error::{Result, VaultError};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    Add,
    Update,
    Remove,
    Rotate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub ts: String,
    pub op: Op,
    pub entry_id: String,
    pub label: Option<String>,
    pub content_hash: Option<String>,
    pub key_id: String,
}

fn events_path(vault_dir: &Path) -> std::path::PathBuf {
    vault_dir.join("index").join("events.jsonl")
}

pub fn append_event(vault_dir: &Path, event: &Event) -> Result<()> {
    use std::io::Write;
    let path = events_path(vault_dir);
    let mut line = serde_json::to_string(event).map_err(VaultError::Json)?;
    line.push('\n');
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(VaultError::Io)?;
    file.write_all(line.as_bytes()).map_err(VaultError::Io)?;
    Ok(())
}

pub fn read_events(vault_dir: &Path) -> Result<Vec<Event>> {
    let path = events_path(vault_dir);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = std::fs::read_to_string(&path).map_err(VaultError::Io)?;
    data.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(VaultError::Json))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn setup(dir: &std::path::Path) {
        std::fs::create_dir_all(dir.join("index")).unwrap();
    }

    fn make_event(op: Op, entry_id: &str, label: Option<&str>, content_hash: Option<&str>) -> Event {
        Event {
            ts: "2024-01-01T00:00:00Z".to_owned(),
            op,
            entry_id: entry_id.to_owned(),
            label: label.map(|s| s.to_owned()),
            content_hash: content_hash.map(|s| s.to_owned()),
            key_id: "key-1".to_owned(),
        }
    }

    #[test]
    fn append_and_read_events() {
        let dir = tempdir().unwrap();
        setup(dir.path());
        let e1 = make_event(Op::Add, "uuid-1", Some(".env"), Some("hash-abc"));
        let e2 = make_event(Op::Remove, "uuid-2", None, None);
        append_event(dir.path(), &e1).unwrap();
        append_event(dir.path(), &e2).unwrap();
        let events = read_events(dir.path()).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].entry_id, "uuid-1");
        assert_eq!(events[0].op, Op::Add);
        assert_eq!(events[1].entry_id, "uuid-2");
        assert_eq!(events[1].op, Op::Remove);
        assert!(events[1].content_hash.is_none());
    }

    #[test]
    fn read_events_empty() {
        let dir = tempdir().unwrap();
        setup(dir.path());
        let events = read_events(dir.path()).unwrap();
        assert!(events.is_empty());
    }
}
