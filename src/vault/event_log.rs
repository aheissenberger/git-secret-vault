use std::io::{BufRead, Write};
use std::path::Path;
use serde::{Deserialize, Serialize};
use crate::error::{Result, VaultError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Op { Add, Update, Remove, Rotate }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub ts: String,
    pub op: Op,
    pub entry_id: String,
    pub content_hash: Option<String>,
    pub key_id: String,
}

impl Event {
    pub fn now(op: Op, entry_id: String, content_hash: Option<String>, key_id: String) -> Self {
        Self { ts: chrono::Utc::now().to_rfc3339(), op, entry_id, content_hash, key_id }
    }
}

pub fn append_event(vault_dir: &Path, event: &Event) -> Result<()> {
    let path = vault_dir.join("index").join("events.jsonl");
    let line = serde_json::to_string(event)
        .map_err(|e| VaultError::Other(format!("event serialize: {e}")))?;
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&path)
        .map_err(VaultError::Io)?;
    writeln!(file, "{line}").map_err(VaultError::Io)
}

pub fn read_events(vault_dir: &Path) -> Result<Vec<Event>> {
    let path = vault_dir.join("index").join("events.jsonl");
    if !path.exists() { return Ok(vec![]); }
    let file = std::fs::File::open(&path).map_err(VaultError::Io)?;
    std::io::BufReader::new(file).lines()
        .filter(|l| l.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(true))
        .map(|l| {
            let line = l.map_err(VaultError::Io)?;
            serde_json::from_str(&line).map_err(|e| VaultError::Other(format!("event parse: {e}")))
        })
        .collect()
}
