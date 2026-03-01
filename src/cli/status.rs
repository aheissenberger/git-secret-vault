use std::path::Path;

use clap::Args;
use serde_json::json;

use crate::crypto;
use crate::error::{Result, VaultError};
use crate::vault::{format, index::OuterIndex};

#[derive(Args)]
pub struct StatusArgs {
    /// Path to outer index file
    #[arg(long, default_value = ".git-secret-vault.index.json")]
    pub index: String,

    /// Path to vault file (enables authenticated verification when provided with password)
    #[arg(long, default_value = "git-secret-vault.zip")]
    pub vault: String,

    /// Read password from stdin for authenticated verification mode
    #[arg(long)]
    pub password_stdin: bool,

    /// Output machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &StatusArgs, quiet: bool) -> Result<()> {
    let index_path = Path::new(&args.index);
    let vault_path = Path::new(&args.vault);

    if !index_path.exists() {
        return Err(VaultError::VaultNotFound(args.index.clone()));
    }

    let outer = OuterIndex::read(index_path)?;

    // Authenticated verification mode: vault exists and password supplied via stdin.
    if vault_path.exists() && args.password_stdin {
        return run_authenticated(args, &outer, vault_path, quiet);
    }

    // Privacy-preserving summary mode (no password required).
    if args.json {
        let out = json!({
            "uuid": outer.uuid,
            "format_version": outer.format_version,
            "updated_at": outer.updated_at,
            "entry_count": outer.entry_count,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else if !quiet {
        println!("Vault UUID:    {}", outer.uuid);
        println!("Format:        v{}", outer.format_version);
        println!("Last updated:  {}", outer.updated_at);
        println!("Entries:       {}", outer.entry_count);
    }

    Ok(())
}

/// Authenticated verification: decrypt manifest and verify each entry against local files.
fn run_authenticated(
    args: &StatusArgs,
    outer: &OuterIndex,
    vault_path: &Path,
    quiet: bool,
) -> Result<()> {
    let password = crypto::read_password_stdin()?;
    let (manifest, _) = format::read_manifest(vault_path, &password)?;

    let cwd = std::env::current_dir().map_err(VaultError::Io)?;

    let mut results: Vec<serde_json::Value> = Vec::new();
    let mut any_stale = false;
    let mut any_missing = false;

    for entry in &manifest.entries {
        let local = cwd.join(&entry.path);
        let state = if local.exists() {
            let data = std::fs::read(&local).map_err(VaultError::Io)?;
            let local_hash = format::sha256_hex(&data);
            if local_hash == entry.sha256 {
                "up-to-date"
            } else {
                any_stale = true;
                "stale"
            }
        } else {
            any_missing = true;
            "missing"
        };

        results.push(json!({ "path": entry.path, "state": state }));

        if !quiet && !args.json {
            println!("{}: {}", entry.path, state);
        }
    }

    if args.json {
        let out = json!({
            "uuid": outer.uuid,
            "format_version": outer.format_version,
            "updated_at": outer.updated_at,
            "entry_count": outer.entry_count,
            "entries": results,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    }

    if any_stale || any_missing {
        return Err(VaultError::Other(
            "One or more vault entries are stale or missing locally.".to_owned(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::vault::{
        format,
        index::OuterIndex,
        manifest::{Manifest, ManifestEntry},
    };
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    fn setup_vault_with_entry(
        dir: &std::path::Path,
        password: &str,
        name: &str,
        content: &[u8],
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let vault_path = dir.join("vault.zip");
        let index_path = dir.join(".index.json");
        let mut manifest = Manifest::new("status-uuid");
        manifest.upsert(ManifestEntry {
            path: name.to_owned(),
            size: content.len() as u64,
            mtime: String::new(),
            sha256: format::sha256_hex(content),
            mode: None,
        });
        let mut updates = BTreeMap::new();
        updates.insert(name.to_owned(), content.to_vec());
        let marker = format::rewrite_vault(&vault_path, password, &updates, &manifest).unwrap();
        let outer = OuterIndex::new("status-uuid", 1, marker);
        outer.write(&index_path).unwrap();
        (vault_path, index_path)
    }

    #[test]
    fn status_summary_reads_outer_index() {
        let dir = tempdir().unwrap();
        let (_, index_path) = setup_vault_with_entry(dir.path(), "pw", "s.env", b"secret");
        let outer = OuterIndex::read(&index_path).unwrap();
        assert_eq!(outer.uuid, "status-uuid");
        assert_eq!(outer.entry_count, 1);
    }

    #[test]
    fn authenticated_status_detects_up_to_date_file() {
        let dir = tempdir().unwrap();
        let (vault_path, _) = setup_vault_with_entry(dir.path(), "pw", "s.env", b"secret");
        std::fs::write(dir.path().join("s.env"), b"secret").unwrap();

        let (manifest, _) = format::read_manifest(&vault_path, "pw").unwrap();
        for entry in &manifest.entries {
            let local = dir.path().join(&entry.path);
            assert!(local.exists());
            let data = std::fs::read(&local).unwrap();
            assert_eq!(format::sha256_hex(&data), entry.sha256);
        }
    }

    #[test]
    fn authenticated_status_detects_stale_file() {
        let dir = tempdir().unwrap();
        let (vault_path, _) = setup_vault_with_entry(dir.path(), "pw", "s.env", b"original");
        std::fs::write(dir.path().join("s.env"), b"modified").unwrap();

        let (manifest, _) = format::read_manifest(&vault_path, "pw").unwrap();
        for entry in &manifest.entries {
            let local = dir.path().join(&entry.path);
            let data = std::fs::read(&local).unwrap();
            let local_hash = format::sha256_hex(&data);
            assert_ne!(local_hash, entry.sha256, "stale file should have different hash");
        }
    }

    #[test]
    fn authenticated_status_detects_missing_file() {
        let dir = tempdir().unwrap();
        let (vault_path, _) = setup_vault_with_entry(dir.path(), "pw", "s.env", b"content");
        // Do NOT write local file.

        let (manifest, _) = format::read_manifest(&vault_path, "pw").unwrap();
        for entry in &manifest.entries {
            let local = dir.path().join(&entry.path);
            assert!(!local.exists(), "local file should be missing");
        }
    }
}
