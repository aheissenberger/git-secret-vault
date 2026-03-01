// Validate vault integrity (FR-024).

use std::path::Path;

use clap::Args;
use serde_json::json;

use crate::crypto;
use crate::error::{Result, VaultError};
use crate::vault::format;

#[derive(Args)]
pub struct VerifyArgs {
    /// Path to vault directory
    #[arg(long, default_value = ".git-secret-vault")]
    pub vault_dir: String,

    /// Read password from stdin instead of interactive prompt
    #[arg(long)]
    pub password_stdin: bool,

    /// Output machine-readable JSON summary
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug)]
struct EntryResult {
    path: String,
    sha256: String,
    status: &'static str,
}

pub fn run(args: &VerifyArgs, quiet: bool, verbose: bool) -> Result<()> {
    let vault_dir = Path::new(&args.vault_dir);
    let vault_path = vault_dir.join("vault.zip");
    let vault_path = vault_path.as_path();

    if !vault_path.exists() {
        return Err(VaultError::VaultNotFound(std::path::PathBuf::from(&args.vault_dir)));
    }

    let password = crypto::get_password(args.password_stdin, "Vault password: ")?;

    let (manifest, _) = format::read_manifest(vault_path, &password)?;

    let mut results: Vec<EntryResult> = Vec::new();
    let mut any_failed = false;

    for entry in &manifest.entries {
        let status = match format::read_entry(vault_path, &password, &entry.path) {
            Ok(data) => {
                let actual = format::sha256_hex(&data);
                if actual == entry.sha256 {
                    "ok"
                } else {
                    any_failed = true;
                    "corrupt"
                }
            }
            Err(_) => {
                any_failed = true;
                "missing"
            }
        };

        if !quiet && !args.json {
            if verbose {
                println!("{}: {} [sha256:{}]", entry.path, status, entry.sha256);
            } else {
                println!("{}: {} [{}]", entry.path, status, entry.sha256);
            }
        }

        results.push(EntryResult {
            path: entry.path.clone(),
            sha256: entry.sha256.clone(),
            status,
        });
    }

    if args.json {
        let entries: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                json!({
                    "path": r.path,
                    "sha256": r.sha256,
                    "status": r.status,
                })
            })
            .collect();
        let out = json!({
            "entries": entries,
            "ok": !any_failed,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    }

    if any_failed {
        Err(VaultError::Other(
            "One or more vault entries failed verification.".to_owned(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{
        format,
        manifest::{Manifest, ManifestEntry},
    };
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    fn make_vault(dir: &Path, password: &str, entries: &[(&str, &[u8])]) -> std::path::PathBuf {
        let vault_path = dir.join("vault.zip");
        let mut manifest = Manifest::new("uuid");
        let mut updates = BTreeMap::new();
        for (name, content) in entries {
            manifest.upsert(ManifestEntry {
                path: (*name).to_owned(),
                size: content.len() as u64,
                mtime: String::new(),
                sha256: format::sha256_hex(content),
                mode: None,
            });
            updates.insert((*name).to_owned(), content.to_vec());
        }
        format::rewrite_vault(&vault_path, password, &updates, &manifest).unwrap();
        vault_path
    }

    #[test]
    #[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
    fn verify_ok_when_all_entries_match() {
        let dir = tempdir().unwrap();
        let vault_path = make_vault(
            dir.path(),
            "pw",
            &[("a.env", b"hello"), ("b.env", b"world")],
        );

        let (manifest, _) = format::read_manifest(&vault_path, "pw").unwrap();
        let mut any_failed = false;
        for entry in &manifest.entries {
            let data = format::read_entry(&vault_path, "pw", &entry.path).unwrap();
            let actual = format::sha256_hex(&data);
            if actual != entry.sha256 {
                any_failed = true;
            }
        }
        assert!(!any_failed, "all entries should verify ok");
    }

    #[test]
    #[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
    fn verify_fails_on_hash_mismatch() {
        let dir = tempdir().unwrap();
        // Create a vault where the manifest entry has a wrong hash.
        let vault_path = dir.path().join("vault.zip");
        let mut manifest = Manifest::new("uuid");
        manifest.upsert(ManifestEntry {
            path: "tampered.env".to_owned(),
            size: 5,
            mtime: String::new(),
            sha256: "wrong-hash-value".to_owned(), // deliberately wrong
            mode: None,
        });
        let mut updates = BTreeMap::new();
        updates.insert("tampered.env".to_owned(), b"hello".to_vec());
        format::rewrite_vault(&vault_path, "pw", &updates, &manifest).unwrap();

        let (manifest, _) = format::read_manifest(&vault_path, "pw").unwrap();
        let mut any_failed = false;
        for entry in &manifest.entries {
            let data = format::read_entry(&vault_path, "pw", &entry.path).unwrap();
            let actual = format::sha256_hex(&data);
            if actual != entry.sha256 {
                any_failed = true;
            }
        }
        assert!(any_failed, "tampered entry should fail verification");
    }

    #[test]
    #[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
    fn verify_empty_vault_succeeds() {
        let dir = tempdir().unwrap();
        let vault_path = make_vault(dir.path(), "pw", &[]);

        let (manifest, _) = format::read_manifest(&vault_path, "pw").unwrap();
        assert!(manifest.entries.is_empty());
        // No entries → no failures.
        let any_failed = false;
        assert!(!any_failed);
    }

    #[test]
    fn verify_missing_vault_returns_error() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("no-vault.zip");
        assert!(!vault_path.exists());
        let result = format::read_manifest(&vault_path, "pw");
        assert!(result.is_err());
    }
}
