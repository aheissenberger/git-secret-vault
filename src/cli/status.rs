// Show vault status (FR-022, FR-023).

use std::path::Path;

use clap::Args;
use serde_json::json;

use crate::crypto;
use crate::error::{Result, VaultError};
use crate::vault::Vault;

#[derive(Args)]
pub struct StatusArgs {
    /// Path to vault directory
    #[arg(long, default_value = ".git-secret-vault")]
    pub vault_dir: String,

    /// Read password from stdin for authenticated verification mode
    #[arg(long)]
    pub password_stdin: bool,

    /// Output machine-readable JSON
    #[arg(long)]
    pub json: bool,

    /// Exit with code 1 if any tracked entries differ from vault (requires password)
    #[arg(long)]
    pub fail_if_dirty: bool,

    /// Do not prompt interactively; use --password-stdin or VAULT_PASSWORD only
    #[arg(long)]
    pub no_prompt: bool,
}

pub fn run(args: &StatusArgs, quiet: bool, _verbose: bool) -> Result<()> {
    let vault_dir = Path::new(&args.vault_dir);
    let meta_path = vault_dir.join("vault.meta.json");

    if !meta_path.exists() {
        return Err(VaultError::VaultNotFound(vault_dir.to_path_buf()));
    }

    let vault = Vault::open(vault_dir)?;
    let has_password_source =
        args.password_stdin || args.no_prompt || std::env::var("VAULT_PASSWORD").is_ok();

    if has_password_source {
        return run_authenticated(args, &vault, quiet);
    }

    if args.fail_if_dirty {
        return Err(VaultError::Other(
            "--fail-if-dirty requires --password-stdin or VAULT_PASSWORD".to_owned(),
        ));
    }

    // Privacy-preserving summary (no password needed).
    let snapshot = vault.snapshot()?;
    if args.json {
        let out = json!({
            "crypto_suite": vault.meta.crypto_suite,
            "entry_count": snapshot.entries.len(),
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else if !quiet {
        println!("Crypto:  {}", vault.meta.crypto_suite);
        println!("Entries: {}", snapshot.entries.len());
    }
    Ok(())
}

fn run_authenticated(args: &StatusArgs, vault: &Vault, quiet: bool) -> Result<()> {
    let password = crypto::get_password_no_prompt(args.password_stdin)?;
    let key = vault.derive_key(&password)?;
    let snapshot = vault.snapshot()?;
    let cwd = std::env::current_dir().map_err(VaultError::Io)?;

    let mut results: Vec<serde_json::Value> = Vec::new();
    let mut dirty_count = 0usize;

    for entry in &snapshot.entries {
        let local = cwd.join(&entry.label);
        let state = if local.exists() {
            let data = std::fs::read(&local).map_err(VaultError::Io)?;
            if crate::crypto::content_hash(&data) == entry.content_hash {
                "up-to-date"
            } else {
                dirty_count += 1;
                "stale"
            }
        } else {
            dirty_count += 1;
            "missing"
        };
        results.push(json!({ "label": entry.label, "state": state }));
    }

    if args.json {
        let out = json!({ "entry_count": snapshot.entries.len(), "entries": results });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else if !quiet {
        for r in &results {
            println!("{}: {}", r["label"].as_str().unwrap_or(""), r["state"].as_str().unwrap_or(""));
        }
    }

    if args.fail_if_dirty && dirty_count > 0 {
        return Err(VaultError::Other(format!("vault is dirty: {dirty_count} entries differ")));
    }
    let _ = key; // key accepted for API symmetry; hash comparison uses plaintext hashes
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn no_meta_json_returns_vault_not_found() {
        let dir = tempdir().unwrap();
        let args = StatusArgs {
            vault_dir: dir.path().to_str().unwrap().to_owned(),
            password_stdin: false, no_prompt: false, json: false, fail_if_dirty: false,
        };
        let result = run(&args, true, false);
        assert!(matches!(result, Err(VaultError::VaultNotFound(_))));
    }

    #[test]
    fn fail_if_dirty_without_password_source_is_error() {
        let dir = tempdir().unwrap();
        // Create minimal vault structure
        std::fs::create_dir_all(dir.path().join("blobs")).unwrap();
        std::fs::create_dir_all(dir.path().join("index")).unwrap();
        let vault = Vault::init(dir.path(), "pw").unwrap();
        let _ = vault;
        let args = StatusArgs {
            vault_dir: dir.path().to_str().unwrap().to_owned(),
            password_stdin: false, no_prompt: false, json: false, fail_if_dirty: true,
        };
        unsafe { std::env::remove_var("VAULT_PASSWORD") };
        let result = run(&args, true, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("--fail-if-dirty"));
    }
}
