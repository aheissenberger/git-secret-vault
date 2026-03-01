use std::path::Path;

use clap::Args;
use serde_json::json;

use crate::crypto;
use crate::error::{Result, VaultError};
use crate::vault::Vault;

#[derive(Args)]
pub struct VerifyArgs {
    /// Path to vault directory
    #[arg(long, default_value = ".git-secret-vault")]
    pub vault: String,

    /// Read password from stdin instead of interactive prompt
    #[arg(long)]
    pub password_stdin: bool,

    /// Output machine-readable JSON summary
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &VerifyArgs, quiet: bool, verbose: bool) -> Result<()> {
    let vault_dir = Path::new(&args.vault);
    let vault = Vault::open(vault_dir)?;

    let password = crypto::get_password(args.password_stdin, "Vault password: ")?;
    let key = vault.derive_key(&password)?;

    let snap = vault.snapshot()?;

    let mut any_failed = false;
    let mut results: Vec<serde_json::Value> = Vec::new();

    for entry in &snap.entries {
        let (status, hash) = match crate::vault::blob::load_blob(&vault.dir, &key, &entry.content_hash) {
            Ok(data) => {
                let actual = crate::crypto::content_hash(&data);
                if actual == entry.content_hash {
                    ("ok", entry.content_hash.clone())
                } else {
                    any_failed = true;
                    ("corrupt", entry.content_hash.clone())
                }
            }
            Err(_) => {
                any_failed = true;
                ("missing", entry.content_hash.clone())
            }
        };

        if !quiet && !args.json {
            if verbose {
                println!("{}: {} [sha256:{}]", entry.label, status, hash);
            } else {
                println!("{}: {} [{}]", entry.label, status, &hash[..8.min(hash.len())]);
            }
        }

        results.push(json!({
            "path": entry.label,
            "sha256": hash,
            "status": status,
        }));
    }

    if args.json {
        let out = json!({
            "entries": results,
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
    use tempfile::tempdir;
    use crate::vault::Vault;

    const TEST_PASSWORD: &str = "correct-horse-battery-staple-42!";

    #[test]
    fn verify_empty_vault_succeeds() {
        let dir = tempdir().unwrap();
        let vault_dir = dir.path().join("vault");
        let vault = Vault::init(&vault_dir, TEST_PASSWORD).unwrap();
        let key = vault.derive_key(TEST_PASSWORD).unwrap();
        assert!(vault.verify(&key).is_ok());
    }
}
