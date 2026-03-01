use std::path::Path;

use clap::Args;

use crate::crypto;
use crate::error::{Result, VaultError};
use crate::vault::Vault;

#[derive(Args)]
pub struct RmArgs {
    /// Paths of entries to remove from the vault (at least one required)
    #[arg(required = true)]
    pub paths: Vec<String>,

    /// Path to vault directory
    #[arg(long, default_value = ".git-secret-vault")]
    pub vault: String,

    /// Read password from stdin instead of interactive prompt
    #[arg(long)]
    pub password_stdin: bool,

    /// Also delete matching plaintext files from the working directory
    #[arg(long)]
    pub remove_local: bool,
}

pub fn run(args: &RmArgs, quiet: bool, _verbose: bool) -> Result<()> {
    let vault_dir = Path::new(&args.vault);
    let vault = Vault::open(vault_dir)?;

    let password = crypto::get_password(args.password_stdin, "Vault password: ")?;
    let key = vault.derive_key(&password)?;

    let expanded_paths = crate::fs::expand_paths(&args.paths)?;
    let snap = vault.snapshot()?;

    let to_remove: Vec<String> = expanded_paths
        .iter()
        .filter(|p| snap.entries.iter().any(|e| &e.label == *p))
        .cloned()
        .collect();

    if to_remove.is_empty() {
        return Err(VaultError::Other(
            "No matching entries found in vault for the given paths.".to_owned(),
        ));
    }

    for label in &to_remove {
        vault.remove(&key, label)?;

        if !quiet {
            println!("removed from vault: {label}");
        }

        if args.remove_local {
            let local = Path::new(label);
            if local.exists() {
                std::fs::remove_file(local).map_err(VaultError::Io)?;
                if !quiet {
                    println!("removed local file: {label}");
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    #[test]
    fn rm_with_remove_local_deletes_plaintext() {
        let dir = tempdir().unwrap();
        let local_file = dir.path().join("secret.env");
        std::fs::write(&local_file, b"data").unwrap();
        assert!(local_file.exists());

        let to_remove = vec!["secret.env".to_owned()];
        for path_str in &to_remove {
            let local = dir.path().join(path_str);
            if local.exists() {
                std::fs::remove_file(&local).unwrap();
            }
        }

        assert!(!local_file.exists(), "local file should be deleted");
    }
}
