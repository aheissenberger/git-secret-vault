// Remove vault entries (FR-021).

use std::path::Path;
use clap::Args;
use crate::crypto;
use crate::error::{Result, VaultError};
use crate::vault::Vault;

#[derive(Args)]
pub struct RmArgs {
    /// Labels of entries to remove from the vault (at least one required)
    #[arg(required = true)]
    pub paths: Vec<String>,

    /// Path to vault directory
    #[arg(long, default_value = ".git-secret-vault")]
    pub vault_dir: String,

    /// Read password from stdin instead of interactive prompt
    #[arg(long)]
    pub password_stdin: bool,

    /// Also delete matching plaintext files from the working directory
    #[arg(long)]
    pub remove_local: bool,
}

pub fn run(args: &RmArgs, quiet: bool, _verbose: bool) -> Result<()> {
    let vault_dir = Path::new(&args.vault_dir);
    if !vault_dir.join("vault.meta.json").exists() {
        return Err(VaultError::VaultNotFound(vault_dir.to_path_buf()));
    }

    let vault = Vault::open(vault_dir)?;
    let password = crypto::get_password(args.password_stdin, "Vault password: ")?;
    let key = vault.derive_key(&password)?;

    let snapshot = vault.snapshot()?;
    let available: Vec<&str> = snapshot.entries.iter().map(|e| e.label.as_str()).collect();

    let mut removed = 0usize;
    for label in &args.paths {
        if !available.contains(&label.as_str()) {
            if !quiet {
                eprintln!("warning: entry not found in vault: {label}");
            }
            continue;
        }
        vault.remove(&key, label)?;
        if args.remove_local {
            let local = std::env::current_dir().map_err(VaultError::Io)?.join(label);
            if local.exists() {
                std::fs::remove_file(&local).map_err(VaultError::Io)?;
                if !quiet { println!("removed local: {label}"); }
            }
        }
        if !quiet { println!("removed: {label}"); }
        removed += 1;
    }

    if removed == 0 {
        return Err(VaultError::Other("no matching entries found in vault".to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_vault_with_entry(dir: &std::path::Path, password: &str, label: &str, content: &[u8]) -> Vault {
        let vault = Vault::init(dir, password).unwrap();
        let key = vault.derive_key(password).unwrap();
        vault.lock(&key, label, content).unwrap();
        vault
    }

    #[test]
    fn rm_existing_entry_succeeds() {
        let dir = tempdir().unwrap();
        make_vault_with_entry(dir.path(), "pw", "sec.env", b"secret");
        let args = RmArgs {
            paths: vec!["sec.env".to_owned()],
            vault_dir: dir.path().to_str().unwrap().to_owned(),
            password_stdin: false,
            remove_local: false,
        };
        // Can't call run() directly without tty for password prompt; test the vault API
        let vault = Vault::open(dir.path()).unwrap();
        let key = vault.derive_key("pw").unwrap();
        vault.remove(&key, "sec.env").unwrap();
        let snap = vault.snapshot().unwrap();
        assert!(snap.entries.is_empty());
    }
}
