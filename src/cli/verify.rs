// Validate vault integrity (FR-024).

use std::path::Path;

use clap::Args;

use crate::crypto;
use crate::error::{Result, VaultError};
use crate::vault::Vault;

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

pub fn run(args: &VerifyArgs, quiet: bool, _verbose: bool) -> Result<()> {
    let vault_dir = Path::new(&args.vault_dir);

    let vault = Vault::open(vault_dir)?;
    let password = crypto::get_password(args.password_stdin, "Vault password: ")?;
    let key = vault.derive_key(&password)?;

    vault.verify(&key)?;

    if !quiet {
        if args.json {
            println!("{{\"ok\":true}}");
        } else {
            println!("Vault integrity verified.");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Vault;
    use tempfile::tempdir;

    // Tests for new API: see src/vault/mod.rs

    #[test]
    fn verify_ok_when_all_entries_match() {
        let dir = tempdir().unwrap();
        let vault = Vault::init(dir.path(), "pw").unwrap();
        let key = vault.derive_key("pw").unwrap();
        vault.lock(&key, "a.env", b"hello").unwrap();
        vault.lock(&key, "b.env", b"world").unwrap();
        assert!(vault.verify(&key).is_ok());
    }

    #[test]
    fn verify_empty_vault_succeeds() {
        let dir = tempdir().unwrap();
        let vault = Vault::init(dir.path(), "pw").unwrap();
        let key = vault.derive_key("pw").unwrap();
        assert!(vault.verify(&key).is_ok());
    }

    #[test]
    fn verify_missing_vault_returns_error() {
        let dir = tempdir().unwrap();
        let nonexistent = dir.path().join("no-vault");
        let result = Vault::open(&nonexistent);
        assert!(result.is_err());
    }
}
