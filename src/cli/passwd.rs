// Change vault password / rotate encryption key (FR-018).

use std::path::Path;
use clap::Args;
use crate::crypto;
use crate::error::{Result, VaultError};
use crate::vault::Vault;

#[derive(Args)]
pub struct PasswdArgs {
    /// Path to vault directory
    #[arg(long, default_value = ".git-secret-vault")]
    pub vault_dir: String,

    /// Read old password from stdin
    #[arg(long)]
    pub password_stdin: bool,
}

pub fn run(args: &PasswdArgs, quiet: bool, _verbose: bool) -> Result<()> {
    let vault_dir = Path::new(&args.vault_dir);
    if !vault_dir.join("vault.meta.json").exists() {
        return Err(VaultError::VaultNotFound(vault_dir.to_path_buf()));
    }

    let vault = Vault::open(vault_dir)?;
    let old_password = crypto::get_password(args.password_stdin, "Current password: ")?;
    let old_key = vault.derive_key(&old_password)?;

    // Verify old password by attempting to decrypt one blob
    vault.verify(&old_key)?;

    let new_password = crypto::get_password(false, "New password: ")?;
    let confirm = crypto::get_password(false, "Confirm new password: ")?;
    if new_password != confirm {
        return Err(VaultError::Other("passwords do not match".to_owned()));
    }
    crypto::validate_password_strength(&new_password)?;

    vault.rotate_key(&old_key, &new_password)?;

    if !quiet {
        println!("Password changed successfully. New key ID added to vault.meta.json.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn rotate_key_changes_encryption() {
        let dir = tempdir().unwrap();
        let vault = Vault::init(dir.path(), "old-password-123").unwrap();
        let old_key = vault.derive_key("old-password-123").unwrap();
        vault.lock(&old_key, "sec.env", b"my secret").unwrap();

        vault.rotate_key(&old_key, "new-password-456").unwrap();

        // Re-open vault and verify new password works
        let vault2 = Vault::open(dir.path()).unwrap();
        let new_key = vault2.derive_key("new-password-456").unwrap();
        let plaintext = vault2.unlock(&new_key, "sec.env").unwrap();
        assert_eq!(plaintext, b"my secret");
    }
}
