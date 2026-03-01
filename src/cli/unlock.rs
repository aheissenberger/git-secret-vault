use std::path::Path;

use clap::Args;

use crate::crypto;
use crate::error::{Result, VaultError};
use crate::fs::{safe_join, write_file};
use crate::vault::format;

#[derive(Args)]
pub struct UnlockArgs {
    /// Specific entries to unlock (unlocks all when omitted)
    pub paths: Vec<String>,

    /// Path to vault file
    #[arg(long, default_value = "git-secret-vault.zip")]
    pub vault: String,

    /// Read password from stdin instead of interactive prompt
    #[arg(long)]
    pub password_stdin: bool,

    /// Overwrite existing files without prompting
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: &UnlockArgs, quiet: bool) -> Result<()> {
    let vault_path = Path::new(&args.vault);

    if !vault_path.exists() {
        return Err(VaultError::VaultNotFound(args.vault.clone()));
    }

    let password = crypto::get_password(args.password_stdin, "Vault password: ")?;

    let (manifest, _) = format::read_manifest(vault_path, &password)?;

    let cwd = std::env::current_dir().map_err(VaultError::Io)?;

    let entries_to_unlock: Vec<_> = if args.paths.is_empty() {
        manifest.entries.iter().collect()
    } else {
        manifest
            .entries
            .iter()
            .filter(|e| args.paths.iter().any(|p| p == &e.path))
            .collect()
    };

    if entries_to_unlock.is_empty() {
        return Err(VaultError::Other(
            "No matching entries found in vault.".to_owned(),
        ));
    }

    for entry in entries_to_unlock {
        // Validate path safety (SEC-006).
        let dest = safe_join(&cwd, &entry.path)?;

        if dest.exists() && !args.force {
            return Err(VaultError::ConflictExists(entry.path.clone()));
        }

        let data = format::read_entry(vault_path, &password, &entry.path)?;

        // Verify integrity before writing.
        let actual_hash = format::sha256_hex(&data);
        if actual_hash != entry.sha256 {
            return Err(VaultError::Other(format!(
                "Hash mismatch for {}: vault may be corrupt",
                entry.path
            )));
        }

        write_file(&dest, &data).map_err(VaultError::Io)?;

        // Restore POSIX permissions if recorded.
        #[cfg(unix)]
        if let Some(mode) = entry.mode {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(mode);
            std::fs::set_permissions(&dest, perms).map_err(VaultError::Io)?;
        }

        if !quiet {
            println!("unlocked: {}", entry.path);
        }
    }

    Ok(())
}
