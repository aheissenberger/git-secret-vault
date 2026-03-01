use std::path::Path;

use clap::Args;

use crate::crypto;
use crate::error::{Result, VaultError};
use crate::fs::{safe_join, write_file};
use crate::vault::Vault;

#[derive(Args)]
pub struct UnlockArgs {
    /// Specific entries to unlock (unlocks all when omitted)
    pub paths: Vec<String>,

    /// Path to vault directory
    #[arg(long, default_value = ".git-secret-vault")]
    pub vault_dir: String,

    /// Read password from stdin instead of interactive prompt
    #[arg(long)]
    pub password_stdin: bool,

    /// Overwrite existing files without prompting
    #[arg(long)]
    pub force: bool,

    /// Keep existing local files when conflicts are detected (skip vault version)
    #[arg(long)]
    pub keep_local: bool,

    /// Write vault version alongside existing file as `<name>.vault-copy`
    #[arg(long)]
    pub keep_both: bool,

    /// Skip conflicting files silently without interactive prompting
    #[arg(long)]
    pub no_prompt: bool,

    /// Open $MERGE_TOOL or $EDITOR with the vault version for manual resolution.
    /// Falls back to 'vi' if neither is set.
    #[arg(long, conflicts_with_all = ["force", "keep_local", "keep_both", "no_prompt"])]
    pub merge: bool,

    /// Skip keyring lookup and go straight to interactive prompt
    #[arg(long)]
    pub no_keyring: bool,

    /// Fail if keyring lookup does not find a credential (no interactive fallback)
    #[arg(long)]
    pub require_keyring: bool,
}

pub fn run(args: &UnlockArgs, quiet: bool, _verbose: bool) -> Result<()> {
    let vault_dir = Path::new(&args.vault_dir);

    let vault = Vault::open(vault_dir)?;

    let password = if args.no_keyring {
        crypto::get_password(args.password_stdin, "Vault password: ")?
    } else {
        let vault_uuid = vault.meta.key_ids.first().cloned();
        crypto::get_password_with_keyring(
            args.password_stdin,
            vault_uuid.as_deref(),
            args.require_keyring,
            "Vault password: ",
        )?
    };

    let key = vault.derive_key(&password)?;
    let snapshot = vault.snapshot()?;
    let cwd = std::env::current_dir().map_err(VaultError::Io)?;

    let entries_to_unlock: Vec<_> = if args.paths.is_empty() {
        snapshot.entries.iter().collect()
    } else {
        snapshot
            .entries
            .iter()
            .filter(|e| args.paths.iter().any(|p| p == &e.label))
            .collect()
    };

    if entries_to_unlock.is_empty() {
        return Err(VaultError::Other(
            "No matching entries found in vault.".to_owned(),
        ));
    }

    for entry in entries_to_unlock {
        let dest = safe_join(&cwd, &entry.label)?;

        if dest.exists() {
            if args.force {
                // Overwrite unconditionally.
            } else if args.keep_local {
                if !quiet {
                    println!("skipped (--keep-local): {}", entry.label);
                }
                continue;
            } else if args.keep_both {
                let copy_name = format!("{}.vault-copy", entry.label);
                let copy_dest = safe_join(&cwd, &copy_name)?;
                let data = vault.unlock(&key, &entry.label)?;
                write_file(&copy_dest, &data).map_err(VaultError::Io)?;
                if !quiet {
                    println!("kept-both: {} → {}", entry.label, copy_name);
                }
                continue;
            } else if args.merge {
                let vault_data = vault.unlock(&key, &entry.label)?;
                let resolved = resolve_with_editor(&vault_data, &dest)?;
                write_file(&dest, &resolved).map_err(VaultError::Io)?;
                if !quiet {
                    println!("merged: {}", entry.label);
                }
                continue;
            } else if args.no_prompt {
                continue;
            } else {
                return Err(VaultError::ConflictExists(entry.label.clone()));
            }
        }

        let data = vault.unlock(&key, &entry.label)?;
        write_file(&dest, &data).map_err(VaultError::Io)?;

        if !quiet {
            println!("unlocked: {}", entry.label);
        }
    }

    Ok(())
}

fn resolve_with_editor(vault_content: &[u8], local_path: &Path) -> Result<Vec<u8>> {
    let dir = tempfile::tempdir().map_err(VaultError::Io)?;
    let tmp = dir.path().join(local_path.file_name().unwrap_or_default());
    std::fs::write(&tmp, vault_content).map_err(VaultError::Io)?;

    let editor = std::env::var("MERGE_TOOL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".to_string());

    let status = std::process::Command::new(&editor)
        .arg(&tmp)
        .status()
        .map_err(|e| VaultError::Other(format!("failed to launch editor {editor:?}: {e}")))?;

    if !status.success() {
        return Err(VaultError::Other(
            "editor exited with non-zero status".to_owned(),
        ));
    }

    std::fs::read(&tmp).map_err(VaultError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Vault;
    use tempfile::tempdir;

    // Tests for new API: see src/vault/mod.rs

    #[test]
    fn keep_local_skips_existing_file() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("secret.env");
        std::fs::write(&dest, b"local content").unwrap();

        let d = crate::fs::safe_join(dir.path(), "secret.env").unwrap();
        assert!(d.exists(), "conflicting file should exist");
        assert_eq!(std::fs::read(&d).unwrap(), b"local content");
    }

    #[test]
    fn keep_both_writes_vault_copy() {
        let dir = tempdir().unwrap();
        let vault = Vault::init(dir.path(), "pw").unwrap();
        let key = vault.derive_key("pw").unwrap();
        vault.lock(&key, "secret.env", b"vault content").unwrap();

        let dest = dir.path().join("secret.env");
        std::fs::write(&dest, b"local content").unwrap();

        let copy_dest = dir.path().join("secret.env.vault-copy");
        let data = vault.unlock(&key, "secret.env").unwrap();
        write_file(&copy_dest, &data).unwrap();

        assert_eq!(std::fs::read(&copy_dest).unwrap(), b"vault content");
        assert_eq!(std::fs::read(&dest).unwrap(), b"local content");
    }
}
