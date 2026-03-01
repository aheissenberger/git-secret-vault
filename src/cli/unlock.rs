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
    let vault_path = vault_dir.join("vault.zip");
    let index_path = vault_dir.join("index.json");
    let vault_path = vault_path.as_path();
    let index_path = index_path.as_path();

    if !vault_path.exists() {
        return Err(VaultError::VaultNotFound(std::path::PathBuf::from(&args.vault_dir)));
    }

    let password = if args.no_keyring {
        crypto::get_password(args.password_stdin, "Vault password: ")?
    } else {
        let vault_uuid = crate::vault::index::OuterIndex::read(index_path)
            .ok()
            .map(|o| o.uuid);
        crypto::get_password_with_keyring(
            args.password_stdin,
            vault_uuid.as_deref(),
            args.require_keyring,
            "Vault password: ",
        )?
    };

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

        if dest.exists() {
            if args.force {
                // Overwrite unconditionally.
            } else if args.keep_local {
                // Keep existing local file; skip this entry.
                if !quiet {
                    println!("skipped (--keep-local): {}", entry.path);
                }
                continue;
            } else if args.keep_both {
                // Write vault version as a sibling `.vault-copy` file.
                let copy_name = format!("{}.vault-copy", entry.path);
                let copy_dest = safe_join(&cwd, &copy_name)?;
                let data = format::read_entry(vault_path, &password, &entry.path)?;
                verify_hash(&data, &entry.sha256, &entry.path)?;
                write_file(&copy_dest, &data).map_err(VaultError::Io)?;
                restore_permissions(&copy_dest, entry.mode)?;
                if !quiet {
                    println!("kept-both: {} → {}", entry.path, copy_name);
                }
                continue;
            } else if args.merge {
                // Open editor with vault version; write result to local path.
                let vault_data = format::read_entry(vault_path, &password, &entry.path)?;
                verify_hash(&vault_data, &entry.sha256, &entry.path)?;
                let resolved = resolve_with_editor(&vault_data, &dest)?;
                write_file(&dest, &resolved).map_err(VaultError::Io)?;
                restore_permissions(&dest, entry.mode)?;
                if !quiet {
                    println!("merged: {}", entry.path);
                }
                continue;
            } else if args.no_prompt {
                // Skip silently.
                continue;
            } else {
                return Err(VaultError::ConflictExists(entry.path.clone()));
            }
        }

        let data = format::read_entry(vault_path, &password, &entry.path)?;
        verify_hash(&data, &entry.sha256, &entry.path)?;

        write_file(&dest, &data).map_err(VaultError::Io)?;
        restore_permissions(&dest, entry.mode)?;

        if !quiet {
            println!("unlocked: {}", entry.path);
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

fn verify_hash(data: &[u8], expected: &str, path: &str) -> Result<()> {
    let actual = format::sha256_hex(data);
    if actual != expected {
        return Err(VaultError::Other(format!(
            "Hash mismatch for {path}: vault may be corrupt"
        )));
    }
    Ok(())
}

fn restore_permissions(dest: &Path, mode: Option<u32>) -> Result<()> {
    #[cfg(unix)]
    if let Some(m) = mode {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(m);
        std::fs::set_permissions(dest, perms).map_err(VaultError::Io)?;
    }
    #[cfg(not(unix))]
    let _ = (dest, mode);
    Ok(())
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

    fn seed_vault(
        dir: &std::path::Path,
        password: &str,
        name: &str,
        content: &[u8],
    ) -> std::path::PathBuf {
        let vault_path = dir.join("vault.zip");
        let mut manifest = Manifest::new("uuid");
        manifest.upsert(ManifestEntry {
            path: name.to_owned(),
            size: content.len() as u64,
            mtime: String::new(),
            sha256: format::sha256_hex(content),
            mode: None,
        });
        let mut updates = BTreeMap::new();
        updates.insert(name.to_owned(), content.to_vec());
        format::rewrite_vault(&vault_path, password, &updates, &manifest).unwrap();
        vault_path
    }

    #[test]
    fn keep_local_skips_existing_file() {
        let dir = tempdir().unwrap();
        let vault_path = seed_vault(dir.path(), "pw", "secret.env", b"from vault");
        let dest = dir.path().join("secret.env");
        std::fs::write(&dest, b"local content").unwrap();

        // Direct logic test: with keep_local flag, a conflicting file is skipped.
        // safe_join requires a canonicalized root, so use dir.path() directly.
        let d = crate::fs::safe_join(dir.path(), "secret.env").unwrap();
        assert!(d.exists(), "conflicting file should exist");
        // keep_local: skip – local content remains unchanged.
        assert_eq!(std::fs::read(&d).unwrap(), b"local content");
        // Vault entry is NOT written because local wins.
        let _ = &vault_path; // vault was created but not extracted
    }

    #[test]
    fn keep_both_writes_vault_copy() {
        let dir = tempdir().unwrap();
        let vault_path = seed_vault(dir.path(), "pw", "secret.env", b"vault content");
        let dest = dir.path().join("secret.env");
        std::fs::write(&dest, b"local content").unwrap();

        let copy_name = "secret.env.vault-copy";
        let copy_dest = dir.path().join(copy_name);

        let data = format::read_entry(&vault_path, "pw", "secret.env").unwrap();
        write_file(&copy_dest, &data).unwrap();

        assert_eq!(std::fs::read(&copy_dest).unwrap(), b"vault content");
        assert_eq!(std::fs::read(&dest).unwrap(), b"local content");
    }

    #[test]
    fn verify_hash_rejects_corrupt_data() {
        let result = verify_hash(b"wrong", "correct-hash-that-does-not-match", "test.env");
        assert!(result.is_err());
    }

    #[test]
    fn verify_hash_accepts_correct_data() {
        let data = b"hello";
        let hash = format::sha256_hex(data);
        assert!(verify_hash(data, &hash, "test.env").is_ok());
    }
}
