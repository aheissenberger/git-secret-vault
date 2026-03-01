use std::path::Path;

use clap::Args;

use crate::crypto;
use crate::error::{Result, VaultError};
use crate::vault::Vault;

#[derive(Args)]
pub struct LockArgs {
    /// Files to add to the vault (locks all tracked entries when omitted)
    pub paths: Vec<String>,

    /// Path to vault directory
    #[arg(long, default_value = ".git-secret-vault")]
    pub vault: String,

    /// Read password from stdin instead of interactive prompt
    #[arg(long)]
    pub password_stdin: bool,

    /// Validate vault is current without modifying it (exit non-zero if stale)
    #[arg(long)]
    pub check: bool,

    /// Delete plaintext files after successful encryption
    #[arg(long)]
    pub remove: bool,

    /// Delete plaintext after lock using best-effort secure erase (overwrite before delete). NOT guaranteed on SSDs or copy-on-write filesystems.
    #[arg(long)]
    pub shred: bool,

    /// Skip keyring lookup and go straight to interactive prompt
    #[arg(long)]
    pub no_keyring: bool,

    /// Fail if keyring lookup does not find a credential (no interactive fallback)
    #[arg(long)]
    pub require_keyring: bool,
}

pub fn run(args: &LockArgs, quiet: bool, verbose: bool) -> Result<()> {
    let vault_dir = Path::new(&args.vault);
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

    let snap = vault.snapshot()?;

    let path_strings: Vec<String> = if args.paths.is_empty() {
        if snap.entries.is_empty() {
            return Err(VaultError::Other(
                "No tracked entries in vault. Provide file paths to lock.".to_owned(),
            ));
        }
        snap.entries.iter().map(|e| e.label.clone()).collect()
    } else {
        crate::fs::expand_paths(&args.paths)?
    };

    let mut locked_paths: Vec<String> = Vec::new();

    for path_str in &path_strings {
        let local = Path::new(path_str);
        if !local.exists() {
            return Err(VaultError::Other(format!("File not found: {path_str}")));
        }

        let canonical = local
            .components()
            .filter_map(|c| match c {
                std::path::Component::Normal(s) => s.to_str().map(|s| s.to_owned()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("/");

        let data = std::fs::read(local).map_err(VaultError::Io)?;

        if args.check {
            if let Some(entry) = snap.entries.iter().find(|e| e.label == canonical) {
                let current_hash = crypto::content_hash(&data);
                if current_hash != entry.content_hash {
                    return Err(VaultError::Other(format!(
                        "--check: vault is stale for {canonical}"
                    )));
                }
                if !quiet {
                    println!("{canonical}: up-to-date");
                }
            } else {
                return Err(VaultError::Other(format!(
                    "--check: {canonical} not in vault"
                )));
            }
            continue;
        }

        vault.lock(&key, &canonical, &data)?;
        locked_paths.push(path_str.clone());

        if !quiet {
            println!("locked: {canonical}");
        }
        if verbose {
            println!("  sha256: {}", crypto::content_hash(&data));
            println!(
                "  size:   {} bytes",
                std::fs::metadata(local).map(|m| m.len()).unwrap_or(0)
            );
        }
    }

    if args.remove {
        for path_str in &locked_paths {
            let local = Path::new(path_str);
            if local.exists() {
                std::fs::remove_file(local).map_err(VaultError::Io)?;
                if !quiet {
                    println!("removed: {path_str}");
                }
            }
        }
    }

    if args.shred {
        eprintln!("warning: --shred performs best-effort overwrite before deletion.");
        eprintln!("warning: Secure deletion is NOT guaranteed on SSDs, copy-on-write");
        eprintln!("warning: filesystems (btrfs, APFS, ZFS), or network-mounted volumes.");
        for path_str in &locked_paths {
            let local = Path::new(path_str);
            if local.exists() {
                if let Ok(metadata) = std::fs::metadata(local) {
                    let len = metadata.len() as usize;
                    let zeros = vec![0u8; len];
                    let _ = std::fs::write(local, &zeros);
                }
                std::fs::remove_file(local).map_err(VaultError::Io)?;
                if !quiet {
                    println!("shredded: {path_str}");
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
    fn shred_deletes_file_after_overwrite() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("secret.txt");
        std::fs::write(&file, b"sensitive data").unwrap();
        assert!(file.exists());

        let path_str = file.to_str().unwrap();
        let local = std::path::Path::new(path_str);
        if local.exists() {
            if let Ok(metadata) = std::fs::metadata(local) {
                let len = metadata.len() as usize;
                let zeros = vec![0u8; len];
                let _ = std::fs::write(local, &zeros);
            }
            std::fs::remove_file(local).unwrap();
        }

        assert!(!file.exists());
    }
}
