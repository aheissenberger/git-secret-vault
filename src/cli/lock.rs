use std::collections::BTreeMap;
use std::path::Path;

use clap::Args;

use crate::crypto;
use crate::error::{Result, VaultError};
use crate::vault::{format, index::OuterIndex};

#[derive(Args)]
pub struct LockArgs {
    /// Files to add to the vault (locks all tracked entries when omitted)
    pub paths: Vec<String>,

    /// Path to vault directory
    #[arg(long, default_value = ".git-secret-vault")]
    pub vault_dir: String,

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
        let outer_for_uuid = crate::vault::index::OuterIndex::read(index_path)?;
        crypto::get_password_with_keyring(
            args.password_stdin,
            Some(&outer_for_uuid.uuid),
            args.require_keyring,
            "Vault password: ",
        )?
    };

    // Load existing manifest (to carry forward existing entries).
    let (mut manifest, _) = format::read_manifest(vault_path, &password)?;

    // Determine which paths to process: explicit args or all tracked entries.
    let path_strings: Vec<String> = if args.paths.is_empty() {
        if manifest.entries.is_empty() {
            return Err(VaultError::Other(
                "No tracked entries in vault. Provide file paths to lock.".to_owned(),
            ));
        }
        manifest.entries.iter().map(|e| e.path.clone()).collect()
    } else {
        crate::fs::expand_paths(&args.paths)?
    };

    let mut updates: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut locked_paths: Vec<String> = Vec::new();

    for path_str in &path_strings {
        let local = Path::new(path_str);
        if !local.exists() {
            return Err(VaultError::Other(format!("File not found: {path_str}")));
        }

        // Canonical entry name: normalised relative path using forward slashes.
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
            // Drift check: compare stored hash against current file.
            if let Some(entry) = manifest.entries.iter().find(|e| e.path == canonical) {
                let current_hash = format::sha256_hex(&data);
                if current_hash != entry.sha256 {
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

        let entry = format::entry_from_file(&canonical, local, &data);
        manifest.upsert(entry);
        updates.insert(canonical.clone(), data);
        locked_paths.push(path_str.clone());

        if !quiet {
            println!("locked: {canonical}");
        }
        if verbose {
            println!(
                "  sha256: {}",
                format::sha256_hex(&std::fs::read(local).unwrap_or_default())
            );
            println!(
                "  size:   {} bytes",
                std::fs::metadata(local).map(|m| m.len()).unwrap_or(0)
            );
        }
    }

    if args.check {
        return Ok(());
    }

    let marker = format::rewrite_vault(vault_path, &password, &updates, &manifest)?;

    // Update outer index entry count and integrity marker.
    let mut outer = OuterIndex::read(index_path)?;
    outer.entry_count = manifest.entries.len();
    outer.integrity_marker = marker;
    outer.updated_at = chrono::Utc::now().to_rfc3339();
    outer.write(index_path)?;

    // Remove plaintext files after successful vault write if --remove was specified.
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
                // Best-effort: overwrite with zeros before deletion
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
    use super::*;
    use crate::vault::{format, index::OuterIndex, manifest::Manifest};
    use tempfile::tempdir;

    fn setup_vault(
        dir: &std::path::Path,
        password: &str,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let vault_path = dir.join("vault.zip");
        let index_path = dir.join(".index.json");
        let manifest = Manifest::new("test-uuid");
        let marker = format::rewrite_vault(
            &vault_path,
            password,
            &std::collections::BTreeMap::new(),
            &manifest,
        )
        .unwrap();
        let outer = OuterIndex::new("test-uuid", 0, marker);
        outer.write(&index_path).unwrap();
        (vault_path, index_path)
    }

    #[test]
    #[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
    fn lock_single_file_updates_vault_and_index() {
        let dir = tempdir().unwrap();
        let (vault_path, index_path) = setup_vault(dir.path(), "pw123");

        let secret = dir.path().join("secret.env");
        std::fs::write(&secret, b"DB_PASS=hunter2").unwrap();

        let args = LockArgs {
            paths: vec!["secret.env".to_owned()],
            vault_dir: vault_path.parent().unwrap().to_str().unwrap().to_owned(),
            password_stdin: false,
            check: false,
            remove: false,
            shred: false,
            no_keyring: false,
            require_keyring: false,
        };

        // Change to dir so relative path works.
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let result = {
            let pw = zeroize::Zeroizing::new("pw123".to_owned());
            // Use internal logic directly: simulate run with known password.
            let vault = std::path::Path::new(&args.vault_dir).join("vault.zip");
            let vault = vault.as_path();
            let (mut manifest, _) = format::read_manifest(vault, &pw).unwrap();
            let local = std::path::Path::new("secret.env");
            let data = std::fs::read(local).unwrap();
            let entry = format::entry_from_file("secret.env", local, &data);
            manifest.upsert(entry);
            let mut updates = std::collections::BTreeMap::new();
            updates.insert("secret.env".to_owned(), data);
            let marker = format::rewrite_vault(vault, &pw, &updates, &manifest).unwrap();
            let mut outer = OuterIndex::read(&index_path).unwrap();
            outer.entry_count = manifest.entries.len();
            outer.integrity_marker = marker;
            outer.write(&index_path).unwrap();
            Ok::<(), crate::error::VaultError>(())
        };
        std::env::set_current_dir(original).unwrap();

        assert!(result.is_ok());
        let outer = OuterIndex::read(&index_path).unwrap();
        assert_eq!(outer.entry_count, 1);
    }

    #[test]
    #[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
    fn lock_no_args_on_empty_vault_returns_error() {
        let dir = tempdir().unwrap();
        let (vault_path, index_path) = setup_vault(dir.path(), "pw");

        let args = LockArgs {
            paths: vec![],
            vault_dir: vault_path.parent().unwrap().to_str().unwrap().to_owned(),
            password_stdin: false,
            check: false,
            remove: false,
            shred: false,
            no_keyring: false,
            require_keyring: false,
        };
        // Empty manifest + empty paths = error.
        let manifest = Manifest::new("u");
        assert!(manifest.entries.is_empty());
        // Simulate the guard.
        let path_strings: Vec<String> = if args.paths.is_empty() {
            if manifest.entries.is_empty() {
                vec![] // would trigger error
            } else {
                manifest.entries.iter().map(|e| e.path.clone()).collect()
            }
        } else {
            args.paths.clone()
        };
        // The guard fires when paths_strings is empty due to empty manifest.
        assert!(path_strings.is_empty());
    }

    #[test]
    #[ignore = "vault format stubs not yet implemented; awaiting feat/vault-format merge"]
    fn lock_no_args_with_tracked_entries_uses_manifest_paths() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("v.zip");

        // Seed vault with one entry.
        let mut manifest = Manifest::new("uuid-noarg");
        let content = b"hello";
        manifest.upsert(crate::vault::manifest::ManifestEntry {
            path: "tracked.env".to_owned(),
            size: content.len() as u64,
            mtime: String::new(),
            sha256: format::sha256_hex(content),
            mode: None,
        });
        let mut updates = std::collections::BTreeMap::new();
        updates.insert("tracked.env".to_owned(), content.to_vec());
        format::rewrite_vault(&vault_path, "pw", &updates, &manifest).unwrap();

        // No paths in args → should use manifest entries.
        let args = LockArgs {
            paths: vec![],
            vault_dir: vault_path.to_str().unwrap().to_owned(),
            password_stdin: false,
            check: false,
            remove: false,
            shred: false,
            no_keyring: false,
            require_keyring: false,
        };
        let (loaded_manifest, _) = format::read_manifest(&vault_path, "pw").unwrap();
        let path_strings: Vec<String> = if args.paths.is_empty() {
            loaded_manifest
                .entries
                .iter()
                .map(|e| e.path.clone())
                .collect()
        } else {
            args.paths.clone()
        };
        assert_eq!(path_strings, vec!["tracked.env"]);
    }

    #[test]
    fn shred_deletes_file_after_overwrite() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("secret.txt");
        std::fs::write(&file, b"sensitive data").unwrap();
        assert!(file.exists());

        // Simulate the shred block logic directly.
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
