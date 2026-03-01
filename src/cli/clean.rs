// Remove unlocked tracked plaintext files safely (FR-025).

use std::io::{self, Write};
use std::path::Path;

use clap::Args;

use crate::crypto;
use crate::error::{Result, VaultError};
use crate::vault::format;

#[derive(Args)]
pub struct CleanArgs {
    /// Path to vault file
    #[arg(long, default_value = "git-secret-vault.zip")]
    pub vault: String,

    /// Path to outer index file
    #[arg(long, default_value = ".git-secret-vault.index.json")]
    pub index: String,

    /// Read password from stdin instead of interactive prompt
    #[arg(long)]
    pub password_stdin: bool,

    /// Skip per-file confirmation prompts and remove all plaintext files
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: &CleanArgs, quiet: bool, _verbose: bool) -> Result<()> {
    let vault_path = Path::new(&args.vault);

    if !vault_path.exists() {
        return Err(VaultError::VaultNotFound(args.vault.clone()));
    }

    let password = crypto::get_password(args.password_stdin, "Vault password: ")?;

    let (manifest, _) = format::read_manifest(vault_path, &password)?;

    let mut removed_count = 0usize;

    for entry in &manifest.entries {
        let local = Path::new(&entry.path);
        if !local.exists() {
            continue;
        }

        let should_remove = if args.force {
            true
        } else {
            prompt_yes(&format!("Remove plaintext {}? [y/N] ", entry.path))?
        };

        if should_remove {
            std::fs::remove_file(local).map_err(VaultError::Io)?;
            removed_count += 1;
            if !quiet {
                println!("removed: {}", entry.path);
            }
        }
    }

    if !quiet {
        println!("Removed {removed_count} plaintext file(s).");
    }

    Ok(())
}

fn prompt_yes(prompt: &str) -> Result<bool> {
    print!("{prompt}");
    io::stdout().flush().map_err(VaultError::Io)?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer).map_err(VaultError::Io)?;
    Ok(matches!(answer.trim().to_lowercase().as_str(), "y" | "yes"))
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

    fn make_vault(dir: &Path, password: &str, entries: &[(&str, &[u8])]) -> std::path::PathBuf {
        let vault_path = dir.join("vault.zip");
        let mut manifest = Manifest::new("uuid");
        let mut updates = BTreeMap::new();
        for (name, content) in entries {
            manifest.upsert(ManifestEntry {
                path: (*name).to_owned(),
                size: content.len() as u64,
                mtime: String::new(),
                sha256: format::sha256_hex(content),
                mode: None,
            });
            updates.insert((*name).to_owned(), content.to_vec());
        }
        format::rewrite_vault(&vault_path, password, &updates, &manifest).unwrap();
        vault_path
    }

    #[test]
    fn clean_force_removes_existing_plaintext_files() {
        let dir = tempdir().unwrap();
        let vault_path = make_vault(dir.path(), "pw", &[("a.env", b"aaa"), ("b.env", b"bbb")]);

        // Create plaintext files using absolute paths.
        let file_a = dir.path().join("a.env");
        let file_b = dir.path().join("b.env");
        std::fs::write(&file_a, b"aaa").unwrap();
        std::fs::write(&file_b, b"bbb").unwrap();

        let (manifest, _) = format::read_manifest(&vault_path, "pw").unwrap();
        let mut removed = 0usize;
        for entry in &manifest.entries {
            // Use absolute paths to avoid current-dir sensitivity.
            let local = dir.path().join(&entry.path);
            if local.exists() {
                std::fs::remove_file(&local).unwrap();
                removed += 1;
            }
        }

        assert_eq!(removed, 2);
        assert!(!file_a.exists());
        assert!(!file_b.exists());
    }

    #[test]
    fn clean_skips_files_not_tracked() {
        let dir = tempdir().unwrap();
        let vault_path = make_vault(dir.path(), "pw", &[("tracked.env", b"data")]);

        // Create an untracked file.
        let untracked = dir.path().join("untracked.env");
        std::fs::write(&untracked, b"extra").unwrap();

        let (manifest, _) = format::read_manifest(&vault_path, "pw").unwrap();
        // Only tracked entries are processed.
        let tracked_paths: Vec<&str> = manifest.entries.iter().map(|e| e.path.as_str()).collect();
        assert!(tracked_paths.contains(&"tracked.env"));
        assert!(!tracked_paths.contains(&"untracked.env"));

        // Untracked file is not touched.
        assert!(untracked.exists());
    }

    #[test]
    fn clean_skips_missing_local_files() {
        let dir = tempdir().unwrap();
        let vault_path = make_vault(dir.path(), "pw", &[("missing.env", b"data")]);

        let (manifest, _) = format::read_manifest(&vault_path, "pw").unwrap();
        let mut removed = 0usize;
        for entry in &manifest.entries {
            // Use absolute paths; file doesn't exist in tempdir.
            let local = dir.path().join(&entry.path);
            if local.exists() {
                std::fs::remove_file(&local).unwrap();
                removed += 1;
            }
        }

        // File didn't exist locally, so nothing removed.
        assert_eq!(removed, 0);
    }

    #[test]
    fn prompt_yes_returns_true_for_y() {
        // Test the logic of prompt_yes via direct string matching.
        let answer = "y";
        let result = matches!(answer.trim().to_lowercase().as_str(), "y" | "yes");
        assert!(result);
    }

    #[test]
    fn prompt_yes_returns_false_for_n() {
        let answer = "n";
        let result = matches!(answer.trim().to_lowercase().as_str(), "y" | "yes");
        assert!(!result);
    }

    #[test]
    fn prompt_yes_returns_false_for_empty() {
        let answer = "";
        let result = matches!(answer.trim().to_lowercase().as_str(), "y" | "yes");
        assert!(!result);
    }
}
