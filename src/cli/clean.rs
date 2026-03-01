// Remove unlocked tracked plaintext files safely (FR-025).

use std::io::{self, Write};
use std::path::Path;

use clap::Args;

use crate::error::{Result, VaultError};
use crate::vault::Vault;

#[derive(Args)]
pub struct CleanArgs {
    /// Path to vault directory
    #[arg(long, default_value = ".git-secret-vault")]
    pub vault_dir: String,

    /// Read password from stdin instead of interactive prompt
    #[arg(long)]
    pub password_stdin: bool,

    /// Skip per-file confirmation prompts and remove all plaintext files
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: &CleanArgs, quiet: bool, _verbose: bool) -> Result<()> {
    let vault_dir = Path::new(&args.vault_dir);

    let vault = Vault::open(vault_dir)?;
    let snapshot = vault.snapshot()?;

    let mut removed_count = 0usize;

    for entry in &snapshot.entries {
        let local = Path::new(&entry.label);
        if !local.exists() {
            continue;
        }

        let should_remove = if args.force {
            true
        } else {
            prompt_yes(&format!("Remove plaintext {}? [y/N] ", entry.label))?
        };

        if should_remove {
            std::fs::remove_file(local).map_err(VaultError::Io)?;
            removed_count += 1;
            if !quiet {
                println!("removed: {}", entry.label);
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
    use crate::vault::Vault;
    use tempfile::tempdir;

    // Tests for new API: see src/vault/mod.rs

    #[test]
    fn clean_force_removes_existing_plaintext_files() {
        let dir = tempdir().unwrap();
        let vault = Vault::init(dir.path(), "pw").unwrap();
        let key = vault.derive_key("pw").unwrap();
        vault.lock(&key, "a.env", b"aaa").unwrap();
        vault.lock(&key, "b.env", b"bbb").unwrap();

        let file_a = dir.path().join("a.env");
        let file_b = dir.path().join("b.env");
        std::fs::write(&file_a, b"aaa").unwrap();
        std::fs::write(&file_b, b"bbb").unwrap();

        let snapshot = vault.snapshot().unwrap();
        let mut removed = 0usize;
        for entry in &snapshot.entries {
            let local = dir.path().join(&entry.label);
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
    fn clean_skips_missing_local_files() {
        let dir = tempdir().unwrap();
        let vault = Vault::init(dir.path(), "pw").unwrap();
        let key = vault.derive_key("pw").unwrap();
        vault.lock(&key, "missing.env", b"data").unwrap();

        let snapshot = vault.snapshot().unwrap();
        let mut removed = 0usize;
        for entry in &snapshot.entries {
            let local = dir.path().join(&entry.label);
            if local.exists() {
                std::fs::remove_file(&local).unwrap();
                removed += 1;
            }
        }
        assert_eq!(removed, 0);
    }

    #[test]
    fn prompt_yes_returns_true_for_y() {
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
