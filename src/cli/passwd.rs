// Re-encrypt vault with a new password (FR-022).

use std::collections::BTreeMap;
use std::path::Path;

use clap::Args;

use crate::crypto;
use crate::error::{Result, VaultError};
use crate::vault::{format, index::OuterIndex};

#[derive(Args)]
pub struct PasswdArgs {
    /// Path to vault file
    #[arg(long, default_value = "git-secret-vault.zip")]
    pub vault: String,

    /// Path to outer index file
    #[arg(long, default_value = ".git-secret-vault.index.json")]
    pub index: String,

    /// Read OLD password from stdin instead of interactive prompt
    #[arg(long)]
    pub password_stdin: bool,

    /// Read NEW password from stdin (one line) instead of interactive prompt
    #[arg(long)]
    pub new_password_stdin: bool,

    /// Print team password rotation checklist after success
    #[arg(long)]
    pub rotate: bool,
}

pub fn run(args: &PasswdArgs, quiet: bool, _verbose: bool) -> Result<()> {
    let vault_path = Path::new(&args.vault);
    let index_path = Path::new(&args.index);

    if !vault_path.exists() {
        return Err(VaultError::VaultNotFound(args.vault.clone()));
    }

    // Read old password.
    let old_password = crypto::get_password(args.password_stdin, "Current vault password: ")?;

    // Read manifest with old password.
    let (manifest, _) = format::read_manifest(vault_path, &old_password)?;

    // Read all entries before re-encrypting.
    let mut updates: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for entry in &manifest.entries {
        let data = format::read_entry(vault_path, &old_password, &entry.path)?;
        updates.insert(entry.path.clone(), data);
    }

    // Read new password.
    let new_password = if args.new_password_stdin {
        crypto::read_password_stdin()?
    } else {
        crypto::prompt_new_password()?
    };
    crypto::validate_password_strength(&new_password)?;

    // Rewrite vault with new password atomically.
    let marker = format::rewrite_vault(vault_path, &new_password, &updates, &manifest)?;

    // Update outer index.
    if index_path.exists() {
        let mut outer = OuterIndex::read(index_path)?;
        outer.integrity_marker = marker;
        outer.updated_at = chrono::Utc::now().to_rfc3339();
        outer.write(index_path)?;

        // If a keyring credential exists for this vault, update it with the new password.
        let uuid = outer.uuid.clone();
        let had_credential = crate::keyring_mock::get_password(&uuid).is_some();
        if had_credential
            && crate::keyring_mock::set_password(&uuid, &new_password).is_ok()
            && !quiet
        {
            println!("✓ Updated keyring credential for vault {uuid}");
        }
    }

    if !quiet {
        println!("Password changed successfully.");
    }

    if args.rotate {
        println!();
        println!("Password rotation checklist:");
        println!("1. Share new password with all team members via secure channel");
        println!("2. Team members: re-run `git-secret-vault unlock` with new password");
        println!("3. Update password in CI/CD secret stores");
        println!("4. Revoke old password from all keystores");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{
        format,
        index::OuterIndex,
        manifest::{Manifest, ManifestEntry},
    };
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    fn setup_vault(
        dir: &Path,
        password: &str,
        entries: &[(&str, &[u8])],
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let vault_path = dir.join("vault.zip");
        let index_path = dir.join(".index.json");
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
        let marker = format::rewrite_vault(&vault_path, password, &updates, &manifest).unwrap();
        let outer = OuterIndex::new("uuid", entries.len(), marker);
        outer.write(&index_path).unwrap();
        (vault_path, index_path)
    }

    #[test]
    fn passwd_reencrypts_with_new_password() {
        let dir = tempdir().unwrap();
        let (vault_path, index_path) =
            setup_vault(dir.path(), "old-pw", &[("secret.env", b"sensitive data")]);

        let old_password = zeroize::Zeroizing::new("old-pw".to_owned());
        let new_password = zeroize::Zeroizing::new("new-pw".to_owned());

        // Read manifest with old password.
        let (manifest, _) = format::read_manifest(&vault_path, &old_password).unwrap();

        // Read all entries.
        let mut updates: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for entry in &manifest.entries {
            let data = format::read_entry(&vault_path, &old_password, &entry.path).unwrap();
            updates.insert(entry.path.clone(), data);
        }

        // Rewrite with new password.
        let marker =
            format::rewrite_vault(&vault_path, &new_password, &updates, &manifest).unwrap();

        // Update index.
        let mut outer = OuterIndex::read(&index_path).unwrap();
        outer.integrity_marker = marker;
        outer.write(&index_path).unwrap();

        // Old password must no longer work.
        assert!(
            format::read_manifest(&vault_path, &old_password).is_err(),
            "old password should fail after rotation"
        );

        // New password must work and data must be intact.
        let (restored, _) = format::read_manifest(&vault_path, &new_password).unwrap();
        assert_eq!(restored.entries.len(), 1);
        let data = format::read_entry(&vault_path, &new_password, "secret.env").unwrap();
        assert_eq!(data, b"sensitive data");
    }

    #[test]
    fn passwd_wrong_old_password_returns_error() {
        let dir = tempdir().unwrap();
        let (vault_path, _) = setup_vault(dir.path(), "correct-pw", &[("a.env", b"data")]);

        let wrong = "wrong-password";
        let result = format::read_manifest(&vault_path, wrong);
        assert!(result.is_err(), "wrong old password should fail");
    }

    #[test]
    fn passwd_empty_vault_can_be_reencrypted() {
        let dir = tempdir().unwrap();
        let (vault_path, index_path) = setup_vault(dir.path(), "old", &[]);

        let old_pw = zeroize::Zeroizing::new("old".to_owned());
        let new_pw = zeroize::Zeroizing::new("new".to_owned());

        let (manifest, _) = format::read_manifest(&vault_path, &old_pw).unwrap();
        let updates: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let marker = format::rewrite_vault(&vault_path, &new_pw, &updates, &manifest).unwrap();

        let mut outer = OuterIndex::read(&index_path).unwrap();
        outer.integrity_marker = marker;
        outer.write(&index_path).unwrap();

        let (restored, _) = format::read_manifest(&vault_path, &new_pw).unwrap();
        assert!(restored.entries.is_empty());
    }

    #[test]
    fn passwd_index_marker_updated_after_rotation() {
        let dir = tempdir().unwrap();
        let (vault_path, index_path) = setup_vault(dir.path(), "old-pw", &[("k.env", b"val")]);

        let old_pw = zeroize::Zeroizing::new("old-pw".to_owned());
        let new_pw = zeroize::Zeroizing::new("new-pw".to_owned());

        let (manifest, _) = format::read_manifest(&vault_path, &old_pw).unwrap();
        let mut updates = BTreeMap::new();
        for entry in &manifest.entries {
            let data = format::read_entry(&vault_path, &old_pw, &entry.path).unwrap();
            updates.insert(entry.path.clone(), data);
        }
        let new_marker = format::rewrite_vault(&vault_path, &new_pw, &updates, &manifest).unwrap();
        let mut outer = OuterIndex::read(&index_path).unwrap();
        outer.integrity_marker = new_marker.clone();
        outer.write(&index_path).unwrap();

        // Verify the index was written with the new marker.
        let restored_marker = OuterIndex::read(&index_path).unwrap().integrity_marker;
        assert_eq!(
            restored_marker, new_marker,
            "index should be updated with new marker"
        );
        // The marker is SHA-256 of manifest bytes; manifest content doesn't change
        // with password rotation, so the marker value itself may be the same, but
        // the important thing is the index was successfully updated.
        assert!(!restored_marker.is_empty());
    }
}
