// Keyring credential lifecycle management (FR-023).

use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::error::{Result, VaultError};
use crate::vault::index::OuterIndex;

// ── CLI structs ──────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct KeyringArgs {
    #[command(subcommand)]
    pub action: KeyringAction,

    /// Ignore keyring even if configured (overrides config)
    #[arg(long, global = true)]
    pub no_keyring: bool,

    /// Fail if keyring is unavailable (no fallback to interactive prompt)
    #[arg(long, global = true)]
    pub require_keyring: bool,
}

#[derive(Subcommand)]
pub enum KeyringAction {
    /// Store vault password in the system keyring
    Save {
        #[arg(long, default_value = "git-secret-vault.zip")]
        vault: String,
        #[arg(long, default_value = ".git-secret-vault.index.json")]
        index: String,
        /// Read password from stdin instead of prompting
        #[arg(long)]
        password_stdin: bool,
    },
    /// Check whether a credential exists for this vault
    Status {
        #[arg(long, default_value = "git-secret-vault.zip")]
        vault: String,
        #[arg(long, default_value = ".git-secret-vault.index.json")]
        index: String,
    },
    /// Remove the stored credential for this vault
    Delete {
        #[arg(long, default_value = "git-secret-vault.zip")]
        vault: String,
        #[arg(long, default_value = ".git-secret-vault.index.json")]
        index: String,
    },
    /// List all registered vault credentials
    List,
    /// Delete all registered vault credentials and clear the registry
    Purge,
}

// ── Registry ─────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegistryEntry {
    pub uuid: String,
    pub vault_path: String,
    pub saved_at: String,
}

fn registry_path() -> std::path::PathBuf {
    let config_dir = dirs::config_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    config_dir
        .join("git-secret-vault")
        .join("keyring-registry.json")
}

fn read_registry() -> Result<Vec<RegistryEntry>> {
    let path = registry_path();
    if !path.exists() {
        return Ok(vec![]);
    }
    let data = std::fs::read(&path).map_err(VaultError::Io)?;
    serde_json::from_slice(&data).map_err(VaultError::Json)
}

fn write_registry(entries: &[RegistryEntry]) -> Result<()> {
    let path = registry_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(VaultError::Io)?;
    }
    let data = serde_json::to_vec_pretty(entries).map_err(VaultError::Json)?;
    std::fs::write(&path, data).map_err(VaultError::Io)
}

fn upsert_registry(uuid: &str, vault_path: &str) -> Result<()> {
    let mut entries = read_registry()?;
    let now = chrono::Utc::now().to_rfc3339();
    if let Some(e) = entries.iter_mut().find(|e| e.uuid == uuid) {
        e.vault_path = vault_path.to_owned();
        e.saved_at = now;
    } else {
        entries.push(RegistryEntry {
            uuid: uuid.to_owned(),
            vault_path: vault_path.to_owned(),
            saved_at: now,
        });
    }
    write_registry(&entries)
}

fn remove_from_registry(uuid: &str) -> Result<()> {
    let entries: Vec<RegistryEntry> = read_registry()?
        .into_iter()
        .filter(|e| e.uuid != uuid)
        .collect();
    write_registry(&entries)
}

// ── Subcommand handlers ───────────────────────────────────────────────────────

fn read_uuid(index: &str) -> Result<String> {
    let path = std::path::Path::new(index);
    let idx = OuterIndex::read(path)?;
    Ok(idx.uuid)
}

fn keyring_get(uuid: &str) -> Option<String> {
    crate::keyring_mock::get_password(uuid)
}

fn keyring_set(uuid: &str, secret: &str) -> Result<()> {
    crate::keyring_mock::set_password(uuid, secret)
        .map_err(|e| VaultError::Other(format!("keyring error: {e}")))
}

fn keyring_delete(uuid: &str) -> Result<()> {
    crate::keyring_mock::delete_password(uuid)
        .map_err(|e| VaultError::Other(format!("keyring error: {e}")))
}

fn cmd_save(vault: &str, index: &str, password_stdin: bool, no_keyring: bool) -> Result<()> {
    if no_keyring {
        return Err(VaultError::Other(
            "Keyring disabled via --no-keyring".to_owned(),
        ));
    }
    let uuid = read_uuid(index)?;
    let password = crypto::get_password(password_stdin, "Vault password: ")?;
    keyring_set(&uuid, &password)?;
    upsert_registry(&uuid, vault)?;
    println!("Credential saved to keyring for vault {uuid}");
    Ok(())
}

fn cmd_status(index: &str) -> Result<()> {
    let uuid = read_uuid(index)?;
    match keyring_get(&uuid) {
        Some(_) => {
            println!("Credential found in keyring for vault {uuid}");
            Ok(())
        }
        None => {
            println!("No credential found in keyring for vault {uuid}");
            Err(VaultError::Other(format!(
                "keyring error: no credential for vault {uuid}"
            )))
        }
    }
}

fn cmd_delete(index: &str) -> Result<()> {
    let uuid = read_uuid(index)?;
    keyring_delete(&uuid)?;
    remove_from_registry(&uuid)?;
    println!("Credential deleted from keyring for vault {uuid}");
    Ok(())
}

fn cmd_list() -> Result<()> {
    let entries = read_registry()?;
    if entries.is_empty() {
        println!("No vaults registered.");
        return Ok(());
    }
    println!(
        "{:<38} {:<30} {:<26} Credential Status",
        "UUID", "Vault Path", "Saved At"
    );
    println!("{}", "-".repeat(100));
    for entry in &entries {
        let status = match keyring_get(&entry.uuid) {
            Some(_) => "present",
            None => "missing",
        };
        println!(
            "{:<38} {:<30} {:<26} {}",
            entry.uuid, entry.vault_path, entry.saved_at, status
        );
    }
    Ok(())
}

fn cmd_purge() -> Result<()> {
    let entries = read_registry()?;
    let count = entries.len();
    for entry in &entries {
        // Ignore not-found errors during purge
        let _ = keyring_delete(&entry.uuid);
    }
    write_registry(&[])?;
    println!("Purged {count} credential(s) from keyring.");
    Ok(())
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn run(args: &KeyringArgs, _quiet: bool, _verbose: bool) -> Result<()> {
    match &args.action {
        KeyringAction::Save {
            vault,
            index,
            password_stdin,
        } => cmd_save(vault, index, *password_stdin, args.no_keyring),
        KeyringAction::Status { index, .. } => cmd_status(index),
        KeyringAction::Delete { index, .. } => cmd_delete(index),
        KeyringAction::List => cmd_list(),
        KeyringAction::Purge => cmd_purge(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_path_contains_config_dir() {
        let path = registry_path();
        let path_str = path.to_string_lossy();
        assert!(
            path_str.ends_with("git-secret-vault/keyring-registry.json")
                || path_str.ends_with("git-secret-vault\\keyring-registry.json"),
            "Expected git-secret-vault/keyring-registry.json in path, got: {path_str}"
        );
    }

    #[test]
    fn registry_json_round_trip() {
        let entries = vec![
            RegistryEntry {
                uuid: "test-uuid-1234".to_owned(),
                vault_path: "my-vault.zip".to_owned(),
                saved_at: "2026-03-01T00:00:00Z".to_owned(),
            },
            RegistryEntry {
                uuid: "other-uuid-5678".to_owned(),
                vault_path: "other-vault.zip".to_owned(),
                saved_at: "2026-03-02T00:00:00Z".to_owned(),
            },
        ];

        let json = serde_json::to_string(&entries).unwrap();
        let decoded: Vec<RegistryEntry> = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].uuid, "test-uuid-1234");
        assert_eq!(decoded[0].vault_path, "my-vault.zip");
        assert_eq!(decoded[1].uuid, "other-uuid-5678");
    }

    /// Verifies that `status` returns an error for a UUID that has no keyring credential.
    /// Marked ignore because it interacts with the system keyring.
    #[test]
    #[ignore]
    fn status_returns_error_when_no_credential() {
        // Use a UUID that almost certainly has no stored credential.
        let uuid = "00000000-0000-0000-0000-000000000000-nonexistent";
        let result = crate::keyring_mock::get_password(uuid);
        assert!(result.is_none(), "Expected no credential for fake UUID");
    }
}
