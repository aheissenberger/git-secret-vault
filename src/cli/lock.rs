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

    /// Path to vault file
    #[arg(long, default_value = "vault.szv")]
    pub vault: String,

    /// Path to outer index file
    #[arg(long, default_value = ".safezipvault.index")]
    pub index: String,

    /// Read password from stdin instead of interactive prompt
    #[arg(long)]
    pub password_stdin: bool,

    /// Validate vault is current without modifying it (exit non-zero if stale)
    #[arg(long)]
    pub check: bool,
}

pub fn run(args: &LockArgs, quiet: bool) -> Result<()> {
    let vault_path = Path::new(&args.vault);
    let index_path = Path::new(&args.index);

    if !vault_path.exists() {
        return Err(VaultError::VaultNotFound(args.vault.clone()));
    }
    if args.paths.is_empty() {
        return Err(VaultError::Other(
            "No paths specified. Provide file paths to lock.".to_owned(),
        ));
    }

    let password = crypto::get_password(args.password_stdin, "Vault password: ")?;

    // Load existing manifest (to carry forward existing entries).
    let (mut manifest, _) = format::read_manifest(vault_path, &password)?;

    let mut updates: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    for path_str in &args.paths {
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

        if !quiet {
            println!("locked: {canonical}");
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

    Ok(())
}
