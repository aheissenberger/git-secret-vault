// Import from AES-256 ZIP interchange format into authoritative vault (FR-034).
// Does NOT replace the authoritative format — it adds entries from the ZIP into the vault.

use std::io::Read;
use std::path::Path;

use clap::Args;

use crate::crypto;
use crate::error::{Result, VaultError};
use crate::vault::Vault;

#[derive(Args, Debug)]
pub struct ImportArgs {
    /// Input ZIP file path
    pub input: std::path::PathBuf,

    /// Path to vault directory (must already be initialized)
    #[arg(long, default_value = ".git-secret-vault")]
    pub vault_dir: String,

    /// Read password from stdin (used for both ZIP and vault)
    #[arg(long)]
    pub password_stdin: bool,
}

pub fn run(args: &ImportArgs, _config: &crate::config::Config) -> Result<()> {
    if !args.input.exists() {
        return Err(VaultError::Other(format!("input file not found: {}", args.input.display())));
    }

    let vault_dir = Path::new(&args.vault_dir);
    if !vault_dir.join("vault.meta.json").exists() {
        return Err(VaultError::VaultNotFound(vault_dir.to_path_buf()));
    }

    let vault = Vault::open(vault_dir)?;
    let password = crypto::get_password(args.password_stdin, "Password (ZIP and vault): ")?;
    let key = vault.derive_key(&password)?;

    let data = std::fs::read(&args.input).map_err(VaultError::Io)?;
    let cursor = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| VaultError::Other(format!("ZIP open failed: {e}")))?;

    let mut imported = 0usize;
    let names: Vec<String> = (0..archive.len())
        .filter_map(|i| archive.name_for_index(i).map(|n| n.to_owned()))
        .collect();

    for name in &names {
        let mut file = archive
            .by_name_decrypt(name, password.as_bytes())
            .map_err(|e| VaultError::Other(format!("ZIP decrypt failed for {name}: {e}")))?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).map_err(|e| {
            if e.kind() == std::io::ErrorKind::InvalidData {
                VaultError::WrongPassword
            } else {
                VaultError::Io(e)
            }
        })?;
        vault.lock(&key, name, &buf)?;
        imported += 1;
    }

    println!("Imported {imported} entries from {} into vault", args.input.display());
    Ok(())
}

