use clap::Args;

use crate::crypto;
use crate::error::{Result, VaultError};
use crate::vault::{format, index::OuterIndex, manifest::Manifest};

#[derive(Args)]
pub struct InitArgs {
    /// Path to vault file (default: git-secret-vault.zip)
    #[arg(long, default_value = "git-secret-vault.zip")]
    pub vault: String,

    /// Path to outer index file (default: .git-secret-vault.index.json)
    #[arg(long, default_value = ".git-secret-vault.index.json")]
    pub index: String,

    /// Read password from stdin instead of interactive prompt
    #[arg(long)]
    pub password_stdin: bool,

    /// Skip keyring lookup (no-op at init time; accepted for script consistency)
    #[arg(long)]
    pub no_keyring: bool,

    /// Fail if keyring is required (cannot be satisfied at init time; returns error)
    #[arg(long)]
    pub require_keyring: bool,
}

pub fn run(args: &InitArgs, quiet: bool) -> Result<()> {
    let vault_path = std::path::Path::new(&args.vault);
    let index_path = std::path::Path::new(&args.index);

    if vault_path.exists() {
        return Err(VaultError::VaultExists(args.vault.clone()));
    }

    // Keyring lookup cannot be satisfied at init time (no UUID exists yet).
    if args.require_keyring {
        return Err(VaultError::Other(
            "--require-keyring: vault UUID is not available at init time; \
             use `keyring save` after initialisation"
                .to_owned(),
        ));
    }

    let password = if args.password_stdin {
        crypto::read_password_stdin()?
    } else {
        crypto::prompt_new_password()?
    };

    let vault_uuid = uuid::Uuid::new_v4().to_string();
    let manifest = Manifest::new(&vault_uuid);

    let updates = std::collections::BTreeMap::new();
    let marker = format::rewrite_vault(vault_path, &password, &updates, &manifest)?;

    let outer = OuterIndex::new(&vault_uuid, 0, marker);
    outer.write(index_path)?;

    if !quiet {
        println!("Vault initialised: {} (UUID: {})", args.vault, vault_uuid);
        println!("Index:             {}", args.index);
    }

    Ok(())
}
