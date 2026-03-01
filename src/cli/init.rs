use clap::Args;

use crate::crypto;
use crate::error::{Result, VaultError};

#[derive(Args)]
pub struct InitArgs {
    /// Vault directory
    #[arg(long, default_value = ".git-secret-vault")]
    pub vault_dir: String,

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

pub fn run(args: &InitArgs, quiet: bool, _verbose: bool) -> Result<()> {
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
    crypto::validate_password_strength(&password)?;

    // TODO: replace with Vault::init(&vault_dir, &password) once feat/vault-format is merged
    let vault_dir = std::path::Path::new(&args.vault_dir);
    std::fs::create_dir_all(vault_dir.join("blobs")).map_err(VaultError::Io)?;
    std::fs::create_dir_all(vault_dir.join("index")).map_err(VaultError::Io)?;

    if !quiet {
        println!("Vault initialized at {}", vault_dir.display());
    }

    // Offer to save password to keyring (interactive only, not when stdin is consumed).
    if !args.no_keyring && !args.password_stdin {
        eprint!("Save password to system keyring? [y/N] ");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer).ok();
        if answer.trim().eq_ignore_ascii_case("y") {
            let vault_id = vault_dir.to_string_lossy().into_owned();
            match crate::keyring_mock::set_password(&vault_id, password.as_str()) {
                Ok(_) => eprintln!("✓ Password saved to keyring."),
                Err(e) => eprintln!("warning: keyring save failed: {e}"),
            }
        }
    }

    Ok(())
}
