use clap::Args;

use crate::crypto;
use crate::error::{Result, VaultError};
use crate::vault::Vault;

#[derive(Args)]
pub struct InitArgs {
    /// Path to vault directory (default: .git-secret-vault)
    #[arg(long, default_value = ".git-secret-vault")]
    pub vault: String,

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

    let vault_dir = std::path::Path::new(&args.vault);
    let vault = Vault::init(vault_dir, &password)?;

    if !quiet {
        println!("Vault initialised: {}", args.vault);
    }

    if !args.no_keyring && !args.password_stdin {
        let vault_uuid = vault.meta.key_ids.first().cloned().unwrap_or_default();
        eprint!(
            "Save password to system keyring for vault {}? [y/N] ",
            &vault_uuid[..8.min(vault_uuid.len())]
        );
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer).ok();
        if answer.trim().eq_ignore_ascii_case("y") {
            match crate::keyring_mock::set_password(&vault_uuid, password.as_str()) {
                Ok(_) => eprintln!("✓ Password saved to keyring."),
                Err(e) => eprintln!("warning: keyring save failed: {e}"),
            }
        }
    }

    Ok(())
}
