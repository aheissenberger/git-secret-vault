use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use crate::error::{Result, VaultError};

const POLICY_FILE: &str = ".git-secret-vault-policy.json";

#[derive(Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub password_min_length: u8,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            password_min_length: 8,
        }
    }
}

impl PasswordPolicy {
    fn load() -> Result<Self> {
        let path = std::path::Path::new(POLICY_FILE);
        if path.exists() {
            let data = std::fs::read(path).map_err(VaultError::Io)?;
            serde_json::from_slice(&data)
                .map_err(|e| VaultError::Other(format!("Invalid policy file: {e}")))
        } else {
            Ok(Self::default())
        }
    }

    fn save(&self) -> Result<()> {
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| VaultError::Other(format!("Failed to serialize policy: {e}")))?;
        std::fs::write(POLICY_FILE, json).map_err(VaultError::Io)?;
        Ok(())
    }
}

#[derive(Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub action: PolicyAction,
}

#[derive(Subcommand)]
pub enum PolicyAction {
    /// Show current password policy
    Show {
        /// Print raw JSON output
        #[arg(long)]
        json: bool,
    },
    /// Update password policy settings
    Set {
        /// Minimum password length (>= 8)
        #[arg(long)]
        min_length: u8,
    },
}

pub fn run(args: &PolicyArgs, _quiet: bool) -> Result<()> {
    match &args.action {
        PolicyAction::Show { json } => {
            let policy = PasswordPolicy::load()?;
            if *json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&policy)
                        .map_err(|e| VaultError::Other(format!("Serialization error: {e}")))?
                );
            } else {
                println!("Password policy:");
                println!("  minimum length: {}", policy.password_min_length);
            }
        }
        PolicyAction::Set { min_length } => {
            if *min_length < 8 {
                return Err(VaultError::Other(
                    "minimum length must be >= 8".to_owned(),
                ));
            }
            let mut policy = PasswordPolicy::load()?;
            policy.password_min_length = *min_length;
            policy.save()?;
            println!("Policy updated.");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn show_default_policy_when_no_file() {
        let dir = tempdir().unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();

        let policy = PasswordPolicy::load().unwrap();
        assert_eq!(policy.password_min_length, 8);

        std::env::set_current_dir(original).unwrap();
    }

    #[test]
    fn set_updates_policy_file() {
        let dir = tempdir().unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();

        let mut policy = PasswordPolicy::load().unwrap();
        policy.password_min_length = 12;
        policy.save().unwrap();

        let loaded = PasswordPolicy::load().unwrap();
        assert_eq!(loaded.password_min_length, 12);

        std::env::set_current_dir(original).unwrap();
    }

    #[test]
    fn set_rejects_min_length_below_8() {
        let args = PolicyArgs {
            action: PolicyAction::Set { min_length: 6 },
        };
        let result = run(&args, false);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains(">="));
    }
}
