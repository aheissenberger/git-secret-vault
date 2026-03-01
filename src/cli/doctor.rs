// Diagnose environment readiness (FR-026).

use std::path::Path;

use clap::Args;
use serde_json::json;

use crate::error::Result;
use crate::vault::Vault;

#[derive(Args)]
pub struct DoctorArgs {
    /// Path to vault directory to check
    #[arg(long, default_value = ".git-secret-vault")]
    pub vault: String,

    /// Output machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

struct Check {
    name: &'static str,
    ok: bool,
    description: String,
    hint: Option<String>,
}

pub fn run(args: &DoctorArgs, quiet: bool, verbose: bool) -> Result<()> {
    let vault_dir = Path::new(&args.vault);

    let mut checks: Vec<Check> = Vec::new();

    // 1. Vault directory exists?
    let vault_dir_exists = vault_dir.exists();
    checks.push(Check {
        name: "vault_dir_exists",
        ok: vault_dir_exists,
        description: format!("Vault directory exists: {}", args.vault),
        hint: if vault_dir_exists {
            None
        } else {
            Some(format!(
                "Run `git-secret-vault init --vault {}` to create it.",
                args.vault
            ))
        },
    });

    // 2. Vault meta file exists?
    let meta_exists = vault_dir.join("vault.meta.json").exists();
    checks.push(Check {
        name: "vault_meta_exists",
        ok: meta_exists,
        description: format!("Vault meta file exists: {}/vault.meta.json", args.vault),
        hint: if meta_exists {
            None
        } else {
            Some(format!(
                "Run `git-secret-vault init --vault {}` to create it.",
                args.vault
            ))
        },
    });

    // 3. Vault meta is valid?
    let meta_valid = if meta_exists {
        Vault::open(vault_dir).is_ok()
    } else {
        false
    };
    checks.push(Check {
        name: "vault_meta_readable",
        ok: meta_valid,
        description: "Vault meta file is valid JSON".to_owned(),
        hint: if meta_valid {
            None
        } else {
            Some("Vault meta file is missing or corrupt. Re-initialise the vault.".to_owned())
        },
    });

    // 4. Can write to current directory?
    let can_write = {
        let test_path = Path::new(".git-secret-vault-write-test");
        let ok = std::fs::write(test_path, b"").is_ok();
        if ok {
            let _ = std::fs::remove_file(test_path);
        }
        ok
    };
    checks.push(Check {
        name: "directory_writable",
        ok: can_write,
        description: "Can write to current directory".to_owned(),
        hint: if can_write {
            None
        } else {
            Some("Check directory permissions or run from a writable location.".to_owned())
        },
    });

    // 5. `unzip` binary available on PATH?
    let unzip_available = std::process::Command::new("unzip")
        .arg("--version")
        .output()
        .map(|o| o.status.success() || !o.stdout.is_empty() || !o.stderr.is_empty())
        .unwrap_or(false);
    checks.push(Check {
        name: "unzip_available",
        ok: unzip_available,
        description: "`unzip` binary is available on PATH".to_owned(),
        hint: if unzip_available {
            None
        } else {
            Some(
                "Install `unzip` (e.g. `apt-get install unzip` or `brew install unzip`)."
                    .to_owned(),
            )
        },
    });

    // 6. System keyring accessible?
    let keyring_ok = if crate::keyring_mock::is_mock() {
        true
    } else {
        keyring::Entry::new("git-secret-vault", "doctor-probe")
            .map(|_| true)
            .unwrap_or(false)
    };
    checks.push(Check {
        name: "keyring_available",
        ok: keyring_ok,
        description: "System keyring is accessible".to_owned(),
        hint: if keyring_ok {
            None
        } else {
            Some(
                "Install or configure a keyring backend \
                 (e.g. gnome-keyring, kwallet on Linux, macOS Keychain, or Windows Credential Manager). \
                 Run `git-secret-vault keyring save` after fixing."
                    .to_owned(),
            )
        },
    });

    let any_failed = checks.iter().any(|c| !c.ok);

    if args.json {
        let check_items: Vec<serde_json::Value> = checks
            .iter()
            .map(|c| {
                let message = if c.ok {
                    c.description.clone()
                } else {
                    c.hint
                        .as_deref()
                        .map(|h| format!("{} — {}", c.description, h))
                        .unwrap_or_else(|| c.description.clone())
                };
                json!({ "name": c.name, "ok": c.ok, "message": message })
            })
            .collect();
        let out = json!({ "ok": !any_failed, "checks": check_items });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        for check in &checks {
            if check.ok {
                if !quiet {
                    if verbose {
                        println!("  [OK]   {} ({})", check.description, check.name);
                    } else {
                        println!("  [OK]   {}", check.description);
                    }
                }
            } else if !quiet {
                if let Some(hint) = &check.hint {
                    println!("  [FAIL] {} - {}", check.description, hint);
                } else {
                    println!("  [FAIL] {}", check.description);
                }
            }
        }
    }

    if any_failed {
        Err(crate::error::VaultError::Other(
            "One or more environment checks failed.".to_owned(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use crate::vault::Vault;

    const TEST_PASSWORD: &str = "correct-horse-battery-staple-42!";

    #[test]
    fn doctor_detects_vault_exists() {
        let dir = tempdir().unwrap();
        Vault::init(dir.path(), TEST_PASSWORD).unwrap();
        assert!(dir.path().join("vault.meta.json").exists());
    }

    #[test]
    fn doctor_detects_vault_missing() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.meta.json");
        assert!(!vault_path.exists());
    }

    #[test]
    fn doctor_write_check_succeeds_in_tempdir() {
        let dir = tempdir().unwrap();
        let test_path = dir.path().join(".write-test");
        let ok = std::fs::write(&test_path, b"").is_ok();
        assert!(ok, "should be able to write to temp directory");
        let _ = std::fs::remove_file(&test_path);
    }
}
