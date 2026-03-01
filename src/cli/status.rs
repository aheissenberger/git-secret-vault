use std::path::Path;

use clap::Args;
use serde_json::json;

use crate::crypto;
use crate::error::{Result, VaultError};
use crate::vault::Vault;

#[derive(Args)]
pub struct StatusArgs {
    /// Path to vault directory
    #[arg(long, default_value = ".git-secret-vault")]
    pub vault: String,

    /// Read password from stdin for authenticated verification mode
    #[arg(long)]
    pub password_stdin: bool,

    /// Output machine-readable JSON
    #[arg(long)]
    pub json: bool,

    /// Exit with code 1 if any tracked entries differ from vault (requires password)
    #[arg(long)]
    pub fail_if_dirty: bool,

    /// Do not prompt interactively; use --password-stdin or VAULT_PASSWORD only
    #[arg(long)]
    pub no_prompt: bool,
}

pub fn run(args: &StatusArgs, quiet: bool, _verbose: bool) -> Result<()> {
    let vault_dir = Path::new(&args.vault);

    if !vault_dir.exists() {
        return Err(VaultError::VaultNotFound(args.vault.clone()));
    }

    let vault = Vault::open(vault_dir)?;
    let snap = vault.snapshot()?;

    let has_password_source =
        args.password_stdin || args.no_prompt || std::env::var("VAULT_PASSWORD").is_ok();

    if has_password_source {
        return run_authenticated(args, &vault, &snap, quiet);
    }

    if args.fail_if_dirty {
        return Err(VaultError::Other(
            "--fail-if-dirty requires --password-stdin or VAULT_PASSWORD".to_owned(),
        ));
    }

    if args.json {
        let out = json!({
            "format_version": vault.meta.version,
            "updated_at": snap.generated_at,
            "entry_count": snap.entries.len(),
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else if !quiet {
        let mut output = String::new();
        output.push_str(&format!("Format:        v{}\n", vault.meta.version));
        output.push_str(&format!("Last updated:  {}\n", snap.generated_at));
        output.push_str(&format!("Entries:       {}\n", snap.entries.len()));
        print_with_pager(&output);
    }

    Ok(())
}

fn print_with_pager(output: &str) {
    if let Ok(pager) = std::env::var("PAGER")
        && let Ok(mut child) = std::process::Command::new(&pager)
            .stdin(std::process::Stdio::piped())
            .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(output.as_bytes());
        }
        let _ = child.wait();
        return;
    }
    print!("{output}");
}

fn run_authenticated(
    args: &StatusArgs,
    vault: &Vault,
    snap: &crate::vault::snapshot::Snapshot,
    quiet: bool,
) -> Result<()> {
    let password = crypto::get_password_no_prompt(args.password_stdin)?;
    let key = vault.derive_key(&password)?;

    let cwd = std::env::current_dir().map_err(VaultError::Io)?;

    let mut results: Vec<serde_json::Value> = Vec::new();
    let mut dirty_count = 0usize;

    for entry in &snap.entries {
        let local = cwd.join(&entry.label);
        let state = if local.exists() {
            let data = std::fs::read(&local).map_err(VaultError::Io)?;
            let local_hash = crate::crypto::content_hash(&data);
            if local_hash == entry.content_hash {
                "up-to-date"
            } else {
                dirty_count += 1;
                "stale"
            }
        } else {
            dirty_count += 1;
            "missing"
        };

        results.push(json!({ "path": entry.label, "state": state }));
    }

    // Verify key works (decrypt one blob as sanity check)
    if !snap.entries.is_empty() {
        vault.verify(&key).map_err(|_| VaultError::WrongPassword)?;
    }

    if args.json {
        let out = json!({
            "format_version": vault.meta.version,
            "updated_at": snap.generated_at,
            "entry_count": snap.entries.len(),
            "entries": results,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else if !quiet {
        let mut output = String::new();
        for entry in &results {
            let path = entry["path"].as_str().unwrap_or("");
            let state = entry["state"].as_str().unwrap_or("");
            output.push_str(&format!("{path}: {state}\n"));
        }
        print_with_pager(&output);
    }

    if args.fail_if_dirty && dirty_count > 0 {
        return Err(VaultError::Other(format!(
            "vault is dirty: {dirty_count} entries differ"
        )));
    }

    if dirty_count > 0 && !args.fail_if_dirty {
        return Err(VaultError::Other(
            "One or more vault entries are stale or missing locally.".to_owned(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_with_pager_no_pager_set_does_not_panic() {
        // SAFETY: single-threaded test context
        unsafe { std::env::remove_var("PAGER") };
        print_with_pager("test output\n");
    }
}
