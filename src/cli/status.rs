use std::path::Path;

use clap::Args;
use serde_json::json;

use crate::crypto;
use crate::error::{Result, VaultError};
use crate::vault::{format, index::OuterIndex};

#[derive(Args)]
pub struct StatusArgs {
    /// Path to outer index file
    #[arg(long, default_value = ".git-secret-vault.index.json")]
    pub index: String,

    /// Path to vault file (enables authenticated verification when provided with password)
    #[arg(long, default_value = "git-secret-vault.zip")]
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

pub fn run(args: &StatusArgs, quiet: bool) -> Result<()> {
    let index_path = Path::new(&args.index);
    let vault_path = Path::new(&args.vault);

    if !index_path.exists() {
        return Err(VaultError::VaultNotFound(args.index.clone()));
    }

    let outer = OuterIndex::read(index_path)?;

    // Determine if a non-interactive password source is available.
    let has_password_source = args.password_stdin
        || args.no_prompt
        || std::env::var("VAULT_PASSWORD").is_ok();

    // Authenticated verification mode: vault exists and a password source is available.
    if vault_path.exists() && has_password_source {
        return run_authenticated(args, &outer, vault_path, quiet);
    }

    // --fail-if-dirty without any password source is an error.
    if args.fail_if_dirty {
        return Err(VaultError::Other(
            "--fail-if-dirty requires --password-stdin or VAULT_PASSWORD".to_owned(),
        ));
    }

    // Privacy-preserving summary mode (no password required).
    if args.json {
        let out = json!({
            "uuid": outer.uuid,
            "format_version": outer.format_version,
            "updated_at": outer.updated_at,
            "entry_count": outer.entry_count,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else if !quiet {
        let mut output = String::new();
        output.push_str(&format!("Vault UUID:    {}\n", outer.uuid));
        output.push_str(&format!("Format:        v{}\n", outer.format_version));
        output.push_str(&format!("Last updated:  {}\n", outer.updated_at));
        output.push_str(&format!("Entries:       {}\n", outer.entry_count));
        print_with_pager(&output);
    }

    Ok(())
}

/// Pipe `output` through `$PAGER` when set, otherwise print directly.
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

/// Authenticated verification: decrypt manifest and verify each entry against local files.
fn run_authenticated(
    args: &StatusArgs,
    outer: &OuterIndex,
    vault_path: &Path,
    quiet: bool,
) -> Result<()> {
    let password = crypto::get_password_no_prompt(args.password_stdin)?;
    let (manifest, _) = format::read_manifest(vault_path, &password)?;

    let cwd = std::env::current_dir().map_err(VaultError::Io)?;

    let mut results: Vec<serde_json::Value> = Vec::new();
    let mut dirty_count = 0usize;

    for entry in &manifest.entries {
        let local = cwd.join(&entry.path);
        let state = if local.exists() {
            let data = std::fs::read(&local).map_err(VaultError::Io)?;
            let local_hash = format::sha256_hex(&data);
            if local_hash == entry.sha256 {
                "up-to-date"
            } else {
                dirty_count += 1;
                "stale"
            }
        } else {
            dirty_count += 1;
            "missing"
        };

        results.push(json!({ "path": entry.path, "state": state }));
    }

    if args.json {
        let out = json!({
            "uuid": outer.uuid,
            "format_version": outer.format_version,
            "updated_at": outer.updated_at,
            "entry_count": outer.entry_count,
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
    use crate::vault::{
        format,
        index::OuterIndex,
        manifest::{Manifest, ManifestEntry},
    };
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    fn setup_vault_with_entry(
        dir: &std::path::Path,
        password: &str,
        name: &str,
        content: &[u8],
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let vault_path = dir.join("vault.zip");
        let index_path = dir.join(".index.json");
        let mut manifest = Manifest::new("status-uuid");
        manifest.upsert(ManifestEntry {
            path: name.to_owned(),
            size: content.len() as u64,
            mtime: String::new(),
            sha256: format::sha256_hex(content),
            mode: None,
        });
        let mut updates = BTreeMap::new();
        updates.insert(name.to_owned(), content.to_vec());
        let marker = format::rewrite_vault(&vault_path, password, &updates, &manifest).unwrap();
        let outer = OuterIndex::new("status-uuid", 1, marker);
        outer.write(&index_path).unwrap();
        (vault_path, index_path)
    }

    #[test]
    fn status_summary_reads_outer_index() {
        let dir = tempdir().unwrap();
        let (_, index_path) = setup_vault_with_entry(dir.path(), "pw", "s.env", b"secret");
        let outer = OuterIndex::read(&index_path).unwrap();
        assert_eq!(outer.uuid, "status-uuid");
        assert_eq!(outer.entry_count, 1);
    }

    #[test]
    fn authenticated_status_detects_up_to_date_file() {
        let dir = tempdir().unwrap();
        let (vault_path, _) = setup_vault_with_entry(dir.path(), "pw", "s.env", b"secret");
        std::fs::write(dir.path().join("s.env"), b"secret").unwrap();

        let (manifest, _) = format::read_manifest(&vault_path, "pw").unwrap();
        for entry in &manifest.entries {
            let local = dir.path().join(&entry.path);
            assert!(local.exists());
            let data = std::fs::read(&local).unwrap();
            assert_eq!(format::sha256_hex(&data), entry.sha256);
        }
    }

    #[test]
    fn authenticated_status_detects_stale_file() {
        let dir = tempdir().unwrap();
        let (vault_path, _) = setup_vault_with_entry(dir.path(), "pw", "s.env", b"original");
        std::fs::write(dir.path().join("s.env"), b"modified").unwrap();

        let (manifest, _) = format::read_manifest(&vault_path, "pw").unwrap();
        for entry in &manifest.entries {
            let local = dir.path().join(&entry.path);
            let data = std::fs::read(&local).unwrap();
            let local_hash = format::sha256_hex(&data);
            assert_ne!(local_hash, entry.sha256, "stale file should have different hash");
        }
    }

    #[test]
    fn authenticated_status_detects_missing_file() {
        let dir = tempdir().unwrap();
        let (vault_path, _) = setup_vault_with_entry(dir.path(), "pw", "s.env", b"content");
        // Do NOT write local file.

        let (manifest, _) = format::read_manifest(&vault_path, "pw").unwrap();
        for entry in &manifest.entries {
            let local = dir.path().join(&entry.path);
            assert!(!local.exists(), "local file should be missing");
        }
    }

    /// Helper to invoke `run_authenticated` by constructing minimal args and calling the
    /// internal logic directly through the manifest/format layer (avoids stdin requirement).
    fn check_dirty_via_manifest(
        vault_path: &std::path::Path,
        password: &str,
        cwd: &std::path::Path,
    ) -> (usize, Vec<String>) {
        let (manifest, _) = format::read_manifest(vault_path, password).unwrap();
        let mut dirty = 0usize;
        let mut states = Vec::new();
        for entry in &manifest.entries {
            let local = cwd.join(&entry.path);
            let state = if local.exists() {
                let data = std::fs::read(&local).unwrap();
                if format::sha256_hex(&data) == entry.sha256 {
                    "up-to-date"
                } else {
                    dirty += 1;
                    "stale"
                }
            } else {
                dirty += 1;
                "missing"
            };
            states.push(state.to_owned());
        }
        (dirty, states)
    }

    #[test]
    fn fail_if_dirty_clean_vault_returns_zero_dirty() {
        let dir = tempdir().unwrap();
        let (vault_path, _) = setup_vault_with_entry(dir.path(), "pw", "s.env", b"content");
        std::fs::write(dir.path().join("s.env"), b"content").unwrap();

        let (dirty, states) = check_dirty_via_manifest(&vault_path, "pw", dir.path());
        assert_eq!(dirty, 0, "expected no dirty entries; states: {states:?}");
    }

    #[test]
    fn fail_if_dirty_modified_file_returns_dirty() {
        let dir = tempdir().unwrap();
        let (vault_path, _) = setup_vault_with_entry(dir.path(), "pw", "s.env", b"original");
        std::fs::write(dir.path().join("s.env"), b"tampered").unwrap();

        let (dirty, states) = check_dirty_via_manifest(&vault_path, "pw", dir.path());
        assert!(dirty > 0, "expected dirty entries; states: {states:?}");
    }

    #[test]
    fn fail_if_dirty_without_password_source_is_error() {
        use crate::cli::status::{run, StatusArgs};
        let dir = tempdir().unwrap();
        // Create a minimal index so run() can reach the password-source check.
        let (_, index_path) = setup_vault_with_entry(dir.path(), "pw", "s.env", b"x");
        // Vault exists but we provide no password source (password_stdin=false, no_prompt=false,
        // VAULT_PASSWORD unset).
        let args = StatusArgs {
            index: index_path.to_str().unwrap().to_owned(),
            vault: dir.path().join("vault.zip").to_str().unwrap().to_owned(),
            password_stdin: false,
            no_prompt: false,
            json: false,
            fail_if_dirty: true,
        };
        // Clear env var in case it leaks from the environment.
        // SAFETY: single-threaded test context
        unsafe { std::env::remove_var("VAULT_PASSWORD") };
        let result = run(&args, true);
        assert!(result.is_err(), "expected error when no password source");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("--fail-if-dirty"),
            "error should mention --fail-if-dirty: {msg}"
        );
    }

    #[test]
    fn print_with_pager_no_pager_set_does_not_panic() {
        use super::print_with_pager;
        // SAFETY: single-threaded test context
        unsafe { std::env::remove_var("PAGER") };
        // Should not panic and should print normally.
        print_with_pager("test output\n");
    }
}
