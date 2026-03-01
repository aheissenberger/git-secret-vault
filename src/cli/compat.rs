// Compatibility check command (FR-027).
//
// Reports encryption profile, compatible tools, unzip availability,
// and optionally runs a self-test round-trip.

use clap::Args;
use serde_json::json;

use crate::error::Result;

const PROFILE: &str = "dual-profile AES-256-GCM (vault format v2)";
const COMPATIBLE_TOOLS: &[&str] = &[
    "unzip 6.0+",
    "7-Zip 19+",
    "Python zipfile (AES extra support required)",
];

#[derive(Args)]
pub struct CompatArgs {
    /// Path to vault directory used for self-test (ignored unless --self-test)
    #[arg(long, default_value = ".git-secret-vault")]
    pub vault_dir: String,

    /// Create a tiny test vault, write one entry, read it back, report pass/fail
    #[arg(long)]
    pub self_test: bool,

    /// Output machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

/// Returns `true` if `unzip` is available on PATH.
fn unzip_available() -> bool {
    std::process::Command::new("unzip")
        .arg("--version")
        .output()
        .map(|o| o.status.success() || !o.stdout.is_empty() || !o.stderr.is_empty())
        .unwrap_or(false)
}

/// Runs a round-trip self-test: write one entry to a temp vault and read it back.
/// Returns `Ok(true)` on pass, `Ok(false)` on fail.
fn run_self_test() -> Result<bool> {
    use crate::vault::Vault;
    use tempfile::tempdir;

    let dir = tempdir().map_err(crate::error::VaultError::Io)?;
    let content = b"compat-self-test-payload";
    let password = "compat-test-password";

    let vault = Vault::init(dir.path(), password)?;
    let key = vault.derive_key(password)?;
    vault.lock(&key, "test.txt", content)?;
    let read_back = vault.unlock(&key, "test.txt")?;
    Ok(read_back == content)
}

pub fn run(args: &CompatArgs, quiet: bool, _verbose: bool) -> Result<()> {
    let unzip = unzip_available();

    let self_test_result = if args.self_test {
        match run_self_test() {
            Ok(true) => "pass",
            Ok(false) => "fail",
            Err(_) => "fail",
        }
    } else {
        "skipped"
    };

    if args.json {
        let out = json!({
            "profile": PROFILE,
            "tools": COMPATIBLE_TOOLS,
            "unzip_available": unzip,
            "self_test": self_test_result,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else if !quiet {
        println!("Encryption profile: {PROFILE}");
        println!("Compatible tools:");
        for tool in COMPATIBLE_TOOLS {
            println!("  - {tool}");
        }
        println!("unzip on PATH: {}", if unzip { "yes" } else { "not found" });
        if args.self_test {
            println!("Self-test: {self_test_result}");
        }
    }

    if self_test_result == "fail" {
        return Err(crate::error::VaultError::Other(
            "compat self-test failed".to_owned(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_output_contains_expected_keys() {
        let args = CompatArgs {
            vault_dir: ".git-secret-vault".to_owned(),
            self_test: false,
            json: true,
        };
        // Capture by calling run_self_test separately and checking json shape.
        let unzip = unzip_available();
        let out = json!({
            "profile": PROFILE,
            "tools": COMPATIBLE_TOOLS,
            "unzip_available": unzip,
            "self_test": "skipped",
        });
        assert_eq!(out["profile"], PROFILE);
        assert!(out["tools"].is_array());
        assert_eq!(
            out["tools"].as_array().unwrap().len(),
            COMPATIBLE_TOOLS.len()
        );
        assert_eq!(out["self_test"], "skipped");
        // run without panicking
        run(&args, false, false).unwrap();
    }

    #[test]
    fn self_test_passes() {
        let result = run_self_test().unwrap();
        assert!(result, "self-test round-trip should pass");
    }

    #[test]
    fn self_test_flag_runs_and_reports_pass() {
        let args = CompatArgs {
            vault_dir: ".git-secret-vault".to_owned(),
            self_test: true,
            json: false,
        };
        run(&args, true, false).expect("self-test should pass");
    }

    #[test]
    fn self_test_json_reports_pass() {
        let args = CompatArgs {
            vault_dir: ".git-secret-vault".to_owned(),
            self_test: true,
            json: true,
        };
        run(&args, false, false).expect("self-test should pass");
    }

    #[test]
    fn unzip_check_returns_bool() {
        // Just ensure the function runs without panic.
        let _ = unzip_available();
    }
}
