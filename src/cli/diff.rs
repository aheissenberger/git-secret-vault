// Diff command (FR-020): show differences between vault entries and local files.

use std::path::Path;

use clap::Args;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::crypto;
use crate::error::{Result, VaultError};
use crate::vault::format;

#[derive(Args)]
pub struct DiffArgs {
    /// Paths to compare (compares all tracked entries if omitted)
    pub paths: Vec<String>,

    /// Path to vault file
    #[arg(long, default_value = "git-secret-vault.zip")]
    pub vault: String,

    /// Read password from stdin
    #[arg(long)]
    pub password_stdin: bool,

    /// Output machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug)]
struct EntryResult {
    path: String,
    status: &'static str,
    diff: Option<String>,
    binary: bool,
}

pub fn run(args: &DiffArgs, _quiet: bool) -> Result<()> {
    let vault_path = Path::new(&args.vault);
    if !vault_path.exists() {
        return Err(VaultError::VaultNotFound(args.vault.clone()));
    }

    let password = crypto::get_password(args.password_stdin, "Vault password: ")?;
    let (manifest, _) = format::read_manifest(vault_path, &password)?;

    let cwd = std::env::current_dir().map_err(VaultError::Io)?;
    let mut results: Vec<EntryResult> = Vec::new();

    // Determine which paths to process.
    let filter: Option<std::collections::HashSet<&str>> = if args.paths.is_empty() {
        None
    } else {
        Some(args.paths.iter().map(String::as_str).collect())
    };

    // Process vault entries.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for entry in &manifest.entries {
        if let Some(ref f) = filter
            && !f.contains(entry.path.as_str())
        {
            continue;
        }
        seen.insert(entry.path.clone());

        let vault_bytes = format::read_entry(vault_path, &password, &entry.path)?;
        let local_path = cwd.join(&entry.path);

        if !local_path.exists() {
            results.push(EntryResult {
                path: entry.path.clone(),
                status: "vault-only",
                diff: None,
                binary: false,
            });
            continue;
        }

        let local_bytes = std::fs::read(&local_path).map_err(VaultError::Io)?;

        if vault_bytes == local_bytes {
            results.push(EntryResult {
                path: entry.path.clone(),
                status: "identical",
                diff: None,
                binary: false,
            });
            continue;
        }

        // Check if either side is binary.
        let vault_text = String::from_utf8(vault_bytes.clone());
        let local_text = String::from_utf8(local_bytes.clone());

        match (vault_text, local_text) {
            (Ok(vt), Ok(lt)) => {
                let diff_str = unified_diff(&entry.path, &vt, &lt);
                results.push(EntryResult {
                    path: entry.path.clone(),
                    status: "modified",
                    diff: if diff_str.is_empty() {
                        None
                    } else {
                        Some(diff_str)
                    },
                    binary: false,
                });
            }
            _ => {
                let vault_hash = sha256_short(&vault_bytes);
                let local_hash = sha256_short(&local_bytes);
                let summary = format!(
                    "Binary files differ (vault: {vault_hash}, local: {local_hash})"
                );
                results.push(EntryResult {
                    path: entry.path.clone(),
                    status: "modified",
                    diff: Some(summary),
                    binary: true,
                });
            }
        }
    }

    // Handle explicitly requested paths not in the vault.
    if let Some(ref f) = filter {
        for path in f {
            if !seen.contains(*path) {
                results.push(EntryResult {
                    path: path.to_string(),
                    status: "local-only",
                    diff: None,
                    binary: false,
                });
            }
        }
    }

    let has_changes = results.iter().any(|r| r.status != "identical");

    if args.json {
        let entries: Vec<_> = results
            .iter()
            .map(|r| {
                json!({
                    "path": r.path,
                    "status": r.status,
                    "diff": r.diff,
                    "binary": r.binary,
                })
            })
            .collect();
        let out = json!({ "entries": entries, "has_changes": has_changes });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        for r in &results {
            match r.status {
                "identical" => {}
                "vault-only" => println!("vault-only: {}", r.path),
                "local-only" => println!("local-only: {}", r.path),
                "modified" => {
                    if let Some(ref d) = r.diff {
                        println!("{d}");
                    }
                }
                _ => {}
            }
        }
    }

    if has_changes {
        // Use process::exit so the exit code propagates correctly without
        // printing an error message.
        std::process::exit(1);
    }

    Ok(())
}

/// Produce a unified diff of two text strings.
/// Returns an empty string when the contents are identical.
pub fn unified_diff(path: &str, vault_text: &str, local_text: &str) -> String {
    let vault_lines: Vec<&str> = vault_text.lines().collect();
    let local_lines: Vec<&str> = local_text.lines().collect();

    if vault_lines == local_lines {
        return String::new();
    }

    // Compute LCS-based edit script via Myers-like DP.
    let hunks = compute_hunks(&vault_lines, &local_lines, 3);

    if hunks.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    out.push_str(&format!("--- vault/{path}\n"));
    out.push_str(&format!("+++ local/{path}\n"));
    for hunk in hunks {
        out.push_str(&hunk);
    }
    out
}

/// Compute the longest common subsequence table.
fn lcs_table(a: &[&str], b: &[&str]) -> Vec<Vec<usize>> {
    let m = a.len();
    let n = b.len();
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            if a[i - 1] == b[j - 1] {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                dp[i][j] = dp[i - 1][j].max(dp[i][j - 1]);
            }
        }
    }
    dp
}

#[derive(Debug, Clone, PartialEq)]
enum Op {
    Equal,
    Delete,
    Insert,
}

/// Build the edit operations using backtracking over the LCS table.
fn build_ops(a: &[&str], b: &[&str]) -> Vec<(Op, String)> {
    let dp = lcs_table(a, b);
    let mut ops: Vec<(Op, String)> = Vec::new();
    let mut i = a.len();
    let mut j = b.len();
    while i > 0 || j > 0 {
        if i > 0 && j > 0 && a[i - 1] == b[j - 1] {
            ops.push((Op::Equal, a[i - 1].to_owned()));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j]) {
            ops.push((Op::Insert, b[j - 1].to_owned()));
            j -= 1;
        } else {
            ops.push((Op::Delete, a[i - 1].to_owned()));
            i -= 1;
        }
    }
    ops.reverse();
    ops
}

/// Generate unified-diff hunks with `ctx` context lines.
fn compute_hunks(a: &[&str], b: &[&str], ctx: usize) -> Vec<String> {
    let ops = build_ops(a, b);

    // Assign line numbers.
    let mut entries: Vec<(Op, String, usize, usize)> = Vec::new();
    let mut old_line = 1usize;
    let mut new_line = 1usize;
    for (op, text) in ops {
        match op {
            Op::Equal => {
                entries.push((Op::Equal, text, old_line, new_line));
                old_line += 1;
                new_line += 1;
            }
            Op::Delete => {
                entries.push((Op::Delete, text, old_line, new_line));
                old_line += 1;
            }
            Op::Insert => {
                entries.push((Op::Insert, text, old_line, new_line));
                new_line += 1;
            }
        }
    }

    // Find changed positions.
    let changed: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, (op, _, _, _))| *op != Op::Equal)
        .map(|(i, _)| i)
        .collect();

    if changed.is_empty() {
        return Vec::new();
    }

    // Group changes into hunks.
    let n = entries.len();
    let mut hunk_ranges: Vec<(usize, usize)> = Vec::new();
    let mut start = changed[0].saturating_sub(ctx);
    let mut end = (changed[0] + ctx + 1).min(n);

    for &pos in &changed[1..] {
        let new_start = pos.saturating_sub(ctx);
        let new_end = (pos + ctx + 1).min(n);
        if new_start <= end {
            // Overlapping or adjacent: extend current hunk.
            end = new_end;
        } else {
            hunk_ranges.push((start, end));
            start = new_start;
            end = new_end;
        }
    }
    hunk_ranges.push((start, end));

    let mut hunks = Vec::new();
    for (hstart, hend) in hunk_ranges {
        let slice = &entries[hstart..hend];

        // Count old and new lines in hunk.
        let old_count = slice
            .iter()
            .filter(|(op, _, _, _)| *op == Op::Equal || *op == Op::Delete)
            .count();
        let new_count = slice
            .iter()
            .filter(|(op, _, _, _)| *op == Op::Equal || *op == Op::Insert)
            .count();

        let old_start = slice
            .iter()
            .find(|(op, _, _, _)| *op == Op::Equal || *op == Op::Delete)
            .map(|(_, _, ol, _)| *ol)
            .unwrap_or(1);
        let new_start = slice
            .iter()
            .find(|(op, _, _, _)| *op == Op::Equal || *op == Op::Insert)
            .map(|(_, _, _, nl)| *nl)
            .unwrap_or(1);

        let mut hunk = format!(
            "@@ -{old_start},{old_count} +{new_start},{new_count} @@\n"
        );
        for (op, text, _, _) in slice {
            match op {
                Op::Equal => hunk.push_str(&format!(" {text}\n")),
                Op::Delete => hunk.push_str(&format!("-{text}\n")),
                Op::Insert => hunk.push_str(&format!("+{text}\n")),
            }
        }
        hunks.push(hunk);
    }
    hunks
}

/// First 8 hex chars of SHA-256 of the given bytes.
fn sha256_short(data: &[u8]) -> String {
    let hash = hex::encode(Sha256::digest(data));
    hash[..8].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn unified_diff_identical_returns_empty() {
        let text = "line one\nline two\nline three\n";
        assert_eq!(unified_diff("file.txt", text, text), "");
    }

    #[test]
    fn unified_diff_changed_line_has_plus_minus() {
        let vault = "line one\nold line\nline three\n";
        let local = "line one\nnew line\nline three\n";
        let diff = unified_diff("file.txt", vault, local);
        assert!(diff.contains("-old line"), "missing removal: {diff}");
        assert!(diff.contains("+new line"), "missing addition: {diff}");
        assert!(diff.contains("--- vault/file.txt"), "missing vault header: {diff}");
        assert!(diff.contains("+++ local/file.txt"), "missing local header: {diff}");
    }

    #[test]
    fn unified_diff_context_lines_included() {
        let vault = "ctx1\nctx2\nctx3\nold\nctx4\nctx5\nctx6\n";
        let local = "ctx1\nctx2\nctx3\nnew\nctx4\nctx5\nctx6\n";
        let diff = unified_diff("f.txt", vault, local);
        assert!(diff.contains(" ctx1"), "context line ctx1 missing: {diff}");
        assert!(diff.contains(" ctx3"), "context line ctx3 missing: {diff}");
    }

    #[test]
    fn binary_detection_valid_utf8() {
        let data = b"hello world";
        assert!(String::from_utf8(data.to_vec()).is_ok());
    }

    #[test]
    fn binary_detection_invalid_utf8() {
        let data = vec![0xFF, 0xFE, 0x00];
        assert!(String::from_utf8(data).is_err());
    }

    #[test]
    fn sha256_short_length_is_eight() {
        let s = sha256_short(b"test data");
        assert_eq!(s.len(), 8);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn json_output_structure() {
        // Simulate the JSON structure produced by the run function.
        let results: Vec<Value> = vec![json!({
            "path": "secret.env",
            "status": "modified",
            "diff": "--- vault/secret.env\n+++ local/secret.env\n@@ -1,1 +1,1 @@\n-old\n+new\n",
            "binary": false,
        })];
        let out = json!({ "entries": results, "has_changes": true });
        assert_eq!(out["has_changes"], true);
        assert_eq!(out["entries"][0]["status"], "modified");
        assert!(out["entries"][0]["diff"].is_string());
        assert_eq!(out["entries"][0]["binary"], false);
    }

    #[test]
    fn json_identical_entry_structure() {
        let results: Vec<Value> = vec![json!({
            "path": "secret.env",
            "status": "identical",
            "diff": Value::Null,
            "binary": false,
        })];
        let out = json!({ "entries": results, "has_changes": false });
        assert_eq!(out["has_changes"], false);
        assert_eq!(out["entries"][0]["status"], "identical");
        assert!(out["entries"][0]["diff"].is_null());
    }

    #[test]
    fn unified_diff_added_lines() {
        let vault = "line one\n";
        let local = "line one\nnew line\n";
        let diff = unified_diff("f.txt", vault, local);
        assert!(diff.contains("+new line"), "expected +new line in: {diff}");
    }

    #[test]
    fn unified_diff_removed_lines() {
        let vault = "line one\nremoved line\n";
        let local = "line one\n";
        let diff = unified_diff("f.txt", vault, local);
        assert!(diff.contains("-removed line"), "expected -removed line in: {diff}");
    }
}
