use glob::glob;

use crate::error::{Result, VaultError};

/// Expand a list of path strings, resolving glob patterns relative to cwd.
/// Non-glob strings are returned as-is (even if the file doesn't exist,
/// so the caller's existing "not found" logic still applies).
pub fn expand_paths(patterns: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for pat in patterns {
        if pat.contains('*') || pat.contains('?') || pat.contains('[') {
            let matches: Vec<_> = glob(pat)
                .map_err(|e| VaultError::Other(format!("invalid glob pattern {pat:?}: {e}")))?
                .filter_map(|r| r.ok())
                .filter(|p| p.is_file())
                .collect();
            if matches.is_empty() {
                return Err(VaultError::Other(format!(
                    "no files matched pattern {pat:?}"
                )));
            }
            for path in matches {
                out.push(path.to_string_lossy().into_owned());
            }
        } else {
            out.push(pat.clone());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    // These tests intentionally avoid std::env::set_current_dir because cwd is
    // process-global and can cause flaky behavior when tests run in parallel.

    #[test]
    fn expand_glob_matches_files() {
        let dir = tempdir().unwrap();
        let a_path = dir.path().join("a.env");
        let b_path = dir.path().join("b.env");
        let other_path = dir.path().join("other.txt");

        fs::write(&a_path, b"x").unwrap();
        fs::write(&b_path, b"y").unwrap();
        fs::write(&other_path, b"z").unwrap();

        let pattern = dir.path().join("*.env").to_string_lossy().into_owned();
        let mut result = expand_paths(&[pattern]).unwrap();
        result.sort();
        let mut expected = vec![
            a_path.to_string_lossy().into_owned(),
            b_path.to_string_lossy().into_owned(),
        ];
        expected.sort();
        assert_eq!(result, expected);
    }

    #[test]
    fn non_glob_passthrough() {
        let result = expand_paths(&["exact/path.env".to_string()]).unwrap();
        assert_eq!(result, vec!["exact/path.env"]);
    }

    #[test]
    fn empty_glob_returns_error() {
        let dir = tempdir().unwrap();
        let pattern = dir.path().join("*.nothing").to_string_lossy().into_owned();
        let result = expand_paths(&[pattern]);
        assert!(result.is_err());
    }
}
