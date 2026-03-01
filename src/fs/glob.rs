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

    #[test]
    fn expand_glob_matches_files() {
        let dir = tempdir().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        fs::write("a.env", b"x").unwrap();
        fs::write("b.env", b"y").unwrap();
        fs::write("other.txt", b"z").unwrap();
        let mut result = expand_paths(&["*.env".to_string()]).unwrap();
        result.sort();
        assert_eq!(result, vec!["a.env", "b.env"]);
        std::env::set_current_dir(prev).unwrap();
    }

    #[test]
    fn non_glob_passthrough() {
        let result = expand_paths(&["exact/path.env".to_string()]).unwrap();
        assert_eq!(result, vec!["exact/path.env"]);
    }

    #[test]
    fn empty_glob_returns_error() {
        let dir = tempdir().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let result = expand_paths(&["*.nothing".to_string()]);
        std::env::set_current_dir(prev).unwrap();
        assert!(result.is_err());
    }
}
