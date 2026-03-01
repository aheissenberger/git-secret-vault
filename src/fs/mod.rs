// Filesystem safety: path validation and atomic writes (SEC-006, NFR-003).

use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

use crate::error::{Result, VaultError};

/// Reject absolute paths and `..` traversal; return canonicalized path
/// relative to `root`. Satisfies SEC-006 (zip-slip prevention).
pub fn safe_join(root: &Path, entry_path: &str) -> Result<PathBuf> {
    let entry = Path::new(entry_path);

    for component in entry.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => {
                return Err(VaultError::PathTraversal(entry_path.to_owned()));
            }
            Component::ParentDir => {
                return Err(VaultError::PathTraversal(entry_path.to_owned()));
            }
            _ => {}
        }
    }

    let joined = root.join(entry);
    // Ensure the resulting path stays inside root after normalization.
    let canonical_root = root.canonicalize().map_err(VaultError::Io)?;
    // The joined path may not exist yet – walk components manually.
    let mut resolved = canonical_root.clone();
    for component in entry.components() {
        match component {
            Component::Normal(part) => resolved.push(part),
            _ => return Err(VaultError::PathTraversal(entry_path.to_owned())),
        }
    }

    if !resolved.starts_with(&canonical_root) {
        return Err(VaultError::PathTraversal(entry_path.to_owned()));
    }

    Ok(joined)
}

/// Write `data` to `dest` atomically: write to a temp file in the same
/// directory, fsync, then rename. Satisfies NFR-003.
pub fn atomic_write(dest: &Path, data: &[u8]) -> Result<()> {
    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(VaultError::Io)?;

    let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(VaultError::Io)?;
    tmp.write_all(data).map_err(VaultError::Io)?;
    tmp.flush().map_err(VaultError::Io)?;
    // Best-effort fsync.
    let _ = tmp.as_file().sync_all();
    tmp.persist(dest)
        .map_err(|e: tempfile::PersistError| VaultError::Io(e.error))?;
    Ok(())
}

/// Write file content atomically with parent directory creation.
pub fn write_file(dest: &Path, data: &[u8]) -> io::Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut tmp = tempfile::NamedTempFile::new_in(dest.parent().unwrap_or_else(|| Path::new(".")))?;
    tmp.write_all(data)?;
    tmp.flush()?;
    let _ = tmp.as_file().sync_all();
    tmp.persist(dest)
        .map_err(|e: tempfile::PersistError| e.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    // --- safe_join ---

    #[test]
    fn safe_join_simple_relative_path_succeeds() {
        let dir = tempdir().unwrap();
        let result = safe_join(dir.path(), "secrets/db.env");
        assert!(result.is_ok(), "simple relative path should be accepted");
        assert!(result.unwrap().ends_with("secrets/db.env"));
    }

    #[test]
    fn safe_join_flat_filename_succeeds() {
        let dir = tempdir().unwrap();
        assert!(safe_join(dir.path(), "file.env").is_ok());
    }

    #[test]
    fn safe_join_absolute_path_rejected() {
        let dir = tempdir().unwrap();
        let err = safe_join(dir.path(), "/etc/passwd").unwrap_err();
        assert!(
            matches!(err, VaultError::PathTraversal(_)),
            "absolute path must be rejected"
        );
    }

    #[test]
    fn safe_join_parent_traversal_rejected() {
        let dir = tempdir().unwrap();
        let err = safe_join(dir.path(), "a/../../../etc/passwd").unwrap_err();
        assert!(
            matches!(err, VaultError::PathTraversal(_)),
            ".. traversal must be rejected"
        );
    }

    #[test]
    fn safe_join_dotdot_at_start_rejected() {
        let dir = tempdir().unwrap();
        let err = safe_join(dir.path(), "../sibling").unwrap_err();
        assert!(matches!(err, VaultError::PathTraversal(_)));
    }

    // --- atomic_write ---

    #[test]
    fn atomic_write_creates_file_with_correct_content() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("output.bin");
        atomic_write(&dest, b"hello vault").unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"hello vault");
    }

    #[test]
    fn atomic_write_overwrites_existing_file() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("out.bin");
        atomic_write(&dest, b"first").unwrap();
        atomic_write(&dest, b"second").unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"second");
    }

    #[test]
    fn atomic_write_creates_parent_directories() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("deep/nested/file.txt");
        atomic_write(&dest, b"data").unwrap();
        assert!(dest.exists());
    }

    // --- write_file ---

    #[test]
    fn write_file_creates_file_with_correct_content() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("out.txt");
        write_file(&dest, b"write_file content").unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"write_file content");
    }

    #[test]
    fn write_file_creates_nested_parents() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("a/b/c.txt");
        write_file(&dest, b"nested").unwrap();
        assert!(dest.exists());
    }

    #[test]
    fn write_file_overwrites_existing() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("f.txt");
        write_file(&dest, b"v1").unwrap();
        write_file(&dest, b"v2").unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"v2");
    }
}
