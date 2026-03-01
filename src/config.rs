use crate::error::{Result, VaultError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Conflict resolution policy for unlock.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ConflictDefault {
    #[default]
    Prompt,
    Force,
    KeepLocal,
    KeepBoth,
}

/// Repository-level configuration read from `.git-secret-vault.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Path to the vault directory.
    #[serde(default = "default_vault_dir")]
    pub vault_dir: String,
    /// Default conflict resolution for unlock.
    #[serde(default)]
    pub conflict_default: ConflictDefault,
    /// External diff tool (e.g. "vimdiff"). Used by the diff command.
    #[serde(default)]
    pub diff_tool: Option<String>,
    /// Minimum password length. Overrides the built-in default of 8.
    #[serde(default = "default_min_password_length")]
    pub password_min_length: u8,
    /// When true, status does not reveal entry paths without a password.
    #[serde(default)]
    pub status_privacy_mode: bool,
    /// Glob patterns for files to automatically include when running `lock` with no args.
    #[serde(default)]
    pub include: Vec<String>,
    /// Glob patterns for files to always exclude from `lock` operations.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Override the keyring service namespace (default: "git-secret-vault").
    #[serde(default = "default_keyring_namespace")]
    pub keyring_namespace: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            vault_dir: default_vault_dir(),
            conflict_default: ConflictDefault::default(),
            diff_tool: None,
            password_min_length: default_min_password_length(),
            status_privacy_mode: false,
            include: Vec::new(),
            exclude: Vec::new(),
            keyring_namespace: default_keyring_namespace(),
        }
    }
}

fn default_vault_dir() -> String {
    ".git-secret-vault".to_owned()
}
fn default_min_password_length() -> u8 {
    8
}
fn default_keyring_namespace() -> String {
    "git-secret-vault".to_owned()
}

pub const CONFIG_FILE: &str = ".git-secret-vault.toml";

impl Config {
    /// Load config from the given path, or return defaults if the file doesn't exist.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path).map_err(VaultError::Io)?;
        toml::from_str(&text).map_err(|e| VaultError::Other(format!("config parse error: {e}")))
    }

    /// Load from the default config file in the current directory.
    pub fn load_default() -> Result<Self> {
        Self::load(Path::new(CONFIG_FILE))
    }

    /// Write config to the given path.
    pub fn save(&self, path: &Path) -> Result<()> {
        let text = toml::to_string_pretty(self)
            .map_err(|e| VaultError::Other(format!("config serialize error: {e}")))?;
        crate::fs::atomic_write(path, text.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn load_missing_returns_defaults() {
        let dir = tempdir().unwrap();
        let cfg = Config::load(&dir.path().join("nonexistent.toml")).unwrap();
        assert_eq!(cfg.vault_dir, ".git-secret-vault");
        assert_eq!(cfg.password_min_length, 8);
    }

    #[test]
    fn round_trip_save_and_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = Config {
            password_min_length: 12,
            status_privacy_mode: true,
            ..Default::default()
        };
        cfg.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.password_min_length, 12);
        assert!(loaded.status_privacy_mode);
    }

    #[test]
    fn invalid_toml_returns_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, b"not valid toml ][[[").unwrap();
        assert!(Config::load(&path).is_err());
    }

    #[test]
    fn conflict_default_deserializes_correctly() {
        let toml = r#"conflict_default = "keep-both""#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.conflict_default, ConflictDefault::KeepBoth);
    }
}
