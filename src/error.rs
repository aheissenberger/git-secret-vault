use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Path traversal detected in entry: {0}")]
    PathTraversal(String),

    #[error("Vault already exists at {0}")]
    VaultExists(String),

    #[error("Vault not found at {0}")]
    VaultNotFound(String),

    #[error("Wrong password or corrupt vault")]
    WrongPassword,

    #[error("Conflict: {0} already exists (use --force to overwrite)")]
    ConflictExists(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, VaultError>;
