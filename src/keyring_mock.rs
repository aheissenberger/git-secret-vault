//! File-based keyring backend for dev/test environments.
//!
//! Activated when `GSV_KEYRING_BACKEND=mock` is set. Reads/writes credentials
//! as files under `GSV_MOCK_KEYRING_DIR/items/`, using the same SHA-256 keying
//! scheme as `scripts/mock-keyring.sh`, so the shell scripts and the binary
//! share the same store during a `run-with-keyring.sh` session.

use std::io::Write;
use std::path::PathBuf;

fn is_mock_active() -> bool {
    std::env::var("GSV_KEYRING_BACKEND")
        .map(|v| v == "mock")
        .unwrap_or(false)
}

fn store_dir() -> PathBuf {
    let base = std::env::var("GSV_MOCK_KEYRING_DIR").unwrap_or_else(|_| {
        format!(
            "{}/gsv-mock-keyring-default",
            std::env::temp_dir().display()
        )
    });
    PathBuf::from(base).join("items")
}

fn key_file(app: &str, id: &str) -> PathBuf {
    // Match the sha256sum output format used in mock-keyring.sh
    let input = format!("{app}::{id}");
    let digest = sha256_hex(input.as_bytes());
    store_dir().join(digest)
}

/// Compute a SHA-256 hex digest by calling the system `sha256sum` command,
/// matching the scheme used in `scripts/mock-keyring.sh`. Falls back to a
/// simple FNV-1a fold if the command is unavailable.
fn sha256_hex(data: &[u8]) -> String {
    // Use the system sha256sum command — same approach the shell script uses.
    let output = std::process::Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| {
            if let Some(mut s) = child.stdin.take() {
                let _ = s.write_all(data);
            }
            child.wait_with_output()
        });

    match output {
        Ok(out) if out.status.success() => {
            // sha256sum prints "<hex>  -\n"
            String::from_utf8_lossy(&out.stdout)
                .split_whitespace()
                .next()
                .unwrap_or("fallback")
                .to_owned()
        }
        _ => {
            // Last-resort: use a simple XOR-fold to produce a deterministic filename.
            // Not cryptographically strong but unique enough for test isolation.
            let mut h: u64 = 0xcbf29ce484222325;
            for &b in data {
                h ^= b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
            format!("{h:016x}")
        }
    }
}

/// Retrieve a password from the file-based mock keyring.
/// Returns `None` if the entry does not exist.
pub fn mock_get(app: &str, id: &str) -> Option<String> {
    if !is_mock_active() {
        return None;
    }
    let file = key_file(app, id);
    let content = std::fs::read_to_string(file).ok()?;
    // File format: line1=app, line2=id, line3=secret
    content.lines().nth(2).map(|s| s.to_owned())
}

/// Store a password in the file-based mock keyring.
pub fn mock_set(app: &str, id: &str, secret: &str) -> std::io::Result<()> {
    if !is_mock_active() {
        return Ok(());
    }
    let dir = store_dir();
    std::fs::create_dir_all(&dir)?;
    let file = key_file(app, id);
    let mut f = std::fs::File::create(file)?;
    writeln!(f, "{app}")?;
    writeln!(f, "{id}")?;
    writeln!(f, "{secret}")?;
    Ok(())
}

/// Delete a password entry from the file-based mock keyring.
pub fn mock_delete(app: &str, id: &str) -> std::io::Result<()> {
    if !is_mock_active() {
        return Ok(());
    }
    let file = key_file(app, id);
    if file.exists() {
        std::fs::remove_file(file)?;
    }
    Ok(())
}

/// Returns true when the mock backend is active.
pub fn is_mock() -> bool {
    is_mock_active()
}

// ── Combined helpers (mock → system keyring dispatch) ──────────────────────

pub const SERVICE: &str = "git-secret-vault";

/// Get a password: uses file mock when active, otherwise falls back to system keyring.
pub fn get_password(id: &str) -> Option<String> {
    if is_mock_active() {
        return mock_get(SERVICE, id);
    }
    keyring::Entry::new(SERVICE, id)
        .ok()
        .and_then(|e| e.get_password().ok())
}

/// Set a password: uses file mock when active, otherwise falls back to system keyring.
pub fn set_password(id: &str, secret: &str) -> std::result::Result<(), String> {
    if is_mock_active() {
        return mock_set(SERVICE, id, secret).map_err(|e| e.to_string());
    }
    keyring::Entry::new(SERVICE, id)
        .map_err(|e| e.to_string())?
        .set_password(secret)
        .map_err(|e| e.to_string())
}

/// Delete a credential: uses file mock when active, otherwise falls back to system keyring.
pub fn delete_password(id: &str) -> std::result::Result<(), String> {
    if is_mock_active() {
        return mock_delete(SERVICE, id).map_err(|e| e.to_string());
    }
    keyring::Entry::new(SERVICE, id)
        .map_err(|e| e.to_string())?
        .delete_credential()
        .map_err(|e| e.to_string())
}
