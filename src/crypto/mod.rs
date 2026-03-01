// Password prompt and memory hygiene (SEC-005, FR-005).

use crate::error::{Result, VaultError};
use zeroize::Zeroizing;

/// Read password from stdin (CI / `--password-stdin` mode).
pub fn read_password_stdin() -> Result<Zeroizing<String>> {
    use std::io::{self, BufRead};
    let stdin = io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line).map_err(VaultError::Io)?;
    // Trim trailing newline; wrap in Zeroizing so memory is cleared on drop.
    Ok(Zeroizing::new(
        line.trim_end_matches(['\n', '\r']).to_owned(),
    ))
}

/// Prompt the user for a password interactively (hidden input).
pub fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(VaultError::Io)
}

/// Prompt for a new password twice and verify they match.
pub fn prompt_new_password() -> Result<Zeroizing<String>> {
    loop {
        let pw1 = prompt_password("New vault password: ")?;
        let pw2 = prompt_password("Confirm password:   ")?;
        if *pw1 == *pw2 {
            return Ok(pw1);
        }
        eprintln!("Passwords do not match. Try again.");
    }
}

/// Obtain password either from stdin, env var, or interactively.
///
/// If `VAULT_PASSWORD` is set and `from_stdin` is false, the env-var value is
/// used but a warning is emitted to stderr (SEC-004).
pub fn get_password(from_stdin: bool, prompt: &str) -> Result<Zeroizing<String>> {
    if from_stdin {
        read_password_stdin()
    } else if let Ok(val) = std::env::var("VAULT_PASSWORD") {
        eprintln!(
            "warning: Using VAULT_PASSWORD environment variable exposes password via \
             process environment and system logs. Consider using --password-stdin instead."
        );
        Ok(Zeroizing::new(val))
    } else {
        prompt_password(prompt)
    }
}

/// Validate that a password meets the minimum strength requirements (SEC-002).
///
/// Call this after obtaining a password for *write* operations (lock/init).
/// Do NOT call it for unlock/verify (read) operations.
#[allow(dead_code)]
pub fn validate_password_strength(password: &str) -> Result<()> {
    if password.len() < 8 {
        return Err(VaultError::Other(
            "Password must be at least 8 characters".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_password_strength_accepts_long_enough() {
        assert!(validate_password_strength("12345678").is_ok());
        assert!(validate_password_strength("correct horse battery staple").is_ok());
    }

    #[test]
    fn validate_password_strength_rejects_short() {
        let err = validate_password_strength("short").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("at least 8 characters"), "got: {msg}");
    }

    #[test]
    fn validate_password_strength_rejects_empty() {
        assert!(validate_password_strength("").is_err());
    }

    #[test]
    fn validate_password_strength_rejects_exactly_seven() {
        assert!(validate_password_strength("1234567").is_err());
    }
}
