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

/// Like `get_password` but returns `Err` instead of prompting interactively.
///
/// Used for CI/automation flows (FR-005) where no TTY is available.
/// Checks `VAULT_PASSWORD` env var first (with warning), then reads from stdin
/// when `from_stdin` is `true`, otherwise fails fast.
pub fn get_password_no_prompt(from_stdin: bool) -> Result<Zeroizing<String>> {
    if let Ok(val) = std::env::var("VAULT_PASSWORD") {
        eprintln!(
            "warning: Using VAULT_PASSWORD environment variable exposes password via \
             process environment and system logs. Consider using --password-stdin instead."
        );
        return Ok(Zeroizing::new(val));
    }
    if from_stdin {
        return read_password_stdin();
    }
    Err(crate::error::VaultError::Other(
        "--no-prompt: no non-interactive password source available \
         (use --password-stdin or VAULT_PASSWORD)"
            .to_owned(),
    ))
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
    const WEAK_PASSWORDS: &[&str] = &[
        "password", "12345678", "secret123", "qwerty123", "letmein1", "abc12345",
    ];
    if WEAK_PASSWORDS.contains(&password.to_lowercase().as_str()) {
        return Err(VaultError::Other(
            "Password is too common; choose a stronger password".to_owned(),
        ));
    }
    Ok(())
}

/// Obtain password from stdin, env var, system keyring, or interactive prompt.
///
/// Precedence:
/// 1. `from_stdin` → read from stdin
/// 2. `VAULT_PASSWORD` env var → use with warning
/// 3. `vault_uuid` → try system keyring lookup
/// 4. Interactive prompt
///
/// If `require_keyring` is true and keyring lookup fails (missing UUID or no
/// credential), an error is returned instead of falling back to prompt.
pub fn get_password_with_keyring(
    from_stdin: bool,
    vault_uuid: Option<&str>,
    require_keyring: bool,
    prompt: &str,
) -> Result<Zeroizing<String>> {
    if from_stdin {
        return read_password_stdin();
    }
    if let Ok(val) = std::env::var("VAULT_PASSWORD") {
        eprintln!(
            "warning: Using VAULT_PASSWORD environment variable exposes password via \
             process environment and system logs. Consider using --password-stdin instead."
        );
        return Ok(Zeroizing::new(val));
    }
    if let Some(uuid) = vault_uuid {
        let keyring_pw = keyring::Entry::new("git-secret-vault", uuid)
            .ok()
            .and_then(|e| e.get_password().ok());
        match keyring_pw {
            Some(pw) => return Ok(Zeroizing::new(pw)),
            None if require_keyring => {
                return Err(VaultError::Other(format!(
                    "--require-keyring: no credential found in keyring for vault {uuid}"
                )));
            }
            None => {} // fall through to interactive prompt
        }
    } else if require_keyring {
        return Err(VaultError::Other(
            "--require-keyring: no vault UUID available for keyring lookup".to_owned(),
        ));
    }
    prompt_password(prompt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_password_strength_accepts_long_enough() {
        assert!(validate_password_strength("abcdefgh").is_ok());
        assert!(validate_password_strength("correct horse battery staple").is_ok());
    }

    #[test]
    fn validate_password_strength_rejects_weak_passwords() {
        for weak in &["password", "12345678", "secret123", "qwerty123", "letmein1", "abc12345"] {
            let err = validate_password_strength(weak).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("too common"), "expected 'too common' for {weak}: {msg}");
        }
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

    #[test]
    fn get_password_no_prompt_fails_without_source() {
        // SAFETY: single-threaded test context
        unsafe { std::env::remove_var("VAULT_PASSWORD") };
        let result = get_password_no_prompt(false);
        assert!(result.is_err(), "expected Err when no non-interactive source");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("no non-interactive password source"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn get_password_no_prompt_uses_env_var() {
        // SAFETY: single-threaded test context
        unsafe { std::env::set_var("VAULT_PASSWORD", "env-secret") };
        let result = get_password_no_prompt(false);
        unsafe { std::env::remove_var("VAULT_PASSWORD") };
        assert!(result.is_ok(), "expected Ok when VAULT_PASSWORD is set");
        assert_eq!(result.unwrap().as_str(), "env-secret");
    }
}
