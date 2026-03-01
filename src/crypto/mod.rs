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

/// Obtain password either from stdin or interactively.
pub fn get_password(from_stdin: bool, prompt: &str) -> Result<Zeroizing<String>> {
    if from_stdin {
        read_password_stdin()
    } else {
        prompt_password(prompt)
    }
}
