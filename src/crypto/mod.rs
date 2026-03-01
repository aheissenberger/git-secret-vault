// Cryptographic primitives: Argon2id KDF, XChaCha20-Poly1305 AEAD, SHA-256 content addressing.
// Password prompt and memory hygiene (SEC-005, FR-005).

use crate::error::{Result, VaultError};
use argon2::{Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const NONCE_LEN: usize = 24;

/// Derive a 32-byte key from `password` and `salt` using Argon2id.
///
/// Params: m_cost=65536 (64 MiB), t_cost=3 iterations, p_cost=4 lanes.
pub fn derive_key(password: &[u8], salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|e| VaultError::Other(format!("argon2 params: {e}")))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| VaultError::Other(format!("argon2 hash: {e}")))?;
    Ok(key)
}

/// Generate a random 16-byte salt.
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Encrypt `plaintext` with XChaCha20-Poly1305.
///
/// Returns `nonce (24 bytes) || ciphertext`.
pub fn encrypt_blob(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| VaultError::Other("encryption failed".to_owned()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob produced by [`encrypt_blob`].
///
/// Expects `nonce (24 bytes) || ciphertext` as input.
pub fn decrypt_blob(key: &[u8; 32], nonce_and_ciphertext: &[u8]) -> Result<Vec<u8>> {
    if nonce_and_ciphertext.len() < NONCE_LEN {
        return Err(VaultError::Other("blob too short to contain nonce".to_owned()));
    }
    let (nonce_bytes, ciphertext) = nonce_and_ciphertext.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VaultError::Other("decryption failed (bad key or corrupted data)".to_owned()))
}

/// SHA-256 of `plaintext` as a lowercase hex string (used for content-addressed blob filenames).
pub fn content_hash(plaintext: &[u8]) -> String {
    let digest = Sha256::digest(plaintext);
    hex::encode(digest)
}

/// Generate a new random UUID v4 key ID.
pub fn generate_key_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

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
pub fn validate_password_strength(password: &str) -> Result<()> {
    if password.len() < 8 {
        return Err(VaultError::Other(
            "Password must be at least 8 characters".to_owned(),
        ));
    }
    const WEAK_PASSWORDS: &[&str] = &[
        "password",
        "12345678",
        "secret123",
        "qwerty123",
        "letmein1",
        "abc12345",
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
        let keyring_pw = crate::keyring_mock::get_password(uuid);
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
    // Serialize tests that mutate VAULT_PASSWORD to avoid race conditions.
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
    use super::*;

    #[test]
    fn validate_password_strength_accepts_long_enough() {
        assert!(validate_password_strength("abcdefgh").is_ok());
        assert!(validate_password_strength("correct horse battery staple").is_ok());
    }

    #[test]
    fn validate_password_strength_rejects_weak_passwords() {
        for weak in &[
            "password",
            "12345678",
            "secret123",
            "qwerty123",
            "letmein1",
            "abc12345",
        ] {
            let err = validate_password_strength(weak).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("too common"),
                "expected 'too common' for {weak}: {msg}"
            );
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
        let _guard = ENV_MUTEX.lock().unwrap();
        // SAFETY: serialized by ENV_MUTEX
        unsafe { std::env::remove_var("VAULT_PASSWORD") };
        let result = get_password_no_prompt(false);
        assert!(
            result.is_err(),
            "expected Err when no non-interactive source"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("no non-interactive password source"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn get_password_no_prompt_uses_env_var() {
        let _guard = ENV_MUTEX.lock().unwrap();
        // SAFETY: serialized by ENV_MUTEX
        unsafe { std::env::set_var("VAULT_PASSWORD", "env-secret") };
        let result = get_password_no_prompt(false);
        unsafe { std::env::remove_var("VAULT_PASSWORD") };
        assert!(result.is_ok(), "expected Ok when VAULT_PASSWORD is set");
        assert_eq!(result.unwrap().as_str(), "env-secret");
    }

    #[test]
    fn derive_key_is_deterministic() {
        let salt = [0u8; 16];
        let key1 = derive_key(b"passphrase", &salt).unwrap();
        let key2 = derive_key(b"passphrase", &salt).unwrap();
        assert_eq!(*key1, *key2);
    }

    #[test]
    fn derive_key_differs_by_password() {
        let salt = [1u8; 16];
        let key1 = derive_key(b"password-a", &salt).unwrap();
        let key2 = derive_key(b"password-b", &salt).unwrap();
        assert_ne!(*key1, *key2);
    }

    #[test]
    fn derive_key_differs_by_salt() {
        let key1 = derive_key(b"same-password", &[0u8; 16]).unwrap();
        let key2 = derive_key(b"same-password", &[1u8; 16]).unwrap();
        assert_ne!(*key1, *key2);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"hello, vault!";
        let blob = encrypt_blob(&key, plaintext).unwrap();
        assert!(blob.len() > NONCE_LEN);
        let recovered = decrypt_blob(&key, &blob).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn decrypt_rejects_wrong_key() {
        let key = [7u8; 32];
        let blob = encrypt_blob(&key, b"secret").unwrap();
        let bad_key = [8u8; 32];
        assert!(decrypt_blob(&bad_key, &blob).is_err());
    }

    #[test]
    fn decrypt_rejects_truncated_blob() {
        let blob = vec![0u8; 10]; // less than NONCE_LEN
        assert!(decrypt_blob(&[0u8; 32], &blob).is_err());
    }

    #[test]
    fn encrypt_produces_random_nonces() {
        let key = [0u8; 32];
        let blob1 = encrypt_blob(&key, b"same").unwrap();
        let blob2 = encrypt_blob(&key, b"same").unwrap();
        assert_ne!(&blob1[..NONCE_LEN], &blob2[..NONCE_LEN]);
    }

    #[test]
    fn content_hash_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = content_hash(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn content_hash_differs_for_different_input() {
        assert_ne!(content_hash(b"a"), content_hash(b"b"));
    }

    #[test]
    fn generate_key_id_is_uuid_format() {
        let id = generate_key_id();
        // UUID v4: 8-4-4-4-12 hex groups
        assert_eq!(id.len(), 36);
        assert_eq!(id.chars().filter(|&c| c == '-').count(), 4);
    }

    #[test]
    fn generate_key_id_is_unique() {
        let a = generate_key_id();
        let b = generate_key_id();
        assert_ne!(a, b);
    }
}
