//! Tests for XChaCha20-Poly1305 AEAD properties (SEC-003, SEC-004).

use git_secret_vault::crypto::{
    content_hash, decrypt_blob, derive_key, encrypt_blob, generate_salt,
};

#[test]
fn encrypt_decrypt_round_trip() {
    let salt = generate_salt();
    let key = derive_key(b"test-password", &salt).unwrap();
    let plaintext = b"my secret data";
    let ciphertext = encrypt_blob(&*key, plaintext).unwrap();
    let decrypted = decrypt_blob(&*key, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn encrypt_is_non_deterministic() {
    // XChaCha20-Poly1305 with random nonce — same plaintext produces different ciphertext
    let salt = generate_salt();
    let key = derive_key(b"test-password", &salt).unwrap();
    let plaintext = b"same plaintext";
    let ct1 = encrypt_blob(&*key, plaintext).unwrap();
    let ct2 = encrypt_blob(&*key, plaintext).unwrap();
    assert_ne!(ct1, ct2, "encryption must be non-deterministic (random nonce)");
}

#[test]
fn nonce_is_prepended_24_bytes() {
    let salt = generate_salt();
    let key = derive_key(b"test-password", &salt).unwrap();
    let plaintext = b"hello";
    let ciphertext = encrypt_blob(&*key, plaintext).unwrap();
    // nonce (24) + plaintext (5) + tag (16) = 45 minimum
    assert!(
        ciphertext.len() >= 24 + plaintext.len() + 16,
        "ciphertext length {} is less than expected minimum {}",
        ciphertext.len(),
        24 + plaintext.len() + 16
    );
}

#[test]
fn tampered_ciphertext_fails_decryption() {
    let salt = generate_salt();
    let key = derive_key(b"test-password", &salt).unwrap();
    let plaintext = b"sensitive data";
    let mut ciphertext = encrypt_blob(&*key, plaintext).unwrap();
    // Flip a byte in the ciphertext (after nonce)
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0xFF;
    let result = decrypt_blob(&*key, &ciphertext);
    assert!(result.is_err(), "tampered ciphertext must fail decryption");
}

#[test]
fn wrong_key_fails_decryption() {
    let salt = generate_salt();
    let key1 = derive_key(b"correct-password", &salt).unwrap();
    let key2 = derive_key(b"wrong-password", &salt).unwrap();
    let plaintext = b"sensitive data";
    let ciphertext = encrypt_blob(&*key1, plaintext).unwrap();
    let result = decrypt_blob(&*key2, &ciphertext);
    assert!(result.is_err(), "wrong key must fail decryption");
}

#[test]
fn content_hash_is_deterministic() {
    let data = b"deterministic input";
    let h1 = content_hash(data);
    let h2 = content_hash(data);
    assert_eq!(h1, h2);
    // Should be lowercase hex SHA-256 (64 chars)
    assert_eq!(h1.len(), 64);
    assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn argon2id_kdf_is_deterministic() {
    let salt = generate_salt();
    let k1 = derive_key(b"password", &salt).unwrap();
    let k2 = derive_key(b"password", &salt).unwrap();
    assert_eq!(*k1, *k2, "same password+salt must always produce same key");
}

#[test]
fn different_passwords_produce_different_keys() {
    let salt = generate_salt();
    let k1 = derive_key(b"password1", &salt).unwrap();
    let k2 = derive_key(b"password2", &salt).unwrap();
    assert_ne!(*k1, *k2);
}
