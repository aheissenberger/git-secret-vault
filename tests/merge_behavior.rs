//! Tests for dual-profile merge behavior (FR-031, FR-030).
//!
//! Per-file blobs + append-only event log means two agents can independently
//! add different secrets and merge cleanly (no conflicts on unrelated entries).

use git_secret_vault::vault::{event_log::read_events, snapshot::load_snapshot, Vault};
use tempfile::tempdir;

fn init_vault(dir: &std::path::Path, password: &str) -> Vault {
    Vault::init(dir, password).unwrap()
}

#[test]
fn two_independent_adds_produce_two_entries() {
    // Simulate two agents adding different entries to the same vault directory.
    // In a real merge, events.jsonl lines from both would be concatenated.
    let dir = tempdir().unwrap();
    let vault = init_vault(dir.path(), "pw");
    let key = vault.derive_key("pw").unwrap();

    vault.lock(&*key, "agent-a-secret", b"value-a").unwrap();
    vault.lock(&*key, "agent-b-secret", b"value-b").unwrap();

    let snap = vault.snapshot().unwrap();
    assert_eq!(snap.entries.len(), 2);
    let labels: Vec<&str> = snap.entries.iter().map(|e| e.label.as_str()).collect();
    assert!(labels.contains(&"agent-a-secret"));
    assert!(labels.contains(&"agent-b-secret"));
}

#[test]
fn update_same_entry_uses_latest_event() {
    let dir = tempdir().unwrap();
    let vault = init_vault(dir.path(), "pw");
    let key = vault.derive_key("pw").unwrap();

    vault.lock(&*key, "secret", b"version-1").unwrap();
    vault.lock(&*key, "secret", b"version-2").unwrap();

    // Only one entry in snapshot (update, not duplicate)
    let snap = vault.snapshot().unwrap();
    assert_eq!(snap.entries.len(), 1);

    // Unlock gives latest value
    let plaintext = vault.unlock(&*key, "secret").unwrap();
    assert_eq!(plaintext, b"version-2");
}

#[test]
fn remove_followed_by_add_restores_entry() {
    let dir = tempdir().unwrap();
    let vault = init_vault(dir.path(), "pw");
    let key = vault.derive_key("pw").unwrap();

    vault.lock(&*key, "secret", b"original").unwrap();
    vault.remove(&*key, "secret").unwrap();
    vault.lock(&*key, "secret", b"restored").unwrap();

    let snap = vault.snapshot().unwrap();
    assert_eq!(snap.entries.len(), 1);
    assert_eq!(vault.unlock(&*key, "secret").unwrap(), b"restored");
}

#[test]
fn events_are_append_only() {
    let dir = tempdir().unwrap();
    let vault = init_vault(dir.path(), "pw");
    let key = vault.derive_key("pw").unwrap();

    vault.lock(&*key, "a", b"1").unwrap();
    vault.lock(&*key, "b", b"2").unwrap();
    vault.remove(&*key, "a").unwrap();

    let events = read_events(dir.path()).unwrap();
    // Events: add(a), add(b), remove(a) — all three preserved
    assert_eq!(events.len(), 3);
    // Snapshot reflects final state: only b
    let snap = load_snapshot(dir.path()).unwrap();
    assert_eq!(snap.entries.len(), 1);
    assert_eq!(snap.entries[0].label, "b");
}

#[test]
fn blobs_are_content_addressed() {
    let dir = tempdir().unwrap();
    let vault = init_vault(dir.path(), "pw");
    let key = vault.derive_key("pw").unwrap();

    vault.lock(&*key, "a", b"same-content").unwrap();
    vault.lock(&*key, "b", b"same-content").unwrap();

    // Both entries should reference the same content_hash
    let snap = vault.snapshot().unwrap();
    assert_eq!(snap.entries.len(), 2);
    // Content hashes should be equal (same plaintext = same hash)
    assert_eq!(snap.entries[0].content_hash, snap.entries[1].content_hash);

    // But only one blob file on disk (deduplication via content addressing)
    let blob_files: Vec<_> = std::fs::read_dir(dir.path().join("blobs"))
        .unwrap()
        .collect();
    assert_eq!(blob_files.len(), 1, "same content should produce one blob file");
}

#[test]
fn no_plaintext_paths_in_meta() {
    let dir = tempdir().unwrap();
    let vault = init_vault(dir.path(), "pw");
    let key = vault.derive_key("pw").unwrap();
    vault.lock(&*key, "my-secret.env", b"secret value").unwrap();

    // vault.meta.json must not contain the label "my-secret.env"
    let meta_content =
        std::fs::read_to_string(dir.path().join("vault.meta.json")).unwrap();
    assert!(
        !meta_content.contains("my-secret.env"),
        "vault.meta.json must not contain plaintext labels; got: {meta_content}"
    );

    // Blob filename must not reveal the label either (uses content hash)
    let blob_dir = dir.path().join("blobs");
    for entry in std::fs::read_dir(&blob_dir).unwrap() {
        let filename = entry.unwrap().file_name().into_string().unwrap();
        assert!(
            !filename.contains("secret"),
            "blob filename must not contain label; got: {filename}"
        );
    }
}
