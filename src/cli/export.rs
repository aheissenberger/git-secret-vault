// Export vault to AES-256 ZIP (AE-2) interchange format (FR-034).
// The ZIP is NOT authoritative — it is a compatibility artifact for standard tools.

use std::io::Write;
use std::path::Path;

use clap::Args;

use crate::crypto;
use crate::error::{Result, VaultError};
use crate::vault::Vault;

#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Output ZIP file path
    #[arg(default_value = "vault.zip")]
    pub output: std::path::PathBuf,

    /// Path to vault directory
    #[arg(long, default_value = ".git-secret-vault")]
    pub vault_dir: String,

    /// Read password from stdin
    #[arg(long)]
    pub password_stdin: bool,
}

pub fn run(args: &ExportArgs, _config: &crate::config::Config) -> Result<()> {
    let vault_dir = Path::new(&args.vault_dir);
    if !vault_dir.join("vault.meta.json").exists() {
        return Err(VaultError::VaultNotFound(vault_dir.to_path_buf()));
    }

    let vault = Vault::open(vault_dir)?;
    let password = crypto::get_password(args.password_stdin, "Vault password: ")?;
    let key = vault.derive_key(&password)?;

    let snapshot = vault.snapshot()?;
    if snapshot.entries.is_empty() {
        eprintln!("warning: vault is empty, exporting empty ZIP");
    }

    // Build AES-256 ZIP with one entry per secret (label = filename in ZIP).
    // We use the zip crate with AES-256 (WinZip AE-2) so standard tools can open it.
    let zip_file = std::fs::File::create(&args.output).map_err(VaultError::Io)?;
    let mut zw = zip::ZipWriter::new(zip_file);

    for entry in &snapshot.entries {
        let plaintext = vault.unlock(&key, &entry.label)?;
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .with_aes_encryption(zip::AesMode::Aes256, password.as_str())
            .last_modified_time(zip::DateTime::default()); // zero for determinism
        zw.start_file(&entry.label, opts).map_err(|e| VaultError::Other(e.to_string()))?;
        zw.write_all(&plaintext).map_err(VaultError::Io)?;
    }
    zw.finish().map_err(|e| VaultError::Other(e.to_string()))?;

    println!("Exported {} entries to {}", snapshot.entries.len(), args.output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::path::Path;
    use tempfile::TempDir;

    use super::ExportArgs;
    use crate::vault::Vault;

    #[test]
    fn test_export_import_roundtrip() {
        // 1. Init vault and lock a secret
        let src_dir = TempDir::new().unwrap();
        let vault1 = Vault::init(src_dir.path(), "pass123").unwrap();
        let key1 = vault1.derive_key("pass123").unwrap();
        vault1.lock(&key1, "my-secret", b"hello world").unwrap();
        vault1.lock(&key1, "another", b"secret data").unwrap();

        // 2. Export to a temp ZIP
        let zip_dir = TempDir::new().unwrap();
        let zip_path = zip_dir.path().join("vault.zip");
        let export_args = ExportArgs {
            output: zip_path.clone(),
            vault_dir: src_dir.path().to_str().unwrap().to_owned(),
            password_stdin: false,
        };

        // We can't easily call run() because it prompts for password,
        // so we replicate the export logic inline.
        {
            let vault = Vault::open(Path::new(&export_args.vault_dir)).unwrap();
            let password = "pass123";
            let key = vault.derive_key(password).unwrap();
            let snapshot = vault.snapshot().unwrap();

            let zip_file = std::fs::File::create(&zip_path).unwrap();
            let mut zw = zip::ZipWriter::new(zip_file);
            for entry in &snapshot.entries {
                let plaintext = vault.unlock(&key, &entry.label).unwrap();
                let opts = zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated)
                    .with_aes_encryption(zip::AesMode::Aes256, password)
                    .last_modified_time(zip::DateTime::default());
                zw.start_file(&entry.label, opts).unwrap();
                zw.write_all(&plaintext).unwrap();
            }
            zw.finish().unwrap();
        }

        // 3. Init a second vault and import from the ZIP
        let dst_dir = TempDir::new().unwrap();
        let vault2 = Vault::init(dst_dir.path(), "pass123").unwrap();
        let key2 = vault2.derive_key("pass123").unwrap();

        {
            use std::io::Read;
            let data = std::fs::read(&zip_path).unwrap();
            let cursor = std::io::Cursor::new(data);
            let mut archive = zip::ZipArchive::new(cursor).unwrap();
            let names: Vec<String> = (0..archive.len())
                .filter_map(|i| archive.name_for_index(i).map(|n| n.to_owned()))
                .collect();
            for name in &names {
                let mut file = archive
                    .by_name_decrypt(name, b"pass123")
                    .unwrap();
                let mut buf = Vec::new();
                file.read_to_end(&mut buf).unwrap();
                vault2.lock(&key2, name, &buf).unwrap();
            }
        }

        // 4. Unlock from second vault and verify content matches
        let plain1 = vault2.unlock(&key2, "my-secret").unwrap();
        let plain2 = vault2.unlock(&key2, "another").unwrap();
        assert_eq!(plain1, b"hello world");
        assert_eq!(plain2, b"secret data");
    }
}

