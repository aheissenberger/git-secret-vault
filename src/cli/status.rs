use std::path::Path;

use clap::Args;

use crate::error::{Result, VaultError};
use crate::vault::index::OuterIndex;

#[derive(Args)]
pub struct StatusArgs {
    /// Path to outer index file
    #[arg(long, default_value = ".git-secret-vault.index.json")]
    pub index: String,

    /// Output machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &StatusArgs, quiet: bool) -> Result<()> {
    let index_path = Path::new(&args.index);

    if !index_path.exists() {
        return Err(VaultError::VaultNotFound(args.index.clone()));
    }

    let outer = OuterIndex::read(index_path)?;

    if args.json {
        // Output only approved summary fields – no filenames (SEC-001).
        let out = serde_json::json!({
            "uuid": outer.uuid,
            "format_version": outer.format_version,
            "updated_at": outer.updated_at,
            "entry_count": outer.entry_count,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else if !quiet {
        println!("Vault UUID:    {}", outer.uuid);
        println!("Format:        v{}", outer.format_version);
        println!("Last updated:  {}", outer.updated_at);
        println!("Entries:       {}", outer.entry_count);
    }

    Ok(())
}
