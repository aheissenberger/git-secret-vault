use std::path::PathBuf;

use clap::Args;

use crate::config::Config;
use crate::error::{Result, VaultError};

#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Output ZIP file path
    #[arg(default_value = "vault.zip")]
    pub output: PathBuf,
}

pub fn run(_args: &ExportArgs, _config: &Config) -> Result<()> {
    Err(VaultError::NotImplemented)
}
