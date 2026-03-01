use std::path::PathBuf;

use clap::Args;

use crate::config::Config;
use crate::error::{Result, VaultError};

#[derive(Args, Debug)]
pub struct ImportArgs {
    /// Input ZIP file path
    pub input: PathBuf,
}

pub fn run(_args: &ImportArgs, _config: &Config) -> Result<()> {
    Err(VaultError::NotImplemented)
}
