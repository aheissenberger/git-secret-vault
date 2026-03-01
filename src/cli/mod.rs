pub mod init;
pub mod lock;
pub mod status;
pub mod unlock;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "git-secret-vault",
    about = "SafeZipVault – encrypted secret vault for git repos"
)]
pub struct Cli {
    /// Suppress non-error output
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create a new vault in the current repository
    Init(init::InitArgs),
    /// Encrypt files into the vault
    Lock(lock::LockArgs),
    /// Decrypt files from the vault
    Unlock(unlock::UnlockArgs),
    /// Show vault status without requiring password
    Status(status::StatusArgs),
}
