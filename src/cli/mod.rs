pub mod clean;
pub mod compat;
pub mod completions;
pub mod config_cmd;
pub mod diff;
pub mod doctor;
pub mod harden;
pub mod init;
pub mod keyring_cmd;
pub mod lock;
pub mod passwd;
pub mod policy;
pub mod rm;
pub mod status;
pub mod unlock;
pub mod verify;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "git-secret-vault",
    about = "GitSecretVault – encrypted secret vault for git repos",
    version,
    author
)]
pub struct Cli {
    /// Suppress non-error output
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Start MCP (Model Context Protocol) server on stdio for AI assistant integration
    #[arg(long, global = true)]
    pub mcp: bool,

    /// Vault archive path (used with --mcp)
    #[arg(long, global = true, default_value = "vault.zip")]
    pub vault: String,

    /// Vault index path (used with --mcp)
    #[arg(long, global = true, default_value = ".vault-index.json")]
    pub index: String,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create a new vault in the current repository
    Init(init::InitArgs),
    /// Encrypt files into the vault
    Lock(lock::LockArgs),
    /// Decrypt files from the vault
    Unlock(unlock::UnlockArgs),
    /// Show vault status without requiring password (alias: ls)
    #[command(alias = "ls")]
    Status(status::StatusArgs),
    /// Remove entries from the vault
    Rm(rm::RmArgs),
    /// Validate vault integrity
    Verify(verify::VerifyArgs),
    /// Remove unlocked tracked plaintext files safely
    Clean(clean::CleanArgs),
    /// Check encryption profile and tool compatibility
    Compat(compat::CompatArgs),
    /// Diagnose environment readiness
    Doctor(doctor::DoctorArgs),
    /// Update .gitignore and optionally install git hooks
    Harden(harden::HardenArgs),
    /// Show differences between vault entries and local files
    Diff(diff::DiffArgs),
    /// Re-encrypt vault with a new password
    Passwd(passwd::PasswdArgs),
    /// Generate shell completions
    Completions(completions::CompletionsArgs),
    /// Manage password policy settings
    Policy(policy::PolicyArgs),
    /// Read and write repository config file
    Config(config_cmd::ConfigArgs),
    /// Manage system keyring credentials for vault passwords
    Keyring(keyring_cmd::KeyringArgs),
}
