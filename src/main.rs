mod cli;
mod config;
mod crypto;
mod error;
mod fs;
mod keyring_mock;
mod vault;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.mcp {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(git_secret_vault::mcp::run_mcp_server(
                &cli.vault, &cli.index,
            ))
            .unwrap_or_else(|e| {
                eprintln!("MCP server error: {e}");
                std::process::exit(1);
            });
        return Ok(());
    }

    let Some(command) = &cli.command else {
        eprintln!("error: a subcommand is required (or use --mcp to start the MCP server)");
        std::process::exit(2);
    };

    let result = match command {
        Commands::Init(args) => cli::init::run(args, cli.quiet, cli.verbose),
        Commands::Lock(args) => cli::lock::run(args, cli.quiet, cli.verbose),
        Commands::Unlock(args) => cli::unlock::run(args, cli.quiet, cli.verbose),
        Commands::Status(args) => cli::status::run(args, cli.quiet, cli.verbose),
        Commands::Rm(args) => cli::rm::run(args, cli.quiet, cli.verbose),
        Commands::Verify(args) => cli::verify::run(args, cli.quiet, cli.verbose),
        Commands::Clean(args) => cli::clean::run(args, cli.quiet, cli.verbose),
        Commands::Doctor(args) => cli::doctor::run(args, cli.quiet, cli.verbose),
        Commands::Compat(args) => cli::compat::run(args, cli.quiet, cli.verbose),
        Commands::Harden(args) => cli::harden::run(args, cli.quiet, cli.verbose),
        Commands::Passwd(args) => cli::passwd::run(args, cli.quiet, cli.verbose),
        Commands::Policy(args) => cli::policy::run(args, cli.quiet, cli.verbose),
        Commands::Diff(args) => cli::diff::run(args, cli.quiet, cli.verbose),
        Commands::Completions(args) => cli::completions::run(args),
        Commands::Config(args) => cli::config_cmd::run(args, cli.quiet, cli.verbose),
        Commands::Keyring(args) => cli::keyring_cmd::run(args, cli.quiet, cli.verbose),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
    Ok(())
}
