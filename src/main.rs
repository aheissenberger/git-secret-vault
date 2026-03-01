mod cli;
mod config;
mod crypto;
mod error;
mod fs;
mod vault;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};

fn main() -> Result<()> {
    let cli = Cli::parse();
    let result = match &cli.command {
        Commands::Init(args) => cli::init::run(args, cli.quiet),
        Commands::Lock(args) => cli::lock::run(args, cli.quiet),
        Commands::Unlock(args) => cli::unlock::run(args, cli.quiet),
        Commands::Status(args) => cli::status::run(args, cli.quiet),
        Commands::Rm(args) => cli::rm::run(args, cli.quiet),
        Commands::Verify(args) => cli::verify::run(args, cli.quiet),
        Commands::Clean(args) => cli::clean::run(args, cli.quiet),
        Commands::Doctor(args) => cli::doctor::run(args, cli.quiet),
        Commands::Compat(args) => cli::compat::run(args, cli.quiet),
        Commands::Harden(args) => cli::harden::run(args, cli.quiet),
        Commands::Passwd(args) => cli::passwd::run(args, cli.quiet),
        Commands::Policy(args) => cli::policy::run(args, cli.quiet),
        Commands::Diff(args) => cli::diff::run(args, cli.quiet),
        Commands::Completions(args) => cli::completions::run(args),
        Commands::Config(args) => cli::config_cmd::run(args, cli.quiet),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
    Ok(())
}
