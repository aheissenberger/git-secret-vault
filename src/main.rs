mod cli;
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
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
    Ok(())
}
