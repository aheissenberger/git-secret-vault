use crate::config::{CONFIG_FILE, Config, ConflictDefault};
use crate::error::{Result, VaultError};
use clap::{Args, Subcommand};
use std::path::Path;

#[derive(Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub subcommand: ConfigSubcommand,
}

#[derive(Subcommand)]
pub enum ConfigSubcommand {
    /// Print current effective config
    Show {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Update a single config setting
    Set {
        #[arg(long)]
        vault: Option<String>,
        #[arg(long)]
        index: Option<String>,
        /// One of: prompt, force, keep-local, keep-both
        #[arg(long)]
        conflict_default: Option<String>,
        #[arg(long)]
        diff_tool: Option<String>,
        #[arg(long)]
        min_password_length: Option<u8>,
        #[arg(long)]
        status_privacy_mode: Option<bool>,
        #[arg(long)]
        include: Option<String>,
        #[arg(long)]
        exclude: Option<String>,
        #[arg(long)]
        keyring_namespace: Option<String>,
    },
    /// Write a default config file (errors if one already exists)
    Init,
}

pub fn run(args: &ConfigArgs, _quiet: bool, _verbose: bool) -> Result<()> {
    match &args.subcommand {
        ConfigSubcommand::Show { json } => cmd_show(*json),
        ConfigSubcommand::Set {
            vault,
            index,
            conflict_default,
            diff_tool,
            min_password_length,
            status_privacy_mode,
            include,
            exclude,
            keyring_namespace,
        } => cmd_set(
            vault,
            index,
            conflict_default,
            diff_tool,
            *min_password_length,
            *status_privacy_mode,
            include,
            exclude,
            keyring_namespace,
        ),
        ConfigSubcommand::Init => cmd_init(),
    }
}

fn cmd_show(json: bool) -> Result<()> {
    let cfg = Config::load_default()?;
    if json {
        let out = serde_json::to_string_pretty(&cfg).map_err(VaultError::Json)?;
        println!("{out}");
    } else {
        let conflict = format!("{:?}", cfg.conflict_default).to_lowercase();
        let diff = cfg.diff_tool.as_deref().unwrap_or("(none)");
        println!("vault:                 {}", cfg.vault);
        println!("index:                 {}", cfg.index);
        println!("conflict_default:      {conflict}");
        println!("diff_tool:             {diff}");
        println!("password_min_length:   {}", cfg.password_min_length);
        println!("status_privacy_mode:   {}", cfg.status_privacy_mode);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_set(
    vault: &Option<String>,
    index: &Option<String>,
    conflict_default: &Option<String>,
    diff_tool: &Option<String>,
    min_password_length: Option<u8>,
    status_privacy_mode: Option<bool>,
    include: &Option<String>,
    exclude: &Option<String>,
    keyring_namespace: &Option<String>,
) -> Result<()> {
    let mut cfg = Config::load_default()?;
    if let Some(v) = vault {
        cfg.vault = v.clone();
    }
    if let Some(v) = index {
        cfg.index = v.clone();
    }
    if let Some(v) = conflict_default {
        cfg.conflict_default = parse_conflict_default(v)?;
    }
    if let Some(v) = diff_tool {
        cfg.diff_tool = if v.is_empty() { None } else { Some(v.clone()) };
    }
    if let Some(v) = min_password_length {
        cfg.password_min_length = v;
    }
    if let Some(v) = status_privacy_mode {
        cfg.status_privacy_mode = v;
    }
    if let Some(v) = include {
        cfg.include = if v.is_empty() {
            Vec::new()
        } else {
            v.split(',').map(|s| s.trim().to_owned()).collect()
        };
    }
    if let Some(v) = exclude {
        cfg.exclude = if v.is_empty() {
            Vec::new()
        } else {
            v.split(',').map(|s| s.trim().to_owned()).collect()
        };
    }
    if let Some(v) = keyring_namespace {
        cfg.keyring_namespace = v.clone();
    }
    cfg.save(Path::new(CONFIG_FILE))?;
    Ok(())
}

fn cmd_init() -> Result<()> {
    let path = Path::new(CONFIG_FILE);
    if path.exists() {
        return Err(VaultError::Other(format!(
            "config file already exists: {CONFIG_FILE}"
        )));
    }
    Config::default().save(path)?;
    println!("Created {CONFIG_FILE}");
    Ok(())
}

fn parse_conflict_default(s: &str) -> Result<ConflictDefault> {
    match s {
        "prompt" => Ok(ConflictDefault::Prompt),
        "force" => Ok(ConflictDefault::Force),
        "keep-local" => Ok(ConflictDefault::KeepLocal),
        "keep-both" => Ok(ConflictDefault::KeepBoth),
        other => Err(VaultError::Other(format!(
            "unknown conflict-default value: {other}"
        ))),
    }
}
