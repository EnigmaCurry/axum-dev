use clap::{self, ArgAction, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_serde_derive::ClapSerde;

use std::{env, path::PathBuf};

use crate::errors::CliError;

use super::{AcmeDnsRegisterConfig, ServeConfig};

#[derive(Parser)]
#[command(
    name = env!("CARGO_BIN_NAME"),
    version = env!("CARGO_PKG_VERSION"),
    author = env!("CARGO_PKG_AUTHORS"),
    about = env!("CARGO_PKG_DESCRIPTION"),
    propagate_version = true
)]
pub struct Cli {
    /// Sets the log level, overriding the RUST_LOG environment variable.
    #[arg(
        long,
        global = true,
        value_name = "LEVEL",
        value_parser = ["trace", "debug", "info", "warn", "error"]
    )]
    pub log: Option<String>,

    /// Increase verbosity (-v, -vv, -vvv, -vvvv)
    #[arg(short = 'v', global = true, action = ArgAction::Count)]
    pub verbose: u8,

    /// Base directory for config + state (like `-C` in many GNU tools).
    ///
    /// When set, relative paths for the database, TLS cache, ACME accounts,
    /// and acme-dns credentials are resolved under this directory, and the
    /// directory is created if needed.
    #[arg(
        short = 'C',
        long = "root-dir",
        env = "ROOT_DIR",
        global = true,
        default_value = default_root_dir().into_os_string(),
        value_name = "DIR",
    )]
    pub root_dir: PathBuf,

    /// Config file
    ///
    /// Defaults to `defaults.toml` in the specified ROOT_DIR, but only
    /// if it exists.
    #[arg(short = 'f', long = "config", env = "CONFIG_FILE")]
    pub config_file: Option<std::path::PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

impl Cli {
    pub fn validate(&self) -> Result<(), CliError> {
        match &self.command {
            // we now validate Serve *after* merging config in run_cli
            Commands::Serve(_) => Ok(()),
            Commands::Completions { .. } => Ok(()),
            Commands::AcmeDnsRegister { .. } => Ok(()),
        }
    }
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generates shell completions script (tab completion).
    Completions {
        /// The shell to generate completions for.
        #[arg(value_parser = ["bash", "zsh", "fish"])]
        shell: Option<String>,
    },

    /// Run the HTTP API server.
    Serve(ServeConfig),

    /// Register or inspect acme-dns credentials used for DNS-01 ACME.
    ///
    /// Run this once before `serve` when using `--tls-mode=acme --tls-acme-challenge=dns-01`,
    /// unless you are providing ACME_DNS_* credentials explicitly.
    AcmeDnsRegister(AcmeDnsRegisterConfig),
}

fn default_root_dir() -> PathBuf {
    // CARGO_BIN_NAME is compile-time, so this is cheap.
    let bin = env!("CARGO_BIN_NAME");

    // 1) If XDG_DATA_HOME is set, prefer it.
    if let Ok(xdg) = env::var("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join(bin);
        }
    }

    // 2) Fallback: ~/.local/share/<bin>
    if let Ok(home) = env::var("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home).join(".local").join("share").join(bin);
        }
    }

    // 3) Last resort: current directory / <bin>-data
    PathBuf::from(format!("{bin}-data"))
}

pub fn app() -> clap::Command {
    Cli::command()
}
