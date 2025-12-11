use std::{env, path::PathBuf};

use crate::errors::CliError;

use super::{AcmeDnsRegisterConfig, ServeConfig};
use conf::{Conf, Subcommands};

#[derive(Conf, Debug, Clone)]
#[conf(serde)]
pub struct Cli {
    /// Sets the log level, overriding the RUST_LOG environment variable.
    #[arg(long)]
    pub log: Option<String>,

    /// Increase verbosity. You can keep your existing semantics,
    /// or simplify this to `bool` and adjust `build_log_level`.
    #[arg(short = 'v')]
    #[conf(default(0u8))]
    pub verbose: u8,

    /// Base directory for config + state.
    #[arg(short = 'C', long = "root-dir", env = "ROOT_DIR")]
    #[conf(serde(skip))]
    pub root_dir: PathBuf,

    /// Config file (e.g. defaults.toml in ROOT_DIR)
    #[arg(short = 'f', long = "config", env = "CONFIG_FILE")]
    #[conf(serde(skip))]
    pub config_file: Option<PathBuf>,

    /// Subcommands.
    #[conf(subcommands)]
    pub command: Commands,
}

impl Cli {
    pub fn validate(&self) -> Result<(), CliError> {
        match &self.command {
            // we now validate Serve *after* merging config in run_cli
            Commands::Serve(_) => Ok(()),
            Commands::AcmeDnsRegister { .. } => Ok(()),
        }
    }
}

#[derive(Subcommands, Debug, Clone)]
#[conf(serde)]
pub enum Commands {
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
