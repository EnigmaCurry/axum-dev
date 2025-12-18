use std::{env, fmt, path::PathBuf, str::FromStr};

use crate::errors::CliError;

use super::{AcmeDnsRegisterConfig, ServeConfig};
use conf::{Conf, Subcommands, anstyle::AnsiColor, completion::Shell};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct RootDir(pub PathBuf);

impl FromStr for RootDir {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(RootDir(PathBuf::from(s)))
    }
}

impl fmt::Display for RootDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Good enough for help text / env hint
        write!(f, "{}", self.0.to_string_lossy())
    }
}

const HELP_STYLES: conf::Styles = conf::Styles::styled()
    .header(AnsiColor::Blue.on_default().bold())
    .usage(AnsiColor::Blue.on_default().bold())
    .literal(AnsiColor::White.on_default())
    .placeholder(AnsiColor::Green.on_default());

#[derive(Conf, Debug, Clone)]
#[conf(serde, styles = HELP_STYLES)]
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
    #[conf(default(RootDir(default_root_dir())), serde(skip))]
    pub root_dir: RootDir,

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
            Commands::Completions(_) => Ok(()),
        }
    }
}

#[derive(Conf, Debug, Clone, Serialize, Deserialize)]
#[conf(serde)]
pub struct CompletionArgs {
    /// Shell to generate completions for (bash|elvish|fish|powershell|zsh)
    #[conf(pos, serde(skip))]
    pub shell: Shell,
}

#[derive(Subcommands, Debug, Clone)]
#[conf(serde)]
pub enum Commands {
    /// Output shell completion scripts
    Completions(CompletionArgs),
    /// Run the HTTP API server.
    Serve(ServeConfig),

    /// Register or inspect acme-dns credentials used for DNS-01 ACME.
    ///
    /// Run this once before `serve` when using `--tls-mode=acme --tls-acme-challenge=dns-01`,
    /// unless you are providing ACME_DNS_* credentials explicitly.
    AcmeDnsRegister(AcmeDnsRegisterConfig),
}

fn default_root_dir() -> PathBuf {
    let bin = env!("CARGO_BIN_NAME");

    if let Ok(xdg) = env::var("XDG_DATA_HOME")
        && !xdg.is_empty()
    {
        return PathBuf::from(xdg).join(bin);
    }

    if let Ok(home) = env::var("HOME")
        && !home.is_empty()
    {
        return PathBuf::from(home).join(".local").join("share").join(bin);
    }

    PathBuf::from(format!("{bin}-data"))
}
