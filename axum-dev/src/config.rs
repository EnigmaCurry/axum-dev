pub mod acme;
pub use acme::AcmeDnsRegisterConfig;
pub mod auth;
pub use auth::AuthConfig;
pub mod cli;
pub use cli::{Cli, Commands};
pub mod database;
pub use database::DatabaseConfig;
pub mod network;
pub use network::NetworkConfig;
pub mod serve;
pub use serve::ServeConfig;
pub mod session;
pub use session::SessionConfig;
pub mod tls;
pub use tls::{TlsAcmeChallenge, TlsConfig, TlsMode};
pub mod log;
use conf::Conf;
pub use log::build_log_level;

use serde::{Deserialize, Serialize};
use std::{fmt, ops::Deref, path::PathBuf, str::FromStr};

use crate::errors::CliError;

#[derive(Conf, Debug, Clone, Serialize, Deserialize)]
#[conf(serde)]
pub struct AppConfig {
    #[conf(flatten)]
    pub network: NetworkConfig,
    #[conf(flatten)]
    pub database: DatabaseConfig,
    #[conf(flatten)]
    pub session: SessionConfig,
    #[conf(flatten)]
    pub auth: AuthConfig,
    #[conf(flatten)]
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StringList(pub Vec<String>);

impl FromStr for StringList {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let items = s
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();
        Ok(StringList(items))
    }
}

impl fmt::Display for StringList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.join(","))
    }
}

impl Deref for StringList {
    type Target = [String];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub(crate) fn resolve_config_path(cli: &Cli, root_dir: &PathBuf) -> Option<PathBuf> {
    if let Some(p) = cli.config_file.clone() {
        return Some(if p.is_relative() { root_dir.join(p) } else { p });
    }

    let p = root_dir.join("defaults.toml");
    if p.exists() { Some(p) } else { None }
}

pub(crate) fn args_after_subcommand(
    args: &[std::ffi::OsString],
    sub: &str,
) -> Option<Vec<std::ffi::OsString>> {
    let bin = args.get(0)?.clone();
    let idx = args.iter().position(|a| a.to_string_lossy() == sub)?;
    let mut out = Vec::with_capacity(1 + (args.len().saturating_sub(idx + 1)));
    out.push(bin);
    out.extend_from_slice(&args[idx + 1..]);
    Some(out)
}

pub(crate) fn load_toml_doc(path: &PathBuf) -> Result<toml::Value, CliError> {
    let s = std::fs::read_to_string(path).map_err(|e| {
        CliError::RuntimeError(format!(
            "Could not read config file {}: {e}",
            path.display()
        ))
    })?;

    toml::from_str(&s).map_err(|e| {
        CliError::RuntimeError(format!(
            "Config file {} is not valid TOML: {e}",
            path.display()
        ))
    })
}
