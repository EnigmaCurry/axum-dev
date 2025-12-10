use clap::{self, ArgAction, Args, CommandFactory, Parser, Subcommand, ValueEnum};

use crate::errors::CliError;

use super::{AppConfigOpt, AuthConfig, DatabaseConfig, NetworkConfig, SessionConfig, TlsConfig};

#[derive(Args)]
pub struct ServeConfig {
    /// CLI/env overrides for the server config.
    #[command(flatten)]
    pub config_cli: AppConfigOpt,
}
