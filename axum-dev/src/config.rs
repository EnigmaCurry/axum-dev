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
use std::{fmt, ops::Deref, str::FromStr};

#[derive(Conf, Debug, Clone)]
#[conf(serde)]
pub struct AppConfig {
    #[conf(flatten, serde(flatten))]
    pub network: NetworkConfig,
    #[conf(flatten, serde(flatten))]
    pub database: DatabaseConfig,
    #[conf(flatten, serde(flatten))]
    pub session: SessionConfig,
    #[conf(flatten, serde(flatten))]
    pub auth: AuthConfig,
    #[conf(flatten, serde(flatten))]
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
