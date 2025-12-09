pub mod acme;
pub use acme::AcmeDnsRegisterConfig;
pub mod auth;
pub use auth::AuthConfig;
pub mod cli;
pub use cli::{Cli, Commands, app};
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
pub use log::build_log_level;

use clap_serde_derive::ClapSerde;

#[derive(ClapSerde, Debug, Clone)]
pub struct AppConfig {
    #[clap_serde]
    #[command(flatten)]
    pub network: NetworkConfig,

    #[clap_serde]
    #[command(flatten)]
    pub database: DatabaseConfig,

    #[clap_serde]
    #[command(flatten)]
    pub session: SessionConfig,

    #[clap_serde]
    #[command(flatten)]
    pub auth: AuthConfig,

    #[clap_serde]
    #[command(flatten)]
    pub tls: TlsConfig,
}

pub type AppConfigOpt = <AppConfig as ClapSerde>::Opt;
