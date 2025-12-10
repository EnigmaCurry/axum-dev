use clap::{self, ArgAction, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_serde_derive::ClapSerde;

#[derive(ClapSerde, Args, Debug, Clone)]
pub struct DatabaseConfig {
    /// Database URL for sqlx (or set DATABASE_URL).
    #[arg(
        long = "database-url",
        env = "DATABASE_URL",
        value_name = "URL",
        help_heading = "Database"
    )]
    pub database_url: Option<String>,
}
