use conf::Conf;
use serde::{Deserialize, Serialize};

#[derive(Conf, Debug, Clone, Serialize, Deserialize)]
#[conf(serde)]
pub struct DatabaseConfig {
    /// Database URL for sqlx (or set DATABASE_URL).
    #[arg(long = "database-url", env = "DATABASE_URL")]
    pub database_url: Option<String>,
}
