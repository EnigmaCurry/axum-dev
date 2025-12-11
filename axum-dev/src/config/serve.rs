use super::AppConfig;
use conf::Conf;

#[derive(Conf, Debug, Clone)]
#[conf(serde)]
pub struct ServeConfig {
    /// CLI/env overrides for the server config.
    #[conf(flatten)]
    pub app: AppConfig,
}
