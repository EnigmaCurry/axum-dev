use clap::{self, ArgAction, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_serde_derive::ClapSerde;
use serde::Serialize;

#[derive(ClapSerde, Serialize, Args, Debug, Clone)]
pub struct NetworkConfig {
    /// IP to bind (or set NET_LISTEN_IP).
    #[arg(
        long = "net-listen-ip",
        env = "NET_LISTEN_IP",
        value_name = "IP",
        default_value = "127.0.0.1",
        help_heading = "Network"
    )]
    pub listen_ip: String,

    /// Port to bind (or set NET_LISTEN_PORT).
    #[default(3001)]
    #[arg(
        long = "net-listen-port",
        env = "NET_LISTEN_PORT",
        value_name = "PORT",
        help_heading = "Network"
    )]
    pub listen_port: u16,

    /// Primary public hostname for this app (used as the default TLS CN).
    #[arg(
        long = "net-host",
        env = "NET_HOST",
        value_name = "DNSNAME",
        help_heading = "Network"
    )]
    pub net_host: Option<String>,
}
