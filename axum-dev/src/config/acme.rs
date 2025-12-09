use clap::{self, ArgAction, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_serde_derive::ClapSerde;

#[derive(Args, Debug)]
pub struct AcmeDnsRegisterConfig {
    /// Base URL of the acme-dns API (e.g. https://auth.acme-dns.io).
    #[arg(
        long = "acme-dns-api-base",
        env = "ACME_DNS_API_BASE",
        value_name = "URL",
        default_value = "https://auth.acme-dns.io",
        help_heading = "ACME-DNS"
    )]
    pub api_base: String,

    /// Optional CIDR ranges allowed to call the acme-dns /update API.
    ///
    /// This is passed through to the acme-dns `allowfrom` field.
    #[arg(
        long = "acme-dns-allowfrom",
        env = "ACME_DNS_ALLOWFROM",
        value_name = "CIDR",
        value_delimiter = ',',
        num_args = 0..,
        help_heading = "ACME-DNS"
    )]
    pub allowfrom: Vec<String>,

    /// Primary public hostname.
    #[arg(
        long = "net-host",
        env = "NET_HOST",
        value_name = "DNSNAME",
        help_heading = "ACME-DNS"
    )]
    pub net_host: Option<String>,

    /// Additional DNS SubjectAltNames (SANs) for the TLS certificate.
    ///
    /// APP_HOST is used as the primary Common Name (CN); these names are added
    /// as SubjectAltNames. Used for ACME and self-signed modes.
    #[arg(
        long = "tls-san",
        env = "TLS_SANS",
        value_name = "DNSNAME",
        num_args = 0..,
        value_delimiter = ',',
        help_heading = "TLS"
    )]
    pub sans: Vec<String>,
}
