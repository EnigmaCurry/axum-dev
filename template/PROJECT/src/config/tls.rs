use std::path::PathBuf;

use clap::{Args, ValueEnum};
use clap_serde_derive::ClapSerde;
use serde::Deserialize;

use crate::errors::CliError;

#[derive(Default, Copy, Clone, Debug, Eq, PartialEq, ValueEnum, Deserialize)]
pub enum TlsMode {
    /// No TLS – listen on plain HTTP only.
    #[default]
    None,
    /// Use local certificate and private key files.
    Manual,
    /// Use ACME (Let's Encrypt, etc.) for automatic TLS certificates.
    Acme,
    /// Use a self-signed certificate generated at startup.
    #[value(name = "self-signed")]
    SelfSigned,
}

#[derive(Default, Deserialize, Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum TlsAcmeChallenge {
    /// Use the TLS-ALPN-01 challenge type.
    #[value(name = "tls-alpn-01")]
    #[default]
    TlsAlpn01,

    /// Use the HTTP-01 challenge type.
    #[value(name = "http-01")]
    Http01,

    /// Use the DNS-01 challenge type.
    #[value(name = "dns-01")]
    Dns01,
}

#[derive(ClapSerde, Args, Debug, Clone)]
pub struct TlsConfig {
    /// TLS mode to use: none, manual, acme, or self-signed.
    #[arg(long = "tls-mode", env = "TLS_MODE", value_enum, help_heading = "TLS")]
    #[default(TlsMode::None)]
    pub mode: TlsMode,

    /// Path to TLS certificate (PEM) when --tls-mode=manual.
    #[arg(
        long = "tls-cert-path",
        env = "TLS_CERT_PATH",
        value_name = "FILE",
        help_heading = "TLS"
    )]
    pub cert_path: Option<PathBuf>,

    /// Path to TLS private key (PEM) when --tls-mode=manual.
    #[arg(
        long = "tls-key-path",
        env = "TLS_KEY_PATH",
        value_name = "FILE",
        help_heading = "TLS"
    )]
    pub key_path: Option<PathBuf>,

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

    /// ACME challenge type to use when --tls-mode=acme.
    #[arg(
        long = "tls-acme-challenge",
        env = "TLS_ACME_CHALLENGE",
        value_enum,
        help_heading = "TLS"
    )]
    #[default(TlsAcmeChallenge::TlsAlpn01)]
    pub acme_challenge: TlsAcmeChallenge,

    /// ACME directory URL (e.g. Let's Encrypt).
    /// Only used when --tls-mode=acme.
    #[arg(
        long = "tls-acme-directory-url",
        env = "TLS_ACME_DIRECTORY_URL",
        value_name = "URL",
        help_heading = "TLS"
    )]
    #[default("https://acme-v02.api.letsencrypt.org/directory".to_string())]
    pub acme_directory_url: String,

    /// Contact email for ACME registration when --tls-mode=acme.
    #[arg(
        long = "tls-acme-email",
        env = "TLS_ACME_EMAIL",
        value_name = "EMAIL",
        help_heading = "TLS"
    )]
    pub acme_email: Option<String>,

    /// Validity in days for self-signed certificate.
    /// Used when --tls-mode=self-signed.
    #[arg(
        long = "tls-self-signed-valid-days",
        env = "TLS_SELF_SIGNED_VALID_DAYS",
        value_name = "DAYS",
        help_heading = "TLS"
    )]
    #[default(365)]
    pub self_signed_valid_days: u32,
    #[arg(
        long = "acme-dns-api-base",
        env = "ACME_DNS_API_BASE",
        value_name = "URL",
        help_heading = "ACME-DNS"
    )]
    #[default("https://auth.acme-dns.io".to_string())]
    pub acme_dns_api_base: String,
}

impl TlsConfig {
    pub fn validate_with_root(&self, _root_dir: &std::path::Path) -> Result<(), CliError> {
        if matches!(self.mode, TlsMode::Manual) {
            if self.cert_path.is_none() || self.key_path.is_none() {
                return Err(CliError::InvalidArgs(
                    "Both --tls-cert-path and --tls-key-path are required when --tls-mode=manual."
                        .to_string(),
                ));
            }
        }
        Ok(())
    }
}
