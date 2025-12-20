use std::path::PathBuf;

use conf::Conf;
use serde::{Deserialize, Serialize};

use crate::errors::CliError;

use std::{fmt, str::FromStr};

use super::StringList;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub enum TlsMode {
    /// No TLS – listen on plain HTTP only.
    #[default]
    None,
    /// Use local certificate and private key files.
    Manual,
    /// Use ACME (Let's Encrypt, etc.) for automatic TLS certificates.
    Acme,
    /// Use a self-signed certificate generated at startup.
    SelfSigned,
}

impl fmt::Display for TlsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            TlsMode::None => "none",
            TlsMode::Manual => "manual",
            TlsMode::Acme => "acme",
            TlsMode::SelfSigned => "self-signed",
        };
        write!(f, "{s}")
    }
}

impl FromStr for TlsMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(TlsMode::None),
            "manual" => Ok(TlsMode::Manual),
            "acme" => Ok(TlsMode::Acme),
            "self-signed" => Ok(TlsMode::SelfSigned),
            other => Err(format!(
                "invalid TLS mode '{other}', expected one of: none, manual, acme, self-signed"
            )),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub enum TlsAcmeChallenge {
    #[default]
    TlsAlpn01,
    Http01,
    Dns01,
}

impl fmt::Display for TlsAcmeChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            TlsAcmeChallenge::TlsAlpn01 => "tls-alpn-01",
            TlsAcmeChallenge::Http01 => "http-01",
            TlsAcmeChallenge::Dns01 => "dns-01",
        };
        write!(f, "{s}")
    }
}

impl FromStr for TlsAcmeChallenge {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tls-alpn-01" => Ok(TlsAcmeChallenge::TlsAlpn01),
            "http-01" => Ok(TlsAcmeChallenge::Http01),
            "dns-01" => Ok(TlsAcmeChallenge::Dns01),
            other => Err(format!(
                "invalid ACME challenge '{other}', expected one of: tls-alpn-01, http-01, dns-01"
            )),
        }
    }
}

#[derive(Conf, Debug, Clone, Serialize, Deserialize, Default)]
#[conf(serde)]
pub struct TlsConfig {
    /// TLS mode to use: none, manual, acme, or self-signed.
    #[arg(long = "tls-mode", env = "TLS_MODE")]
    #[conf(default(TlsMode::None))]
    pub mode: TlsMode,

    /// Path to TLS certificate (PEM) when --tls-mode=manual.
    #[arg(long = "tls-cert-path", env = "TLS_CERT_PATH")]
    pub cert_path: Option<PathBuf>,

    /// Path to TLS private key (PEM) when --tls-mode=manual.
    #[arg(long = "tls-key-path", env = "TLS_KEY_PATH")]
    pub key_path: Option<PathBuf>,

    /// Additional DNS SubjectAltNames (SANs) for the TLS certificate.
    ///
    /// APP_HOST is used as the primary Common Name (CN); these names are added
    /// as SubjectAltNames. Used for ACME and self-signed modes.
    #[arg(long = "tls-san", env = "TLS_SANS", default(StringList::from_str("").expect("")))]
    pub sans: StringList,

    /// ACME challenge type to use when --tls-mode=acme.
    #[arg(long = "tls-acme-challenge", env = "TLS_ACME_CHALLENGE")]
    #[conf(default(TlsAcmeChallenge::TlsAlpn01))]
    pub acme_challenge: TlsAcmeChallenge,

    /// ACME directory URL (e.g. Let's Encrypt).
    /// Only used when --tls-mode=acme.
    #[arg(long = "tls-acme-directory-url", env = "TLS_ACME_DIRECTORY_URL")]
    #[conf(default("https://acme-v02.api.letsencrypt.org/directory".to_string()))]
    pub acme_directory_url: String,

    /// Contact email for ACME registration when --tls-mode=acme.
    #[arg(long = "tls-acme-email", env = "TLS_ACME_EMAIL")]
    pub acme_email: Option<String>,

    /// Validity in seconds for self-signed certificate.
    /// Used when --tls-mode=self-signed.
    #[arg(
        long = "tls-self-signed-valid-seconds",
        env = "TLS_SELF_SIGNED_VALID_SECONDS"
    )]
    #[conf(default(31536000))]
    pub self_signed_valid_seconds: u32,
    #[arg(long = "acme-dns-api-base", env = "ACME_DNS_API_BASE")]
    #[conf(default("https://auth.acme-dns.io".to_string()))]
    pub acme_dns_api_base: String,
}

impl TlsConfig {
    pub fn validate_with_root(&self, _root_dir: &std::path::Path) -> Result<(), CliError> {
        if matches!(self.mode, TlsMode::Manual)
            && (self.cert_path.is_none() || self.key_path.is_none())
        {
            return Err(CliError::InvalidArgs(
                "Both --tls-cert-path and --tls-key-path are required when --tls-mode=manual."
                    .to_string(),
            ));
        }
        Ok(())
    }
}
