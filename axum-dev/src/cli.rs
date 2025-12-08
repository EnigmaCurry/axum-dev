use crate::{errors::CliError, middleware::auth::AuthenticationMethod};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use std::{env, path::PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = env!("CARGO_BIN_NAME"),
    version = env!("CARGO_PKG_VERSION"),
    author = env!("CARGO_PKG_AUTHORS"),
    about = env!("CARGO_PKG_DESCRIPTION"),
    propagate_version = true
)]
pub struct Cli {
    /// Sets the log level, overriding the RUST_LOG environment variable.
    #[arg(
        long,
        global = true,
        value_name = "LEVEL",
        value_parser = ["trace", "debug", "info", "warn", "error"]
    )]
    pub log: Option<String>,

    /// Sets the log level to debug.
    #[arg(short = 'v', global = true)]
    pub verbose: bool,

    /// Base directory for config + state (like `-C` in many GNU tools).
    ///
    /// When set, relative paths for the database, TLS cache, ACME accounts,
    /// and acme-dns credentials are resolved under this directory, and the
    /// directory is created if needed.
    #[arg(
        short = 'C',
        long = "root-dir",
        env = "ROOT_DIR",
        global = true,
        default_value = default_root_dir().into_os_string(),
        value_name = "DIR",
    )]
    pub root_dir: PathBuf,

    #[command(subcommand)]
    pub command: Commands,
}

impl Cli {
    pub fn validate(&self) -> Result<(), CliError> {
        match &self.command {
            Commands::Serve(args) => args.validate(&self.root_dir),
            Commands::Completions { .. } => Ok(()),
            Commands::AcmeDnsRegister { .. } => Ok(()),
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Generates shell completions script (tab completion).
    Completions {
        /// The shell to generate completions for.
        #[arg(value_parser = ["bash", "zsh", "fish"])]
        shell: Option<String>,
    },

    /// Run the HTTP API server.
    Serve(ServeArgs),

    /// Register or inspect acme-dns credentials used for DNS-01 ACME.
    ///
    /// Run this once before `serve` when using `--tls-mode=acme --tls-acme-challenge=dns-01`,
    /// unless you are providing ACME_DNS_* credentials explicitly.
    AcmeDnsRegister(AcmeDnsRegisterArgs),
}

#[derive(Args, Debug, Clone)]
pub struct ServeArgs {
    #[command(flatten)]
    pub network: NetworkArgs,

    #[command(flatten)]
    pub database: DatabaseArgs,

    #[command(flatten)]
    pub session: SessionArgs,

    #[command(flatten)]
    pub auth: AuthArgs,

    #[command(flatten)]
    pub tls: TlsArgs,
}

impl ServeArgs {
    pub fn validate(&self, root_dir: &std::path::Path) -> Result<(), CliError> {
        self.tls.validate_with_root(root_dir)
    }
}

#[derive(Args, Debug, Clone)]
pub struct NetworkArgs {
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
    #[arg(
        long = "net-listen-port",
        env = "NET_LISTEN_PORT",
        value_name = "PORT",
        default_value_t = 3000u16,
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

#[derive(Args, Debug, Clone)]
pub struct DatabaseArgs {
    /// Database URL for sqlx (or set DATABASE_URL).
    #[arg(
        long = "database-url",
        env = "DATABASE_URL",
        value_name = "URL",
        default_value = "sqlite:data.db",
        help_heading = "Database"
    )]
    pub database_url: String,
}

#[derive(Args, Debug, Clone)]
pub struct SessionArgs {
    /// Whether to set the Secure flag on session cookies.
    /// (true/false or set SESSION_SECURE=true/false).
    #[arg(
        long = "session-secure",
        env = "SESSION_SECURE",
        value_name = "BOOL",
        default_value_t = true,
        help_heading = "Session"
    )]
    pub session_secure: bool,

    /// Session cleanup interval in seconds.
    /// (default 60, or set SESSION_CHECK_SECONDS).
    #[arg(
        long = "session-check-seconds",
        env = "SESSION_CHECK_SECONDS",
        value_name = "SECONDS",
        default_value_t = 60u64,
        help_heading = "Session"
    )]
    pub session_check_seconds: u64,

    /// Session inactivity timeout in seconds.
    /// (default 604800 = 7 days, or set SESSION_EXPIRY_SECONDS).
    #[arg(
        long = "session-expiry-seconds",
        env = "SESSION_EXPIRY_SECONDS",
        value_name = "SECONDS",
        default_value_t = 604800u64,
        help_heading = "Session"
    )]
    pub session_expiry_seconds: u64,
}

#[derive(Args, Debug, Clone)]
pub struct AuthArgs {
    /// Authentication method to use: forward_auth or username_password.
    #[arg(
        long = "auth-method",
        env = "AUTH_METHOD",
        value_name = "METHOD",
        default_value = "forward_auth",
        help_heading = "Authentication"
    )]
    pub authentication_method: AuthenticationMethod,

    /// Header to read the authenticated user email from.
    #[arg(
        long = "auth-trusted-header-name",
        env = "AUTH_TRUSTED_HEADER_NAME",
        value_name = "HEADER",
        default_value = "X-Forwarded-User",
        help_heading = "Authentication"
    )]
    pub trusted_header_name: String,

    /// Only trust the header when the TCP peer IP matches this proxy.
    #[arg(
        long = "auth-trusted-proxy",
        env = "AUTH_TRUSTED_PROXY",
        value_name = "IP",
        default_value = "127.0.0.1",
        help_heading = "Authentication"
    )]
    pub trusted_proxy: std::net::IpAddr,

    /// Enable trusting X-Forwarded-For (or custom) from a trusted proxy.
    #[arg(
        long = "auth-trusted-forwarded-for",
        env = "AUTH_TRUSTED_FORWARDED_FOR",
        action = clap::ArgAction::SetTrue,
        help_heading = "Authentication"
    )]
    pub trusted_forwarded_for: bool,

    /// Header to read client IP from when trusted-forwarded-for is enabled.
    #[arg(
        long = "auth-trusted-forwarded-for-name",
        env = "AUTH_TRUSTED_FORWARDED_FOR_NAME",
        value_name = "HEADER",
        default_value = "X-Forwarded-For",
        help_heading = "Authentication"
    )]
    pub trusted_forwarded_for_name: String,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum TlsMode {
    /// No TLS – listen on plain HTTP only.
    None,
    /// Use local certificate and private key files.
    Manual,
    /// Use ACME (Let's Encrypt, etc.) for automatic TLS certificates.
    Acme,
    /// Use a self-signed certificate generated at startup.
    #[value(name = "self-signed")]
    SelfSigned,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum TlsAcmeChallenge {
    /// Use the TLS-ALPN-01 challenge type.
    #[value(name = "tls-alpn-01")]
    TlsAlpn01,

    /// Use the HTTP-01 challenge type.
    #[value(name = "http-01")]
    Http01,

    /// Use the DNS-01 challenge type.
    #[value(name = "dns-01")]
    Dns01,
}

#[derive(Args, Debug, Clone)]
pub struct TlsArgs {
    /// TLS mode to use: none, manual, acme, or self-signed.
    #[arg(
        long = "tls-mode",
        env = "TLS_MODE",
        value_enum,
        default_value_t = TlsMode::None,
        help_heading = "TLS"
    )]
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
        default_value_t = TlsAcmeChallenge::TlsAlpn01,
        help_heading = "TLS"
    )]
    pub acme_challenge: TlsAcmeChallenge,

    /// ACME directory URL (e.g. Let's Encrypt).
    /// Only used when --tls-mode=acme.
    #[arg(
        long = "tls-acme-directory-url",
        env = "TLS_ACME_DIRECTORY_URL",
        value_name = "URL",
        default_value = "https://acme-v02.api.letsencrypt.org/directory",
        help_heading = "TLS"
    )]
    pub acme_directory_url: String,

    /// Contact email for ACME registration when --tls-mode=acme.
    #[arg(
        long = "tls-acme-email",
        env = "TLS_ACME_EMAIL",
        value_name = "EMAIL",
        help_heading = "TLS"
    )]
    pub acme_email: Option<String>,

    /// Directory to store TLS account, certificate, and key data for ACME or self-signed modes.
    ///
    /// If tls-mode == self-signed, and this option is unset, it will create ephemeral certificates.
    #[arg(
        long = "tls-cache-dir",
        env = "TLS_CACHE_DIR",
        value_name = "DIR",
        help_heading = "TLS"
    )]
    pub cache_dir: Option<String>,

    /// Validity in days for self-signed certificate.
    /// Used when --tls-mode=self-signed.
    #[arg(
        long = "tls-self-signed-valid-days",
        env = "TLS_SELF_SIGNED_VALID_DAYS",
        value_name = "DAYS",
        default_value_t = 365u32,
        help_heading = "TLS"
    )]
    pub self_signed_valid_days: u32,
    #[arg(
        long = "acme-dns-api-base",
        env = "ACME_DNS_API_BASE",
        value_name = "URL",
        default_value = "https://auth.acme-dns.io",
        help_heading = "ACME-DNS"
    )]
    pub acme_dns_api_base: String,
}

impl TlsArgs {
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

#[derive(Args, Debug)]
pub struct AcmeDnsRegisterArgs {
    /// Base URL of the acme-dns API (e.g. https://auth.acme-dns.io).
    #[arg(
        long = "acme-dns-api-base",
        env = "ACME_DNS_API_BASE",
        value_name = "URL",
        default_value = "https://auth.acme-dns.io",
        help_heading = "ACME-DNS"
    )]
    pub api_base: String,

    /// Directory to store acme-dns credentials (defaults to TLS cache dir).
    ///
    /// If not set, we will default to "./tls-cache".
    #[arg(
        long = "tls-cache-dir",
        env = "TLS_CACHE_DIR",
        value_name = "DIR",
        help_heading = "ACME-DNS"
    )]
    pub cache_dir: Option<String>,

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

pub fn app() -> clap::Command {
    Cli::command()
}

fn default_root_dir() -> PathBuf {
    // CARGO_BIN_NAME is compile-time, so this is cheap.
    let bin = env!("CARGO_BIN_NAME");

    // 1) If XDG_DATA_HOME is set, prefer it.
    if let Ok(xdg) = env::var("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join(bin);
        }
    }

    // 2) Fallback: ~/.local/share/<bin>
    if let Ok(home) = env::var("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home).join(".local").join("share").join(bin);
        }
    }

    // 3) Last resort: current directory / <bin>-data
    PathBuf::from(format!("{bin}-data"))
}
