use axum::http::HeaderName;
use clap::{CommandFactory, Parser, error::ErrorKind};
use clap_complete::shells::Shell;
use clap_serde_derive::ClapSerde;
use config::{AcmeDnsRegisterConfig, TlsAcmeChallenge, TlsMode};
use config::{AppConfig, build_log_level};
use errors::CliError;
use middleware::auth::AuthenticationMethod;
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::io::{BufReader, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use tls::dns::{format_acme_dns_cname_help, register_acme_dns_account};
use tracing_subscriber::EnvFilter;

mod api_docs;
mod config;
mod errors;
mod frontend;
mod middleware;
mod models;
mod prelude;
mod response;
mod routes;
mod server;
mod tls;

use crate::config::{Cli, Commands, ServeConfig};
use prelude::*;

fn main() {
    if let Err(e) = run_cli(
        std::env::args_os(),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    ) {
        error!("run_cli failed: {:?}", e);
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn init_tracing(log_level: &str) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_new(log_level)
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .pretty()
        .try_init()
        .ok();
}

/// run_cli is the common entrypoint for both main and unit tests.
pub fn run_cli<I, S, W1, W2>(args: I, out: &mut W1, err: &mut W2) -> Result<(), CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
    W1: Write,
    W2: Write,
{
    // Parse CLI, but intercept help/version/errors instead of exiting the process.
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => {
            debug!("CLI parsing error: kind={:?}, error={}", e.kind(), e);
            match e.kind() {
                // NEW: no subcommand -> print top-level help to stdout and succeed
                ErrorKind::MissingSubcommand => {
                    // Use the same Command builder your test uses
                    let mut cmd = crate::config::app();
                    let _ = cmd.write_help(out);
                    // Optional: no need for extra newline because the test trims
                    return Ok(());
                }

                // Cases where clap already formats the help/version text nicely
                ErrorKind::DisplayHelp
                | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
                | ErrorKind::InvalidSubcommand
                | ErrorKind::UnknownArgument
                | ErrorKind::DisplayVersion => {
                    let _ = write!(out, "{e}");
                    return Ok(());
                }

                // Everything else is a real “invalid args” error
                _ => {
                    return Err(CliError::InvalidArgs(e.to_string()));
                }
            }
        }
    };
    cli.validate()?;

    let log_level = build_log_level(&cli);
    init_tracing(&log_level);

    match cli.command {
        Commands::Completions { shell } => completions(shell, out, err),

        Commands::Serve(mut serve_args) => {
            let root_dir = ensure_root_dir(cli.root_dir.clone())?;

            // 1. Read config file into AppConfig::Opt
            let path = &cli.config_file;
            let file_opt: <AppConfig as ClapSerde>::Opt = if path.exists() {
                let mut s = String::new();
                File::open(path)
                    .and_then(|f| BufReader::new(f).read_to_string(&mut s))
                    .map_err(|e| {
                        CliError::RuntimeError(format!(
                            "Error reading configuration file {}: {e}",
                            path.display()
                        ))
                    })?;

                toml::from_str(&s).map_err(|e| {
                    CliError::RuntimeError(format!(
                        "Error in configuration file {}: {e}",
                        path.display()
                    ))
                })?
            } else {
                Default::default()
            };

            // 2. Merge: CLI/env > config.toml > defaults
            let app_cfg: AppConfig = AppConfig::from(file_opt).merge(&mut serve_args.config_cli);

            // 3. Validate the merged config (eg TLS constraints)
            app_cfg.tls.validate_with_root(&root_dir)?;
            app_cfg.auth.validate()?;

            // 4. Run the server with *AppConfig*
            serve(app_cfg, root_dir, out, err)
        }

        Commands::AcmeDnsRegister(args) => acme_dns_register(args, cli.root_dir.clone(), out, err),
    }
}

fn completions<W1: Write, W2: Write>(
    shell: Option<String>,
    out: &mut W1,
    err: &mut W2,
) -> Result<(), CliError> {
    if let Some(shell) = shell {
        match shell.as_str() {
            "bash" => generate_completion_script(Shell::Bash, out),
            "zsh" => generate_completion_script(Shell::Zsh, out),
            "fish" => generate_completion_script(Shell::Fish, out),
            other => {
                return Err(CliError::UnsupportedShell(other.to_string()));
            }
        }
        Ok(())
    } else {
        let bin = env!("CARGO_BIN_NAME");

        let _ = writeln!(err, "### Instructions to enable tab completion for {bin}\n");
        let _ = writeln!(err, "### Bash (put this in ~/.bashrc:)");
        let _ = writeln!(err, "  source <({bin} completions bash)\n");
        let _ = writeln!(err, "### To make an alias (eg. 'h'), add this too:");
        let _ = writeln!(err, "  alias h={bin}");
        let _ = writeln!(err, "  complete -F _{bin} -o bashdefault -o default h\n");
        let _ = writeln!(
            err,
            "### If you don't use Bash, you can also use Fish or Zsh:"
        );
        let _ = writeln!(err, "### Fish (put this in ~/.config/fish/config.fish");
        let _ = writeln!(err, "  {bin} completions fish | source)\n");
        let _ = writeln!(err, "### Zsh (put this in ~/.zshrc)");
        let _ = writeln!(
            err,
            "  autoload -U compinit; compinit; source <({bin} completions zsh)"
        );
        let _ = writeln!(err);
        Err(CliError::InvalidArgs("no shell argument".into()))
    }
}

fn generate_completion_script<W: Write>(shell: Shell, out: &mut W) {
    // Rebuild the clap Command from the derived Cli type
    clap_complete::generate(shell, &mut Cli::command(), env!("CARGO_BIN_NAME"), out)
}

fn serve<W1: Write, W2: Write>(
    cfg: AppConfig,
    root_dir: std::path::PathBuf,
    _out: &mut W1,
    _err: &mut W2,
) -> Result<(), CliError> {
    let root_dir = ensure_root_dir(root_dir)?;
    // --- Network ---
    let ip = &cfg.network.listen_ip;
    let port = cfg.network.listen_port;
    let addr_str = format!("{ip}:{port}");

    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            return Err(CliError::InvalidArgs(format!(
                "Invalid listen addr '{addr_str}': {e}"
            )));
        }
    };

    // --- TLS mode selection ---
    // --- TLS mode selection ---
    let tls_config = match cfg.tls.mode {
        TlsMode::None => {
            info!("TLS mode: none (plain HTTP).");
            server::TlsConfig::Http
        }
        TlsMode::Manual => {
            let cert_path = cfg.tls.cert_path.clone().ok_or_else(|| {
                CliError::InvalidArgs("Missing --tls-cert-path for --tls-mode=manual".to_string())
            })?;
            let key_path = cfg.tls.key_path.clone().ok_or_else(|| {
                CliError::InvalidArgs("Missing --tls-key-path for --tls-mode=manual".to_string())
            })?;

            info!(
                "TLS mode: manual (HTTPS) – cert={}, key={}",
                cert_path.display(),
                key_path.display()
            );

            server::TlsConfig::RustlsFiles {
                cert_path,
                key_path,
            }
        }
        TlsMode::SelfSigned => {
            let cache_dir = Some(root_dir.join("tls-cache"));
            let sans = cfg.tls.sans.clone();
            let valid_days = cfg.tls.self_signed_valid_days;

            info!(
                "TLS mode: self-signed (HTTPS) – cache_dir={:?}, sans={:?}, valid_days={}",
                cache_dir, sans, valid_days
            );

            server::TlsConfig::SelfSigned {
                cache_dir,
                sans,
                valid_days,
            }
        }
        TlsMode::Acme => {
            // Shared bits: cache dir, domains, directory URL, email.
            let cache_dir: PathBuf = root_dir.join("tls-cache");

            // You may want to ensure the directory exists:
            if let Err(e) = std::fs::create_dir_all(&cache_dir) {
                return Err(CliError::RuntimeError(format!(
                    "Failed to create TLS cache dir {}: {e}",
                    cache_dir.display()
                )));
            }

            let mut domains: Vec<String> = cfg
                .tls
                .sans
                .iter()
                .cloned()
                .filter(|s| !s.trim().is_empty())
                .collect();

            // (rest of your ACME code unchanged, now using `cache_dir`)

            if let Some(ref host) = cfg.network.net_host {
                if !host.trim().is_empty() {
                    domains.push(host.clone());
                }
            }

            // Dedup while preserving order.
            let mut seen = std::collections::BTreeSet::new();
            domains.retain(|d| seen.insert(d.clone()));

            if domains.is_empty() {
                return Err(CliError::InvalidArgs(
                    "ACME mode requires at least one domain. \
         Provide --tls-san and/or --app-host (or APP_HOST)."
                        .to_string(),
                ));
            }

            let directory_url = cfg.tls.acme_directory_url.clone();
            let contact_email = cfg.tls.acme_email.clone();

            match cfg.tls.acme_challenge {
                TlsAcmeChallenge::TlsAlpn01 => {
                    info!(
                        "TLS mode: acme (TLS-ALPN-01) – directory_url={}, cache_dir={}, domains={:?}, contact_email={:?}",
                        directory_url,
                        cache_dir.display(),
                        domains,
                        contact_email,
                    );

                    server::TlsConfig::AcmeTlsAlpn01 {
                        directory_url,
                        cache_dir,
                        domains,
                        contact_email,
                    }
                }

                TlsAcmeChallenge::Dns01 => {
                    info!(
                        "TLS mode: acme (DNS-01) – directory_url={}, cache_dir={}, domains={:?}, contact_email={:?}, acme_dns_api_base={:?}",
                        directory_url,
                        cache_dir.display(),
                        domains,
                        contact_email,
                        cfg.tls.acme_dns_api_base.clone(),
                    );

                    server::TlsConfig::AcmeDns01 {
                        directory_url,
                        cache_dir,
                        domains,
                        contact_email,
                        acme_dns_api_base: cfg.tls.acme_dns_api_base.clone(),
                    }
                }

                TlsAcmeChallenge::Http01 => {
                    return Err(CliError::InvalidArgs(
                        "HTTP-01 is not supported yet. \
                         Use --tls-acme-challenge=tls-alpn-01 or dns-01."
                            .to_string(),
                    ));
                }
            }
        }
    };

    // --- Database + session config ---
    let mut db_url = cfg.clone().database.database_url;

    // Only rewrite the default dev URL; if the user explicitly set DATABASE_URL,
    // we assume they know what they’re doing.
    if db_url == "sqlite:data.db" {
        let db_path = root_dir.join("data.db");
        db_url = format!("sqlite://{}", db_path.display());
    }

    let session_secure = cfg.session.session_secure;
    let session_expiry_secs = cfg.session.session_expiry_seconds;
    let session_check_secs = cfg.session.session_check_seconds;

    // --- Authentication method + trusted USER header options ---
    let auth_method: AuthenticationMethod = cfg.auth.authentication_method;

    let header_name_str = cfg.auth.trusted_header_name.as_str();

    let header_name = match HeaderName::from_bytes(header_name_str.as_bytes()) {
        Ok(h) => h,
        Err(e) => {
            return Err(CliError::InvalidArgs(format!(
                "Invalid header name '{header_name_str}': {e}"
            )));
        }
    };

    let trusted_proxy: Option<IpAddr> = cfg.auth.trusted_proxy;

    let auth_cfg = middleware::trusted_header_auth::ForwardAuthConfig {
        method: auth_method,
        trusted_header_name: header_name,
        trusted_proxy,
    };

    match auth_method {
        AuthenticationMethod::ForwardAuth => {
            let proxy = cfg
                .auth
                .trusted_proxy
                .expect("auth.validate() should guarantee trusted_proxy is Some for ForwardAuth");
            info!(
                "Authentication: forward_auth (trusted header='{}', proxy={})",
                header_name_str, proxy
            );
        }
        AuthenticationMethod::UsernamePassword => {
            info!("Authentication: username_password (header/forward-auth config ignored)");
        }
    }

    // --- Trusted FORWARDED-FOR (client IP) options ---
    let fwd_enabled = cfg.auth.trusted_forwarded_for;
    let fwd_header_str = cfg.auth.trusted_forwarded_for_name.as_str();

    let fwd_header_name = match HeaderName::from_bytes(fwd_header_str.as_bytes()) {
        Ok(h) => h,
        Err(e) => {
            return Err(CliError::InvalidArgs(format!(
                "Invalid forwarded-for header name '{fwd_header_str}': {e}"
            )));
        }
    };

    let fwd_cfg = middleware::trusted_forwarded_for::TrustedForwardedForConfig {
        enabled: fwd_enabled,
        header_name: fwd_header_name,
        trusted_proxy,
    };

    if fwd_enabled {
        if let Some(t) = trusted_proxy {
            info!("Trusted FORWARDED-FOR enabled: header='{fwd_header_str}', trusted_proxy={t}");
        }
    }

    debug!("serve(): parsed cfg = {:?}", cfg.clone());
    info!("Server will listen on {addr} (from {addr_str})");
    info!("Database URL: {db_url}");
    debug!(
        "Session config: secure={}, expiry_secs={}, check_secs={}",
        session_secure, session_expiry_secs, session_check_secs
    );

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => {
            debug!("Tokio runtime created successfully");
            rt
        }
        Err(e) => {
            error!("Failed to create Tokio runtime: {e}");
            return Err(CliError::RuntimeError(format!(
                "Failed to start Tokio runtime: {e}"
            )));
        }
    };

    match rt.block_on(server::run(
        addr,
        auth_cfg,
        fwd_cfg,
        db_url,
        session_secure,
        session_expiry_secs,
        session_check_secs,
        tls_config,
    )) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Log full context to the logger
            error!("server::run failed: {:#}", e);

            // And propagate the full chain back to the user
            Err(CliError::RuntimeError(format!("{:#}", e)))
        }
    }
}

fn acme_dns_register<W1: Write, W2: Write>(
    args: AcmeDnsRegisterConfig,
    root_dir: std::path::PathBuf,
    out: &mut W1,
    _err: &mut W2,
) -> Result<(), CliError> {
    let root_dir = ensure_root_dir(root_dir)?;
    // Where to store creds:
    let cache_dir = root_dir.join("tls-cache");

    if let Err(e) = std::fs::create_dir_all(&cache_dir) {
        return Err(CliError::RuntimeError(format!(
            "Failed to create TLS cache dir {}: {e}",
            cache_dir.display()
        )));
    }

    // Build domain list from NET_HOST + TLS_SANS for CNAME hints
    let mut domains: Vec<String> = Vec::new();

    if let Some(ref host) = args.net_host {
        if !host.trim().is_empty() {
            domains.push(host.clone());
        }
    }

    for s in &args.sans {
        if !s.trim().is_empty() {
            domains.push(s.clone());
        }
    }

    // Dedup
    let mut seen = std::collections::BTreeSet::new();
    domains.retain(|d| seen.insert(d.clone()));

    // Build allow_from
    let allowfrom_opt = if args.allowfrom.is_empty() {
        None
    } else {
        Some(args.allowfrom.clone())
    };

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| CliError::RuntimeError(format!("Failed to start Tokio runtime: {e}")))?;

    let (creds, created_new) = rt
        .block_on(register_acme_dns_account(
            &args.api_base,
            &cache_dir,
            &domains,
            allowfrom_opt.as_deref(),
        ))
        .map_err(|e| CliError::RuntimeError(e.to_string()))?;

    let cred_path = cache_dir.join("acme-dns-credentials.json");

    if created_new {
        writeln!(
            out,
            "Registered new acme-dns account and wrote credentials to:\n  {}\n",
            cred_path.display()
        )?;
    } else {
        writeln!(
            out,
            "Using existing acme-dns account credentials from:\n  {}\n",
            cred_path.display()
        )?;
    }

    writeln!(out, "acme-dns fulldomain:\n  {}", creds.fulldomain)?;

    let cname_help = format_acme_dns_cname_help(&domains, &creds.fulldomain);
    write!(out, "{cname_help}")?;

    Ok(())
}

#[test]
fn help_prints_when_no_subcommand() {
    let mut out = Vec::new();
    let mut err = Vec::new();

    let bin = env!("CARGO_BIN_NAME");
    // No subcommand => run_cli should print top-level help to stdout
    run_cli([bin], &mut out, &mut err).expect("run_cli should succeed for help");

    assert!(
        err.is_empty(),
        "expected no stderr output, got: {}",
        String::from_utf8_lossy(&err)
    );

    let actual = String::from_utf8(out).expect("stdout should be valid utf8");

    // Build expected help text directly from the Command
    let mut cmd = crate::config::app();
    let mut expected_buf = Vec::new();
    cmd.write_help(&mut expected_buf).unwrap();
    let expected_help = String::from_utf8(expected_buf).unwrap();

    // Normalize line endings & trim trailing whitespace for a stable comparison
    fn normalize(s: &str) -> String {
        s.replace("\r\n", "\n").trim_end().to_string()
    }

    let actual_norm = normalize(&actual);
    let expected_norm = normalize(&expected_help);

    assert_eq!(
        actual_norm, expected_norm,
        "normalized help output from run_cli did not match Command::write_help()"
    );
}

fn ensure_root_dir(root_dir: PathBuf) -> Result<PathBuf, CliError> {
    if let Err(e) = fs::create_dir_all(&root_dir) {
        return Err(CliError::RuntimeError(format!(
            "Failed to create root dir {}: {e}",
            root_dir.display()
        )));
    }
    Ok(root_dir)
}
