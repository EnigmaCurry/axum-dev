use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use crate::{
    config::{AppConfig, TlsAcmeChallenge, TlsMode},
    ensure_root_dir,
    errors::CliError,
    middleware::{self, auth::AuthenticationMethod},
    server,
    util::write_files::create_private_dir_all_0700_sync,
};
use anyhow::Context;
use axum::http::HeaderName;
use tracing::{debug, error, info};

pub struct ServePlan {
    pub addr: SocketAddr,
    pub tls_config: server::TlsConfig,
    pub db_url: String,
    pub auth_cfg: middleware::trusted_header_auth::ForwardAuthConfig,
    pub fwd_cfg: middleware::trusted_forwarded_for::TrustedForwardedForConfig,
    pub session_secure: bool,
    pub session_expiry_secs: u64,
    pub session_check_secs: u64,
}

fn plan_serve(cfg: &AppConfig, root_dir: &Path) -> Result<ServePlan, CliError> {
    let addr = parse_listen_addr(cfg)?;
    let tls_config = build_tls_config(cfg, root_dir)?;
    let db_url = build_db_url(cfg, root_dir);
    let (auth_cfg, fwd_cfg) = build_auth_cfgs(cfg)?;

    Ok(ServePlan {
        addr,
        tls_config,
        db_url,
        auth_cfg,
        fwd_cfg,
        session_secure: true,
        session_expiry_secs: cfg.session.expiry_seconds,
        session_check_secs: cfg.session.check_seconds,
    })
}

pub fn serve(cfg: AppConfig, root_dir: PathBuf) -> Result<(), CliError> {
    let root_dir = ensure_root_dir(root_dir)?;

    let plan = plan_serve(&cfg, &root_dir)?;

    debug!(?cfg, "serve(): parsed cfg");
    info!("Server will listen on {}", plan.addr);
    info!("Database URL: {:?}", plan.db_url);
    debug!(
        "Session config: secure={}, expiry_secs={}, check_secs={}",
        plan.session_secure, plan.session_expiry_secs, plan.session_check_secs
    );

    let rt = create_runtime()?;
    rt.block_on(server::run(
        plan.addr,
        plan.auth_cfg,
        plan.fwd_cfg,
        plan.db_url,
        plan.session_secure,
        plan.session_expiry_secs,
        plan.session_check_secs,
        plan.tls_config,
    ))
    .map_err(|e| {
        error!("server::run failed: {:#}", e);
        CliError::RuntimeError(format!("{:#}", e))
    })
}

fn parse_listen_addr(cfg: &AppConfig) -> Result<SocketAddr, CliError> {
    let ip = &cfg.network.listen_ip;
    let port = cfg.network.listen_port;
    let addr_str = format!("{ip}:{port}");

    addr_str
        .parse()
        .map_err(|e| CliError::InvalidArgs(format!("Invalid listen addr '{addr_str}': {e}")))
}

fn build_tls_config(cfg: &AppConfig, root_dir: &Path) -> Result<server::TlsConfig, CliError> {
    match cfg.tls.mode {
        TlsMode::None => {
            info!("TLS mode: none (plain HTTP).");
            Ok(server::TlsConfig::Http)
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

            Ok(server::TlsConfig::RustlsFiles {
                cert_path,
                key_path,
            })
        }

        TlsMode::SelfSigned => {
            let cache_dir = Some(root_dir.join("tls-cache"));
            let sans = cfg.tls.sans.0.clone();
            let valid_days = cfg.tls.self_signed_valid_days;

            info!(
                "TLS mode: self-signed (HTTPS) – cache_dir={:?}, sans={:?}, valid_days={}",
                cache_dir, sans, valid_days
            );

            Ok(server::TlsConfig::SelfSigned {
                cache_dir,
                sans,
                valid_days,
            })
        }

        TlsMode::Acme => {
            let cache_dir: PathBuf = root_dir.join("tls-cache");
            create_private_dir_all_0700_sync(&cache_dir).context((|| {
                format!("TLS cache dir invalid: {}", cache_dir.display())
            })())?;

            let domains = build_acme_domains(cfg)?;
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

                    Ok(server::TlsConfig::AcmeTlsAlpn01 {
                        directory_url,
                        cache_dir,
                        domains,
                        contact_email,
                    })
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

                    Ok(server::TlsConfig::AcmeDns01 {
                        directory_url,
                        cache_dir,
                        domains,
                        contact_email,
                        acme_dns_api_base: cfg.tls.acme_dns_api_base.clone(),
                    })
                }

                TlsAcmeChallenge::Http01 => Err(CliError::InvalidArgs(
                    "HTTP-01 is not supported yet. \
                     Use --tls-acme-challenge=tls-alpn-01 or dns-01."
                        .to_string(),
                )),
            }
        }
    }
}

fn build_acme_domains(cfg: &AppConfig) -> Result<Vec<String>, CliError> {
    let mut domains: Vec<String> = cfg
        .tls
        .sans
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    if let Some(ref host) = cfg.network.host
        && !host.trim().is_empty()
    {
        domains.push(host.clone());
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

    Ok(domains)
}

fn build_db_url(cfg: &AppConfig, root_dir: &Path) -> String {
    match cfg.database.url.as_ref() {
        None => {
            let db_path = root_dir.join("data.db");
            format!("sqlite://{}", db_path.display())
        }
        Some(url) => url.clone(),
    }
}

fn build_auth_cfgs(
    cfg: &AppConfig,
) -> Result<
    (
        middleware::trusted_header_auth::ForwardAuthConfig,
        middleware::trusted_forwarded_for::TrustedForwardedForConfig,
    ),
    CliError,
> {
    let auth_method: AuthenticationMethod = cfg.auth.method;

    let header_name_str = cfg.auth.trusted_header_name.as_str();
    let trusted_header_name = parse_header_name(header_name_str, "trusted header")?;

    let trusted_proxy: Option<IpAddr> = cfg.auth.trusted_proxy;

    let auth_cfg = middleware::trusted_header_auth::ForwardAuthConfig {
        method: auth_method,
        trusted_header_name,
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
            info!("Authentication method: UsernamePassword");
        }
    }

    let fwd_enabled = cfg.auth.trusted_forwarded_for;
    let fwd_header_str = cfg.auth.trusted_forwarded_for_name.as_str();
    let fwd_header_name = parse_header_name(fwd_header_str, "forwarded-for header")?;

    let fwd_cfg = middleware::trusted_forwarded_for::TrustedForwardedForConfig {
        enabled: fwd_enabled,
        header_name: fwd_header_name,
        trusted_proxy,
    };

    if fwd_enabled && let Some(t) = trusted_proxy {
        info!("Trusted FORWARDED-FOR enabled: header='{fwd_header_str}', trusted_proxy={t}");
    }

    Ok((auth_cfg, fwd_cfg))
}

fn parse_header_name(name: &str, label: &str) -> Result<HeaderName, CliError> {
    HeaderName::from_bytes(name.as_bytes())
        .map_err(|e| CliError::InvalidArgs(format!("Invalid {label} name '{name}': {e}")))
}

fn create_runtime() -> Result<tokio::runtime::Runtime, CliError> {
    tokio::runtime::Runtime::new().map_err(|e| {
        error!("Failed to create Tokio runtime: {e}");
        CliError::RuntimeError(format!("Failed to start Tokio runtime: {e}"))
    })
}

#[test]
fn plan_serve_builds_expected_db_url_and_addr() {
    // Build a minimal config (fill in fields as needed for your structs)
    let cfg = AppConfig {
        network: crate::config::NetworkConfig {
            listen_ip: "127.0.0.1".to_string(),
            listen_port: 3001,
            host: None,
            // ..other fields
        },
        database: crate::config::DatabaseConfig {
            url: None, /* .. */
        },
        session: crate::config::SessionConfig {
            expiry_seconds: 3600,
            check_seconds: 60,
            // ..
        },
        auth: crate::config::AuthConfig {
            // ensure this matches validation expectations
            // ..
            ..Default::default()
        },
        tls: crate::config::TlsConfig {
            mode: crate::config::TlsMode::None,
            // ..
            ..Default::default()
        },
    };

    let root = std::path::PathBuf::from("/tmp/axum-dev-test");
    let plan = plan_serve(&cfg, &root).expect("plan_serve should succeed");

    assert_eq!(plan.addr.to_string(), "127.0.0.1:3001");
    assert!(plan.db_url.contains("sqlite://"));
    assert!(plan.db_url.contains("data.db"));
}
