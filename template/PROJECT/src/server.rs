use crate::{
    middleware::{
        trusted_forwarded_for::TrustedForwardedForConfig, trusted_header_auth::ForwardAuthConfig,
    },
    prelude::*,
    routes::router,
    tls::{
        dns::{AcmeDnsProvider, obtain_certificate_with_dns01},
        generate::{ensure_rustls_crypto_provider, generate_self_signed_with_validity},
    },
};
use anyhow::Context;
use axum_server::{Handle, tls_rustls::RustlsConfig};
use futures_util::StreamExt;
use rustls::ServerConfig as RustlsServerConfig;
use sqlx::{ConnectOptions, SqlitePool, sqlite::SqliteConnectOptions};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::fs;
use tokio::task::AbortHandle;
use tokio_rustls_acme::{AcmeConfig, caches::DirCache};
use tower_sessions::{
    Expiry, SessionManagerLayer, cookie::time::Duration as CookieDuration,
    session_store::ExpiredDeletion,
};
use tower_sessions_sqlx_store::SqliteStore;

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
}

#[derive(Clone, Debug)]
pub enum TlsConfig {
    /// Plain HTTP, no TLS.
    Http,
    /// Rustls with certificate and key loaded from PEM files.
    RustlsFiles {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
    /// Self-signed TLS, generated at startup.
    ///
    /// If `cache_dir` is Some, certificates are stored/reused there.
    /// If `cache_dir` is None, certificates are ephemeral (in-memory only).
    SelfSigned {
        cache_dir: Option<PathBuf>,
        sans: Vec<String>,
        valid_days: u32,
    },
    /// ACME (Let's Encrypt or other CA) via TLS-ALPN-01.
    ///
    /// Certificates and account data are stored in `cache_dir`.
    AcmeTlsAlpn01 {
        directory_url: String,
        cache_dir: PathBuf,
        domains: Vec<String>,
        contact_email: Option<String>,
    },

    /// ACME via **DNS-01**, using a DNS provider (e.g. acme-dns).
    ///
    /// Certificates and account data are stored in `cache_dir`.
    AcmeDns01 {
        directory_url: String,
        cache_dir: PathBuf,
        domains: Vec<String>,
        contact_email: Option<String>,
        acme_dns_api_base: String,
    },
}

/// Run the HTTP server until shutdown.
pub async fn run(
    addr: SocketAddr,
    user_cfg: ForwardAuthConfig,
    fwd_cfg: TrustedForwardedForConfig,
    db_url: String,
    session_secure: bool,
    session_expiry_secs: u64,
    session_check_secs: u64,
    tls_config: TlsConfig,
) -> anyhow::Result<()> {
    // Helpful to see where we're running from
    let cwd =
        std::env::current_dir().with_context(|| "failed to determine current working directory")?;
    tracing::info!(
        "server::run starting; cwd='{}', db_url='{}'",
        cwd.display(),
        db_url
    );

    // Database pool and migration
    let connect_opts = SqliteConnectOptions::from_str(&db_url)?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .log_statements(tracing::log::LevelFilter::Trace)
        .log_slow_statements(
            tracing::log::LevelFilter::Warn,
            std::time::Duration::from_millis(100),
        );
    let db: SqlitePool = SqlitePool::connect_with(connect_opts).await?;
    info!("Loaded database connection pool. DATABASE_URL={db_url}");
    sqlx::migrate!().run(&db.clone()).await?;

    // Session store
    let session_store = SqliteStore::new(db.clone());
    session_store.migrate().await?;

    let deletion_task = tokio::task::spawn(
        session_store
            .clone()
            .continuously_delete_expired(core::time::Duration::from_secs(session_check_secs)),
    );

    // Convert the CLI/env-specified seconds into a cookie::time::Duration
    let session_expiry = CookieDuration::seconds(session_expiry_secs as i64);

    let session_layer = SessionManagerLayer::new(session_store.clone())
        .with_secure(session_secure)
        .with_expiry(Expiry::OnInactivity(session_expiry));

    // Shared state
    let state = AppState { db };

    let app = router(user_cfg, fwd_cfg, state.clone())
        .layer(session_layer)
        .with_state(state);

    ensure_rustls_crypto_provider();

    match tls_config {
        TlsConfig::Http => {
            match tokio::net::TcpListener::bind(addr).await {
                Ok(listener) => {
                    let bound_addr = listener.local_addr()?;
                    info!("listening on http://{bound_addr}");

                    axum::serve(
                        listener,
                        app.into_make_service_with_connect_info::<SocketAddr>(),
                    )
                    .with_graceful_shutdown(shutdown_signal(deletion_task.abort_handle(), None))
                    .await?;
                }
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    // Privileged-port helper message
                    return Err(anyhow::anyhow!(
                        "Failed to bind to {addr}: Permission denied (os error 13).\n\
             On Unix-like systems, binding to ports below 1024 (like 80 or 443) \
             requires elevated privileges (e.g., running as root or with CAP_NET_BIND_SERVICE).\n\
             Either:\n  - run this binary with appropriate privileges, or\n  - use a higher port (e.g. 3000) and put a reverse proxy (nginx, caddy, traefik) in front."
                    ));
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Failed to bind to {addr}: {e}"));
                }
            }
        }
        TlsConfig::RustlsFiles {
            cert_path,
            key_path,
        } => {
            info!(
                "loading TLS certificate from '{}' and key from '{}'",
                cert_path.display(),
                key_path.display()
            );

            let rustls_config =
                axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path).await?;

            // Create a handle for graceful shutdown
            let handle = axum_server::Handle::new();

            // Spawn the shutdown handler that will:
            //  - abort the deletion task
            //  - call handle.graceful_shutdown(...)
            let shutdown_task = tokio::spawn(shutdown_signal(
                deletion_task.abort_handle(),
                Some(handle.clone()),
            ));

            info!("listening on https://{addr}");

            let server = axum_server::bind_rustls(addr, rustls_config)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>());

            if let Err(e) = server.await {
                // axum_server error is usually an io::Error under the hood, but we only
                // get it via its Display. So we pattern-match on the string to detect EACCES.
                let msg = e.to_string();
                if msg.contains("Permission denied") {
                    return Err(anyhow::anyhow!(
                        "Failed to start HTTPS listener on {addr}: {msg}\n\
             This usually means you're trying to bind to a privileged port \
             (below 1024, such as 443) without sufficient privileges.\n\
             Either:\n  - run with appropriate permissions (root or CAP_NET_BIND_SERVICE), or\n  - listen on a higher port (e.g. 3000) and front it with a reverse proxy."
                    ));
                } else {
                    return Err(anyhow::anyhow!("HTTPS server failed on {addr}: {e}"));
                }
            }

            // Make sure the shutdown task has finished (and bubble up any errors)
            shutdown_task.await?;
        }
        TlsConfig::SelfSigned {
            cache_dir,
            mut sans,
            valid_days, // still used for generation, see note below
        } => {
            if sans.is_empty() {
                sans.push("localhost".to_string());
            }

            let (cert_pem, key_pem) = if let Some(dir) = cache_dir {
                fs::create_dir_all(&dir).await?;

                let cert_path = dir.join("self_signed_cert.pem");
                let key_path = dir.join("self_signed_key.pem");

                // Try to load & validate the cached cert using x509-parser
                use rustls_pemfile::certs as load_pem_certs;
                use x509_parser::prelude::*;

                let use_cached = if cert_path.exists() && key_path.exists() {
                    match fs::read(&cert_path).await {
                        Ok(pem_bytes) => {
                            let mut slice: &[u8] = &pem_bytes;
                            let mut iter = load_pem_certs(&mut slice);

                            // Option<Result<CertificateDer<'static>, io::Error>>
                            match iter.next().transpose() {
                                Ok(Some(der)) => match parse_x509_certificate(der.as_ref()) {
                                    Ok((_rem, x509)) => {
                                        let validity = x509.validity();
                                        let now = ASN1Time::now();
                                        if validity.is_valid_at(now) {
                                            true
                                        } else {
                                            info!(
                                                "Cached self-signed cert at '{}' is expired/invalid; regenerating",
                                                cert_path.display()
                                            );
                                            false
                                        }
                                    }
                                    Err(err) => {
                                        info!(
                                            "Failed to parse cached self-signed cert '{}': {err}; regenerating",
                                            cert_path.display()
                                        );
                                        false
                                    }
                                },
                                Ok(None) => {
                                    info!(
                                        "Cached self-signed cert '{}' has no certificates; regenerating",
                                        cert_path.display()
                                    );
                                    false
                                }
                                Err(err) => {
                                    info!(
                                        "Failed to decode PEM for cached self-signed cert '{}': {err}; regenerating",
                                        cert_path.display()
                                    );
                                    false
                                }
                            }
                        }
                        Err(err) => {
                            info!(
                                "Failed to read cached self-signed cert '{}': {err}; regenerating",
                                cert_path.display()
                            );
                            false
                        }
                    }
                } else {
                    false
                };

                if use_cached {
                    // unchanged
                    let cert = fs::read(&cert_path).await?;
                    let key = fs::read(&key_path).await?;
                    info!(
                        "Loading cached self-signed TLS certificate from '{}' and key from '{}'",
                        cert_path.display(),
                        key_path.display()
                    );
                    (cert, key)
                } else {
                    info!(
                        "Generating new cached self-signed TLS certificate \
         (valid_days={}, sans={:?}) in '{}'",
                        valid_days,
                        sans,
                        dir.display()
                    );

                    let (cert_pem, key_pem) = generate_self_signed_with_validity(sans, valid_days)?;

                    fs::write(&cert_path, &cert_pem).await?;
                    fs::write(&key_path, &key_pem).await?;
                    (cert_pem, key_pem)
                }
            } else {
                info!(
                    "Generating ephemeral self-signed TLS certificate \
         (valid_days={}, sans={:?}); not cached",
                    valid_days, sans
                );

                generate_self_signed_with_validity(sans, valid_days)?
            };

            let rustls_config = RustlsConfig::from_pem(cert_pem, key_pem).await?;

            let handle = Handle::new();
            let shutdown_task = tokio::spawn(shutdown_signal(
                deletion_task.abort_handle(),
                Some(handle.clone()),
            ));

            info!("listening on https://{addr} (self-signed)");

            let server = axum_server::bind_rustls(addr, rustls_config)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>());

            if let Err(e) = server.await {
                // axum_server error is usually an io::Error under the hood, but we only
                // get it via its Display. So we pattern-match on the string to detect EACCES.
                let msg = e.to_string();
                if msg.contains("Permission denied") {
                    return Err(anyhow::anyhow!(
                        "Failed to start HTTPS listener on {addr}: {msg}\n\
             This usually means you're trying to bind to a privileged port \
             (below 1024, such as 443) without sufficient privileges.\n\
             Either:\n  - run with appropriate permissions (root or CAP_NET_BIND_SERVICE), or\n  - listen on a higher port (e.g. 3000) and front it with a reverse proxy."
                    ));
                } else {
                    return Err(anyhow::anyhow!("HTTPS server failed on {addr}: {e}"));
                }
            }

            shutdown_task.await?;
        }
        TlsConfig::AcmeTlsAlpn01 {
            directory_url,
            cache_dir,
            domains,
            contact_email,
        } => {
            // Ensure cache dir exists
            fs::create_dir_all(&cache_dir).await.with_context(|| {
                format!("failed to create TLS cache dir '{}'", cache_dir.display())
            })?;

            info!(
                "Starting ACME TLS (tls-alpn-01) – directory_url='{}', cache_dir='{}', domains={:?}, contact_email={:?}",
                directory_url,
                cache_dir.display(),
                domains,
                contact_email,
            );

            // Build ACME configuration
            let mut state = {
                let mut cfg = AcmeConfig::new(domains.clone())
                    .cache(DirCache::new(cache_dir.clone()))
                    .directory(directory_url.clone());

                if let Some(ref email) = contact_email {
                    if !email.is_empty() {
                        cfg = cfg.contact([format!("mailto:{email}")]);
                    }
                }

                cfg.state()
            };

            // Hook ACME into rustls
            let rustls_config = RustlsServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(state.resolver());

            let acceptor = state.axum_acceptor(Arc::new(rustls_config));

            // Drive ACME state + log events
            tokio::spawn(async move {
                while let Some(res) = state.next().await {
                    match res {
                        Ok(ev) => tracing::info!("acme event: {:?}", ev),
                        Err(err) => tracing::error!("acme error: {:?}", err),
                    }
                }
            });

            // axum_server + graceful shutdown, same pattern as self-signed
            let handle = Handle::new();
            let shutdown_task = tokio::spawn(shutdown_signal(
                deletion_task.abort_handle(),
                Some(handle.clone()),
            ));

            info!("listening on https://{addr} (ACME)");

            let server = axum_server::bind(addr)
                .handle(handle)
                .acceptor(acceptor)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>());

            if let Err(e) = server.await {
                // axum_server error is usually an io::Error under the hood, but we only
                // get it via its Display. So we pattern-match on the string to detect EACCES.
                let msg = e.to_string();
                if msg.contains("Permission denied") {
                    return Err(anyhow::anyhow!(
                        "Failed to start HTTPS listener on {addr}: {msg}\n\
             This usually means you're trying to bind to a privileged port \
             (below 1024, such as 443) without sufficient privileges.\n\
             Either:\n  - run with appropriate permissions (root or CAP_NET_BIND_SERVICE), or\n  - listen on a higher port (e.g. 3000) and front it with a reverse proxy."
                    ));
                } else {
                    return Err(anyhow::anyhow!("HTTPS server failed on {addr}: {e}"));
                }
            }

            shutdown_task.await?;
        }
        TlsConfig::AcmeDns01 {
            directory_url,
            cache_dir,
            domains,
            contact_email,
            acme_dns_api_base,
        } => {
            // Ensure cache dir exists
            fs::create_dir_all(&cache_dir).await?;

            info!(
                "Starting ACME TLS (dns-01) – directory_url='{}', cache_dir='{}', domains={:?}, contact_email={:?}",
                directory_url,
                cache_dir.display(),
                domains,
                contact_email,
            );

            // Paths to cache the issued certificate + key.
            let cert_path = cache_dir.join("acme-dns01-cert.pem");
            let key_path = cache_dir.join("acme-dns01-key.pem");

            // Try to reuse a cached, still-valid certificate if present.
            let (cert_pem, key_pem) = {
                use rustls_pemfile::certs as load_pem_certs;
                use x509_parser::prelude::*;

                let use_cached = if cert_path.exists() && key_path.exists() {
                    match fs::read(&cert_path).await {
                        Ok(pem_bytes) => {
                            let mut slice: &[u8] = &pem_bytes;
                            let mut iter = load_pem_certs(&mut slice);

                            match iter.next().transpose() {
                                Ok(Some(der)) => match parse_x509_certificate(der.as_ref()) {
                                    Ok((_rem, x509)) => {
                                        let validity = x509.validity();
                                        let now = ASN1Time::now();
                                        if validity.is_valid_at(now) {
                                            info!(
                                                "Using cached ACME dns-01 certificate from '{}'",
                                                cert_path.display()
                                            );
                                            true
                                        } else {
                                            info!(
                                                "Cached ACME dns-01 cert at '{}' is expired/invalid; requesting a new one",
                                                cert_path.display()
                                            );
                                            false
                                        }
                                    }
                                    Err(err) => {
                                        info!(
                                            "Failed to parse cached ACME dns-01 cert '{}': {err}; requesting a new one",
                                            cert_path.display()
                                        );
                                        false
                                    }
                                },
                                Ok(None) => {
                                    info!(
                                        "Cached ACME dns-01 cert '{}' has no certificates; requesting a new one",
                                        cert_path.display()
                                    );
                                    false
                                }
                                Err(err) => {
                                    info!(
                                        "Failed to decode PEM for cached ACME dns-01 cert '{}': {err}; requesting a new one",
                                        cert_path.display()
                                    );
                                    false
                                }
                            }
                        }
                        Err(err) => {
                            info!(
                                "Failed to read cached ACME dns-01 cert '{}': {err}; requesting a new one",
                                cert_path.display()
                            );
                            false
                        }
                    }
                } else {
                    // No cached files yet.
                    false
                };

                if use_cached {
                    let cert = fs::read(&cert_path).await?;
                    let key = fs::read(&key_path).await?;
                    (cert, key)
                } else {
                    info!(
                        "Requesting new ACME dns-01 certificate (directory_url='{}', domains={:?})",
                        directory_url, domains
                    );

                    // Build DNS provider from cached creds + CLI api_base.
                    let dns_provider = AcmeDnsProvider::from_cache(&acme_dns_api_base, &cache_dir)
                        .await?
                        .into_shared();

                    let (cert_pem, key_pem) = obtain_certificate_with_dns01(
                        &directory_url,
                        contact_email.as_deref(),
                        &domains,
                        dns_provider.as_ref(),
                        &cache_dir,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("ACME dns-01 flow failed: {e:#}"))?;

                    // Persist cert + key for next run.
                    fs::write(&cert_path, &cert_pem).await.with_context(|| {
                        format!(
                            "failed to write ACME dns-01 certificate to '{}'",
                            cert_path.display()
                        )
                    })?;
                    fs::write(&key_path, &key_pem).await.with_context(|| {
                        format!(
                            "failed to write ACME dns-01 key to '{}'",
                            key_path.display()
                        )
                    })?;

                    info!(
                        "Wrote ACME dns-01 certificate to '{}' and key to '{}'",
                        cert_path.display(),
                        key_path.display()
                    );

                    (cert_pem, key_pem)
                }
            };

            let rustls_config = RustlsConfig::from_pem(cert_pem, key_pem).await?;

            let handle = Handle::new();
            let shutdown_task = tokio::spawn(shutdown_signal(
                deletion_task.abort_handle(),
                Some(handle.clone()),
            ));

            info!("listening on https://{addr} (ACME dns-01)");

            let server = axum_server::bind_rustls(addr, rustls_config)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>());

            if let Err(e) = server.await {
                // axum_server error is usually an io::Error under the hood, but we only
                // get it via its Display. So we pattern-match on the string to detect EACCES.
                let msg = e.to_string();
                if msg.contains("Permission denied") {
                    return Err(anyhow::anyhow!(
                        "Failed to start HTTPS listener on {addr}: {msg}\n\
             This usually means you're trying to bind to a privileged port \
             (below 1024, such as 443) without sufficient privileges.\n\
             Either:\n  - run with appropriate permissions (root or CAP_NET_BIND_SERVICE), or\n  - listen on a higher port (e.g. 3000) and front it with a reverse proxy."
                    ));
                } else {
                    return Err(anyhow::anyhow!("HTTPS server failed on {addr}: {e}"));
                }
            }

            shutdown_task.await?;
        }
    }

    // Make sure the background deletion task finishes cleanly.
    deletion_task.await??;

    Ok(())
}

/// Shutdown signal for graceful shutdown on Ctrl+C / SIGTERM.
async fn shutdown_signal(deletion_task_abort_handle: AbortHandle, handle: Option<Handle>) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        signal(SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    // Stop the background deletion task
    deletion_task_abort_handle.abort();

    // If we are running behind axum_server, trigger graceful shutdown there too
    if let Some(handle) = handle {
        // You can tune the timeout; 10 seconds is a typical choice.
        handle.graceful_shutdown(Some(Duration::from_secs(10)));
    }

    info!("shutdown signal received; starting graceful shutdown");
}
