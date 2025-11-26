use sqlx::{sqlite::SqliteConnectOptions, ConnectOptions, SqlitePool};
use std::net::SocketAddr;
use tokio::task::AbortHandle;
use tower_sessions::{
    cookie::time::Duration, session_store::ExpiredDeletion, Expiry, SessionManagerLayer,
};
use tower_sessions_sqlx_store::SqliteStore;

use crate::{
    middleware::trusted_forwarded_for::TrustedForwardedForConfig,
    middleware::trusted_header_auth::TrustedHeaderAuthConfig, prelude::*, routes::router,
};

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub session_store: SqliteStore,
}

/// Run the HTTP server until shutdown.
pub async fn run(
    addr: SocketAddr,
    user_cfg: TrustedHeaderAuthConfig,
    fwd_cfg: TrustedForwardedForConfig,
    db_url: String,
    session_secure: bool,
    session_expiry_secs: u64,
    session_check_secs: u64,
) -> anyhow::Result<()> {
    // Database pool and migration
    let connect_opts = SqliteConnectOptions::from_str(&db_url)?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .log_statements(tracing::log::LevelFilter::Debug)
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
    let session_expiry = Duration::seconds(session_expiry_secs as i64);

    let session_layer = SessionManagerLayer::new(session_store.clone())
        .with_secure(session_secure)
        .with_expiry(Expiry::OnInactivity(session_expiry));

    // Shared state
    let state = AppState { db, session_store };

    let app = router(user_cfg, fwd_cfg)
        .layer(session_layer)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound_addr = listener.local_addr()?;
    info!("listening on http://{bound_addr}");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(deletion_task.abort_handle()))
    .await?;

    deletion_task.await??;

    Ok(())
}

/// Shutdown signal for graceful shutdown on Ctrl+C / SIGTERM.
async fn shutdown_signal(deletion_task_abort_handle: AbortHandle) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        signal(SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { deletion_task_abort_handle.abort() },
        _ = terminate => { deletion_task_abort_handle.abort() },
    }

    info!("shutdown signal received; starting graceful shutdown");
}
