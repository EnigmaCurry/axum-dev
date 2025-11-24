use axum::{http::StatusCode, middleware, routing::get, Router};
use tower_http::trace::TraceLayer;

use crate::{
    middleware::{
        trusted_forwarded_for, trusted_header_auth, TrustedForwardedForConfig,
        TrustedHeaderAuthConfig,
    },
    AppState,
};

pub mod hello;
pub mod user;
pub mod whoami;

/// Build your Axum router. Keep this as a separate function so it’s testable.
pub fn router(
    user_cfg: TrustedHeaderAuthConfig,
    fwd_cfg: TrustedForwardedForConfig,
) -> Router<AppState> {
    let app = Router::<AppState>::new()
        .route("/", get(root))
        .route("/healthz", get(healthz))
        .nest("/hello", hello::router())
        .nest("/whoami", whoami::router())
        .nest("/user", user::router())
        .fallback(fallback_404)
        .layer(TraceLayer::new_for_http());

    // Always install both middlewares; they self-disable and
    // reject spoofing when disabled.
    app.layer(middleware::from_fn_with_state(
        fwd_cfg,
        trusted_forwarded_for,
    ))
    .layer(middleware::from_fn_with_state(
        user_cfg,
        trusted_header_auth,
    ))
}

async fn root() -> &'static str {
    "OK"
}

async fn healthz() -> &'static str {
    "healthy"
}

async fn fallback_404() -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "Not Found")
}
