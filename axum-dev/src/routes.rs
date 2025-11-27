use axum::{http::StatusCode, middleware, routing::get, Router};
use tower_http::trace::TraceLayer;

use crate::{
    middleware::{
        trusted_forwarded_for, trusted_header_auth, user_session::user_session_middleware,
    },
    AppState,
};

pub mod hello;
pub mod user;
pub mod whoami;

/// Build your Axum router. Keep this as a separate function so it’s testable.
pub fn router(
    user_cfg: trusted_header_auth::TrustedHeaderAuthConfig,
    fwd_cfg: trusted_forwarded_for::TrustedForwardedForConfig,
) -> Router<AppState> {
    let app = Router::<AppState>::new()
        .route("/", get(root))
        .route("/healthz", get(healthz))
        .nest("/hello", hello::router())
        .nest("/whoami", whoami::router())
        .nest("/user", user::router())
        .fallback(fallback_404)
        .layer(TraceLayer::new_for_http());

    app
        // REMEMBER: layers are executed from BOTTOM UP (first in, last out).
        // user_session_middleware should run *after* forwarded_for and auth,
        // so it must be added first here (bottom of the stack):
        .layer(middleware::from_fn(user_session_middleware))
        .layer(middleware::from_fn_with_state(
            user_cfg,
            trusted_header_auth::trusted_header_auth,
        ))
        .layer(middleware::from_fn_with_state(
            fwd_cfg,
            trusted_forwarded_for::trusted_forwarded_for,
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
