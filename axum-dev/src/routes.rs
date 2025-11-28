use axum::{http::StatusCode, middleware, routing::get, Router};
use tower_http::trace::TraceLayer;

use crate::{
    middleware::{
        trusted_forwarded_for, trusted_header_auth, user_session::user_session_middleware,
    },
    AppState,
};

pub mod debug;
pub mod hello;
pub mod login;
pub mod user;
pub mod whoami;

pub fn router(
    user_cfg: trusted_header_auth::TrustedHeaderAuthConfig,
    fwd_cfg: trusted_forwarded_for::TrustedForwardedForConfig,
) -> Router<AppState> {
    // Routes that *don’t* care about the ForwardAuth header
    let app = Router::<AppState>::new()
        .route("/", get(root))
        .route("/healthz", get(healthz))
        .nest("/hello", hello::router())
        .nest("/whoami", whoami::router())
        .nest("/user", user::router())
        .nest("/debug", debug::router())
        .fallback(fallback_404);

    // Routes that *do* require the trusted auth header:
    let login = Router::<AppState>::new()
        .route("/login", get(login::login_handler))
        .layer(middleware::from_fn_with_state(
            user_cfg,
            trusted_header_auth::trusted_header_auth,
        ));

    app.merge(login)
        .layer(TraceLayer::new_for_http())
        // stack order from outermost to innermost:
        // trusted_forwarded_for -> user_session_middleware -> routes
        .layer(middleware::from_fn(user_session_middleware))
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
