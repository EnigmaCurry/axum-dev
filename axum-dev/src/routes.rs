use axum::{http::StatusCode, middleware, routing::get, Router};
use tower_http::{services::ServeDir, trace::TraceLayer};

use crate::{
    middleware::{
        csrf_protection, trusted_forwarded_for, trusted_header_auth,
        user_session::user_session_middleware,
    },
    AppState,
};

pub mod debug;
pub mod hello;
pub mod html;
pub mod login;
pub mod user;
pub mod whoami;

pub fn router(
    user_cfg: trusted_header_auth::TrustedHeaderAuthConfig,
    fwd_cfg: trusted_forwarded_for::TrustedForwardedForConfig,
) -> Router<AppState> {
    // 1) JSON APIs (all behind CSRF middleware)
    let api = Router::<AppState>::new()
        .route("/healthz", get(healthz))
        .nest("/hello", hello::router())
        .nest("/whoami", whoami::router())
        .nest("/user", user::router())
        .layer(middleware::from_fn(csrf_protection::csrf_middleware));

    // 2) Start with an empty app:
    let app = Router::<AppState>::new();
    // 2b) add /debug only for debug builds:
    let app = with_debug_routes(app);

    // 3) Compose everything together
    let app = app
        // JSON APIs (CSRF-protected)
        .nest("/api", api)
        // Login / logout – these do their own CSRF checks in the handlers
        .merge(login::router(user_cfg))
        // HTML pages + whoami UI, login form, etc.
        .merge(html::router())
        // Static assets
        .nest_service("/static", ServeDir::new("static"))
        .route("/favicon.ico", get(favicon))
        // Global middlewares
        .layer(middleware::from_fn(user_session_middleware))
        .layer(middleware::from_fn_with_state(
            fwd_cfg,
            trusted_forwarded_for::trusted_forwarded_for,
        ))
        .layer(TraceLayer::new_for_http())
        .fallback(fallback_404);

    app
}

// helper that’s compiled differently in debug vs release
fn with_debug_routes(app: Router<AppState>) -> Router<AppState> {
    #[cfg(debug_assertions)]
    {
        app.nest("/debug", debug::router())
    }

    #[cfg(not(debug_assertions))]
    {
        app
    }
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

async fn favicon() -> StatusCode {
    StatusCode::NO_CONTENT
}
