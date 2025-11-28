use axum::{
    http::StatusCode,
    middleware,
    routing::get,
    Router,
};
use tower_http::{services::ServeDir, trace::TraceLayer};

use crate::{
    middleware::{
        trusted_forwarded_for, trusted_header_auth, user_session::user_session_middleware,
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
    let app = Router::<AppState>::new()
        .merge(html::router())
        .nest_service("/static", ServeDir::new("static"))
        .route("/healthz", get(healthz))
        .nest("/hello", hello::router())
        .nest("/whoami", whoami::router())
        .nest("/user", user::router())
        .fallback(fallback_404);

    // conditionally add /debug in debug builds only
    let app = with_debug_routes(app);

    let app = app
        .merge(login::router(user_cfg))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(user_session_middleware))
        .layer(middleware::from_fn_with_state(
            fwd_cfg,
            trusted_forwarded_for::trusted_forwarded_for,
        ));

    let favicon = Router::new().route("/favicon.ico", get(favicon));
    app.merge(favicon)
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
