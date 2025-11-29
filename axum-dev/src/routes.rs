use axum::{http::StatusCode, middleware, routing::get, Router};
use tower_http::{services::ServeDir, trace::TraceLayer};

use crate::{
    middleware::{
        admin_only::admin_only_middleware, csrf_protection, trusted_forwarded_for,
        trusted_header_auth, user_session::user_session_middleware,
    },
    AppState,
};

pub mod admin;
pub mod api;
pub mod hello;
pub mod html;
pub mod login;
pub mod user;
pub mod whoami;

pub fn router(
    hdr_auth_cfg: trusted_header_auth::TrustedHeaderAuthConfig,
    fwd_for_cfg: trusted_forwarded_for::TrustedForwardedForConfig,
    state: AppState,
) -> Router<AppState> {
    let api = Router::<AppState>::new()
        .nest("/api", api::router())
        .layer(middleware::from_fn(csrf_protection::csrf_middleware));

    let admin_api = Router::<AppState>::new()
        .nest("/admin", admin::router())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admin_only_middleware,
        ))
        .layer(middleware::from_fn(csrf_protection::csrf_middleware));

    Router::<AppState>::new()
        .merge(api)
        .merge(admin_api)
        .merge(login::router(hdr_auth_cfg))
        .merge(html::router())
        .nest_service("/static", ServeDir::new("static"))
        .route("/favicon.ico", get(favicon))
        .layer(middleware::from_fn(user_session_middleware))
        .layer(middleware::from_fn_with_state(
            fwd_for_cfg,
            trusted_forwarded_for::trusted_forwarded_for,
        ))
        .layer(TraceLayer::new_for_http())
        .fallback(fallback_404)
}

async fn fallback_404() -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "Not Found")
}

async fn favicon() -> StatusCode {
    StatusCode::NO_CONTENT
}
