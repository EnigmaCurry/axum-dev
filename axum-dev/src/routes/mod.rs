use aide::{axum::ApiRouter, openapi::OpenApi};
use axum::{Extension, Router, http::StatusCode, middleware, routing::get};
use std::sync::Arc;
use tower_http::{services::ServeDir, trace::TraceLayer};

use crate::{
    AppState,
    api_docs::{configure_openapi, docs_routes},
    middleware::{
        admin_only::admin_only_middleware, csrf_protection, trusted_forwarded_for,
        trusted_header_auth, user_session::user_session_middleware,
    },
};

pub mod admin;
pub mod api;
pub mod healthz;
pub mod hello;
pub mod login;
pub mod user;
pub mod whoami;

pub fn router(
    hdr_auth_cfg: trusted_header_auth::ForwardAuthConfig,
    fwd_for_cfg: trusted_forwarded_for::TrustedForwardedForConfig,
    state: AppState,
) -> Router<AppState> {
    let user_api = ApiRouter::<AppState>::new()
        .nest("/api", api::router())
        .layer(middleware::from_fn(csrf_protection::csrf_middleware));

    let login_api =
        login::router(hdr_auth_cfg).layer(middleware::from_fn(csrf_protection::csrf_middleware));

    let admin_api = ApiRouter::<AppState>::new()
        .nest("/admin", admin::router())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admin_only_middleware,
        ))
        .layer(middleware::from_fn(csrf_protection::csrf_middleware));

    let mut api_spec = OpenApi::default();

    ApiRouter::<AppState>::new()
        // Add all API routes:
        .merge(user_api)
        .merge(login_api)
        // Mount docs (stateless ApiRouter<()>)
        .nest_api_service("/docs", docs_routes())
        // Apply shared OpenAPI configuration:
        .finish_api_with(&mut api_spec, configure_openapi)
        .layer(Extension(Arc::new(api_spec)))
        // Admin route (not documented in OpenAPI spec)
        .merge(admin_api)
        // Add non-API routes:
        .nest_service("/static", ServeDir::new("static"))
        .route("/favicon.ico", get(favicon))
        // Add frontend fallback:
        .route("/", get(crate::frontend::spa_handler))
        .route("/{*path}", get(crate::frontend::spa_handler))
        // Add global middleware:
        .layer(middleware::from_fn(user_session_middleware))
        .layer(middleware::from_fn_with_state(
            fwd_for_cfg,
            trusted_forwarded_for::trusted_forwarded_for,
        ))
        .layer(TraceLayer::new_for_http())
}

async fn favicon() -> StatusCode {
    StatusCode::NO_CONTENT
}
