use crate::errors::AppError;
use axum::{
    extract::{Extension, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Redirect},
    routing::post,
    Form, Router,
};
use serde::Deserialize;
use tower_sessions::Session;

use crate::{
    middleware::{
        trusted_header_auth, trusted_header_auth::ForwardAuthUser, user_session::UserSession,
    },
    models::user,
    prelude::*,
    server::AppState,
};

pub fn router(user_cfg: trusted_header_auth::TrustedHeaderAuthConfig) -> Router<AppState> {
    Router::<AppState>::new()
        .route(
            "/login",
            post(login_handler).layer(middleware::from_fn_with_state(
                user_cfg,
                trusted_header_auth::trusted_header_auth,
            )),
        )
        .route("/logout", post(handle_logout))
}

#[derive(Deserialize)]
struct LoginForm {
    csrf_token: String,
}

async fn login_handler(
    State(state): State<AppState>,
    Extension(trusted_user): Extension<ForwardAuthUser>,
    mut user_session: UserSession,
    session: Session,
    Form(form): Form<LoginForm>,
) -> AppResult<impl IntoResponse> {
    // CSRF check first
    if form.csrf_token != user_session.csrf_token {
        tracing::warn!(
            "CSRF mismatch in login: form={}, session={}",
            form.csrf_token,
            user_session.csrf_token
        );
        // however you like to express 403/401 in AppResult
        return Err(AppError::unauthorized("invalid CSRF token"));
    }

    let external_id = trusted_user.external_id.clone();
    debug!("external_id = {external_id}");

    let user = user::get_or_create_by_external_id(&state.db, &external_id).await?;
    debug!("user = {user:?}");

    user_session.external_user_id = Some(user.external_id);
    user_session.persist(&session).await?;

    Ok(Redirect::to("/login").into_response())
}

#[derive(Deserialize)]
struct LogoutForm {
    csrf_token: String,
}

async fn handle_logout(
    mut user_session: UserSession,
    session: Session,
    Form(form): Form<LogoutForm>,
) -> impl IntoResponse {
    if form.csrf_token != user_session.csrf_token {
        tracing::warn!(
            "CSRF mismatch in logout: form={}, session={}",
            form.csrf_token,
            user_session.csrf_token
        );
        return StatusCode::UNAUTHORIZED.into_response();
    }

    user_session.external_user_id = None;

    if let Err(err) = session.flush().await {
        tracing::error!("Failed to flush session on logout: {err}");
    }

    Redirect::to("/login").into_response()
}
