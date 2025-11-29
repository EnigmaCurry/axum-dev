use crate::{
    errors::AppError,
    views::{HtmlTemplate, LoginTemplate},
};
use axum::{
    extract::{Extension, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Redirect},
    routing::{get, post},
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
            get(get_login)
                .post(login_handler)
                .layer(middleware::from_fn_with_state(
                    user_cfg,
                    trusted_header_auth::trusted_header_auth,
                )),
        )
        .route("/logout", post(logout_handler))
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
        return Err(AppError::unauthorized("invalid CSRF token"));
    }

    let external_id = trusted_user.external_id.clone();
    tracing::debug!("POST /login external_id = {external_id}");

    let user = user::get_or_create_by_external_id(&state.db, &external_id).await?;
    tracing::debug!("user = {user:?}");

    user_session.external_user_id = Some(user.external_id);
    user_session.is_logged_in = true;
    user_session.persist(&session).await?;

    Ok(Redirect::to("/login"))
}

pub async fn get_login(
    State(_state): State<AppState>,
    Extension(trusted_user): Extension<ForwardAuthUser>,
    user_session: UserSession,
) -> AppResult<impl IntoResponse> {
    let external_id = trusted_user.external_id.clone();
    tracing::debug!("GET /login external_id = {external_id}");

    let tmpl = LoginTemplate {
        title: "Login".to_string(),
        logged_in: user_session.is_logged_in,
        external_user_id: Some(trusted_user.external_id),
        csrf_token: user_session.csrf_token.clone(),
    };

    Ok(HtmlTemplate(tmpl))
}

#[derive(Deserialize)]
struct LogoutForm {
    csrf_token: String,
}

async fn logout_handler(
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
    user_session.is_logged_in = false;

    if let Err(err) = session.flush().await {
        tracing::error!("Failed to flush session on logout: {err}");
    }

    Redirect::to("/login").into_response()
}
