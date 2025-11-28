use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use tower_sessions::Session;

use crate::{
    middleware::{trusted_header_auth::ForwardAuthUser, user_session::UserSession},
    models::user,
    prelude::*,
    server::AppState,
};

pub async fn login_handler(
    State(state): State<AppState>,
    Extension(trusted_user): Extension<ForwardAuthUser>,
    mut user_session: UserSession,
    session: Session,
) -> AppResult<impl IntoResponse> {
    let external_id = trusted_user.external_id.clone();
    debug!("external_id = {external_id}");

    // 1) let sqlx::Error bubble up as AppError
    let user = user::get_or_create_by_external_id(&state.db, &external_id).await?;
    debug!("user = {user:?}");

    user_session.forwarded_user_id = Some(ForwardAuthUser {
        external_id: user.external_id,
    });

    // 2) make persist return a compatible error type, or map explicitly
    user_session.persist(&session).await?; // see below

    Ok(Redirect::to("/whoami"))
}
