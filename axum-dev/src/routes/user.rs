use crate::models::{
    ids::UserId,
    user::{self, insert_user},
};
use aide::axum::ApiRouter;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json,
};

use crate::models::user::{CreateUser, PublicUser};
use crate::prelude::*;

pub fn router() -> ApiRouter<AppState> {
    ApiRouter::<AppState>::new()
        .route("/", post(create_user))
        .route("/{user_id}", get(get_user))
}

pub async fn create_user(
    State(state): State<AppState>,
    Json(payload): Json<CreateUser>,
) -> Result<(StatusCode, Json<PublicUser>), (StatusCode, String)> {
    let user = insert_user(&state.db, payload).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("database insert error: {e}"),
        )
    })?;

    Ok((StatusCode::CREATED, Json(user.into())))
}

pub async fn get_user(
    State(state): State<AppState>,
    Path(user_id): Path<UserId>,
) -> Result<(StatusCode, Json<PublicUser>), (StatusCode, String)> {
    let maybe_user = user::select_user(&state.db, user_id.clone())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("database query error: {e}"),
            )
        })?;

    match maybe_user {
        Some(user) => Ok((StatusCode::OK, Json(user.into()))),
        None => Err((
            StatusCode::NOT_FOUND,
            format!("user with id {user_id:?} not found"),
        )),
    }
}
