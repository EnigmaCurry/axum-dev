use crate::models::user::insert_user;
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};

use crate::{
    models::user::{CreateUser, PublicUser},
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::<AppState>::new().route("/", post(create_user))
    //.route("/{user_id}", get(get_user))
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
