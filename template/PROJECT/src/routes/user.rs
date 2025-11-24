use crate::models::user::User;
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use chrono::Utc;
use uuid::Uuid;

use crate::{
    errors::internal_error,
    models::{
        ids::UserId,
        user::{CreateUser, PublicUser},
    },
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::<AppState>::new().route("/", post(create_user))
    //.route("/{user_id}", get(get_user))
}

async fn create_user(
    State(state): State<AppState>,
    Json(payload): Json<CreateUser>,
) -> Result<(StatusCode, Json<PublicUser>), (StatusCode, String)> {
    let id = UserId(Uuid::new_v4());
    let now = Utc::now();
    let created_at = now.timestamp();

    let user = sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (id, email, display_name, created_at)
        VALUES (?, ?, ?, ?)
        RETURNING
          id             as "id: UserId",
          email,
          display_name,
          created_at
        "#,
        id,
        payload.email,
        payload.display_name,
        created_at
    )
    .fetch_one(&state.db)
    .await
    .map_err(internal_error)?;

    Ok((StatusCode::CREATED, Json(user.into())))
}
