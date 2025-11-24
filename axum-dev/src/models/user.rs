use crate::models::ids::{IdentityProviderId, SignupMethodId, UserId};
use crate::models::user_status::UserStatus;
use serde::{Deserialize, Serialize};
use sqlx::types::chrono::NaiveDateTime;
use sqlx::{FromRow, SqlitePool};

#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub id: UserId,
    pub identity_provider_id: IdentityProviderId,
    pub external_id: String,
    pub email: String,
    pub username: Option<String>,

    pub is_registered: bool,
    pub registered_at: Option<NaiveDateTime>,
    pub signup_method_id: Option<SignupMethodId>,

    pub status: UserStatus,

    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Deserialize)]
pub struct CreateUser {
    // shape of whatever your route needs; example:
    pub identity_provider_id: IdentityProviderId,
    pub external_id: String,
    pub email: String,
    pub username: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PublicUser {
    pub id: UserId,
    pub email: String,
    pub username: Option<String>,
}

impl From<User> for PublicUser {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            email: u.email,
            username: u.username,
        }
    }
}

/// Example insert helper – adjust to your actual route needs.
pub async fn insert_user(pool: &SqlitePool, new_user: CreateUser) -> sqlx::Result<User> {
    let id = UserId::new();

    sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (
            id,
            identity_provider_id,
            external_id,
            email,
            username,
            is_registered,
            status
        )
        VALUES (?1, ?2, ?3, ?4, ?5, 0, 'active')
        RETURNING
            id,
            identity_provider_id,
            external_id,
            email,
            username,
            is_registered,
            registered_at,
            signup_method_id,
            status,
            created_at,
            updated_at
        "#,
    )
    .bind(id)
    .bind(new_user.identity_provider_id)
    .bind(new_user.external_id)
    .bind(new_user.email)
    .bind(new_user.username)
    .fetch_one(pool)
    .await
}
