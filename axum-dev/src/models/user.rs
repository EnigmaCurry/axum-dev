use crate::models::ids::{IdentityProviderId, SignupMethodId, UserId};
use crate::models::user_status::UserStatus;
use serde::{Deserialize, Serialize};
use sqlx::types::chrono::NaiveDateTime;
use sqlx::Row;
use sqlx::{Error, FromRow, SqlitePool};

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
        INSERT INTO [user] (
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
    .bind(id.0.to_string())
    .bind(new_user.identity_provider_id)
    .bind(new_user.external_id)
    .bind(new_user.email)
    .bind(new_user.username)
    .fetch_one(pool)
    .await
}

/// Look up a user by its primary‑key.
///
/// Returns:
///   * `Ok(Some(user))` – the row exists.
///   * `Ok(None)`       – no row with that `id`.
///   * `Err(e)`         – any DB‑level error (connection failure, malformed query, …).
pub async fn select_user(pool: &SqlitePool, id: UserId) -> Result<Option<User>, Error> {
    sqlx::query_as::<_, User>(
        r#"
        SELECT
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
        FROM [user]
        WHERE id = ?1
        "#,
    )
    .bind(id.0.to_string())
    .fetch_optional(pool)
    .await
}

/// Look up a user by external OAuth ID.
///
/// Returns:
///   * `Ok(Some(user))` – row exists.
///   * `Ok(None)`       – no row with that external id.
///   * `Err(e)`         – DB error.
pub async fn select_user_by_external_id(
    pool: &SqlitePool,
    external_id: &str,
) -> Result<Option<User>, Error> {
    sqlx::query_as::<_, User>(
        r#"
        SELECT
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
        FROM [user]
        WHERE external_id = ?1
        "#,
    )
    .bind(external_id)
    .fetch_optional(pool)
    .await
}

/// Get the `identity_providers.id` for the Traefik ForwardAuth provider.
///
/// Adjust the `name` if you used a different code in your seed data.
async fn forwardauth_identity_provider_id(pool: &SqlitePool) -> Result<IdentityProviderId, Error> {
    // Assuming IdentityProviderId is a newtype over i64 / i32.
    let raw_id: i64 = sqlx::query(r#"SELECT id FROM identity_provider WHERE name = ?1"#)
        .bind("traefik-forwardauth")
        .map(|row: sqlx::sqlite::SqliteRow| row.get::<i64, _>("id"))
        .fetch_one(pool)
        .await?;

    Ok(IdentityProviderId(raw_id))
}

/// Get an existing user by e-mail, or create one if it doesn’t exist.
///
/// - Uses the `traefik-forwardauth` identity provider.
/// - Uses the email as `external_id` as well.
pub async fn get_or_create_by_external_id(
    pool: &SqlitePool,
    external_id: &str,
) -> Result<User, Error> {
    // Try to find an existing user first.
    if let Some(user) = select_user_by_external_id(pool, external_id).await? {
        return Ok(user);
    }

    // No existing user – create one.
    let identity_provider_id = forwardauth_identity_provider_id(pool).await?;

    // TODO: verify external_id is an email address, if not raise not implemented error.

    let new_user = CreateUser {
        identity_provider_id,
        external_id: external_id.to_string(),
        email: external_id.to_string(),
        username: None,
    };

    insert_user(pool, new_user).await
}
