use super::ids::UserId;
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;

/// Internal User object
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: UserId,
    pub email: String,
    pub display_name: String,
    pub created_at: i64,
}

/// Public User registration request data
#[derive(Debug, Deserialize)]
pub struct CreateUser {
    pub email: String,
    pub display_name: String,
}

/// Public User response object
#[derive(Debug, Serialize)]
pub struct PublicUser {
    pub id: UserId,
    pub email: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
}

impl From<User> for PublicUser {
    fn from(u: User) -> Self {
        let created_at = Utc
            .timestamp_opt(u.created_at, 0)
            .single()
            .unwrap_or_else(|| Utc.timestamp_opt(0, 0).single().unwrap());

        Self {
            id: u.id,
            email: u.email,
            display_name: u.display_name,
            created_at,
        }
    }
}
