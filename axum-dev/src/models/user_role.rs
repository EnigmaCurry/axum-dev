use crate::models::ids::{RoleId, UserId};
use chrono::NaiveDateTime;
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct UserRole {
    pub user_id: UserId,
    pub role_id: RoleId,
    pub assigned_at: NaiveDateTime,
    pub assigned_by: Option<UserId>,
}
