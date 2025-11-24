use crate::models::ids::RoleId;
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct Role {
    pub id: RoleId,
    pub name: String, // 'user', 'admin', 'superadmin', 'support', ...
    pub description: String,
}
