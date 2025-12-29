use crate::models::ids::RoleId;
use sqlx::FromRow;
use strum_macros::AsRefStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum SystemRole {
    Admin,
    Foo,
}

#[derive(Debug, Clone, FromRow)]
pub struct Role {
    pub id: RoleId,
    pub name: String, // 'user', 'admin', 'superadmin', 'support', ...
    pub description: String,
}
