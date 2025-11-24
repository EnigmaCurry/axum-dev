// src/model/identity_provider.rs
use crate::models::ids::IdentityProviderId;
#[allow(unused_imports)]
use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct IdentityProvider {
    pub id: IdentityProviderId,
    pub name: String,
    pub display_name: String,
    pub is_default: bool,
}
