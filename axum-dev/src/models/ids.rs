// src/models/ids.rs
use serde::{Deserialize, Serialize};
use sqlx::Type;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Type, Serialize, Deserialize)]
#[sqlx(transparent)]
pub struct UserId(pub String);

impl UserId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    pub fn as_uuid(&self) -> uuid::Uuid {
        uuid::Uuid::parse_str(&self.0).expect("invalid UUID in UserId")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Type, Serialize, Deserialize)]
#[sqlx(transparent)]
pub struct IdentityProviderId(pub i64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Type, Serialize, Deserialize)]
#[sqlx(transparent)]
pub struct SignupMethodId(pub i64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Type, Serialize, Deserialize)]
#[sqlx(transparent)]
pub struct RoleId(pub i64);
