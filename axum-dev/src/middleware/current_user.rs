// src/middleware/current_user.rs

use axum::{extract::FromRequestParts, http::request::Parts};
use tower_sessions::Session;

use crate::models::ids::UserId;
use crate::{errors::AppError, AppState};

#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub user_id: UserId,
    pub roles: Vec<String>, // e.g. "admin", "user", "superadmin"
}

impl CurrentUser {
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    pub fn has_any_role(&self, allowed: &[&str]) -> bool {
        allowed.iter().any(|r| self.has_role(r))
    }

    pub fn require_any_role(&self, allowed: &[&str]) -> Result<(), AppError> {
        if self.has_any_role(allowed) {
            Ok(())
        } else {
            Err(AppError::forbidden("insufficient role"))
        }
    }
}

// Axum 0.8: async fn directly, no async_trait
impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // 1) load session
        let session = Session::from_request_parts(parts, state)
            .await
            .map_err(|e| AppError::internal(&format!("failed to load session: {e:?}")))?;

        // 2) user_id from session
        let user_id: Option<UserId> = session
            .get("user_id")
            .await
            .map_err(|e| AppError::internal(&format!("failed to read session: {e}")))?;

        let Some(user_id) = user_id else {
            return Err(AppError::unauthorized("not logged in"));
        };

        // 3) roles from DB
        let roles: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT r.name
            FROM user_role ur
            JOIN [role] r ON r.id = ur.role_id
            WHERE ur.user_id = ?1
            "#,
        )
        .bind(&user_id)
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::internal(&format!("failed to load roles: {e}")))?;

        Ok(CurrentUser { user_id, roles })
    }
}
