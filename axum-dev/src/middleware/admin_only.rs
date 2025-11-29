// src/middleware/admin_only.rs

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::IntoResponse,
};
use tower_sessions::Session;
use tracing::warn;

use crate::middleware::user_session::UserSession;
use crate::models::ids::UserId;
use crate::{errors::AppError, AppState}; // adjust path if needed

pub async fn admin_only_middleware(
    State(state): State<AppState>,
    session: Session,
    user_session: UserSession,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, AppError> {
    let path = request.uri().path().to_string();

    // 1) Logged in? -> authoritative check
    if !user_session.is_logged_in {
        warn!(
            %path,
            external_user_id = user_session
                .external_user_id
                .as_deref()
                .unwrap_or("<none>"),
            client_ip = user_session
                .client_ip
                .as_deref()
                .unwrap_or("<unknown>"),
            "admin access denied: not logged in",
        );
        return Err(AppError::unauthorized("Not logged in"));
    }

    // 2) Look up local user_id from the underlying tower Session (for roles)
    let user_id: Option<UserId> = session
        .get("user_id")
        .await
        .map_err(|e| AppError::internal(&format!("failed to read user_id from session: {e}")))?;

    let Some(user_id) = user_id else {
        warn!(
            %path,
            external_user_id = user_session
                .external_user_id
                .as_deref()
                .unwrap_or("<none>"),
            client_ip = user_session
                .client_ip
                .as_deref()
                .unwrap_or("<unknown>"),
            "admin access denied: logged in but no local user_id in session",
        );
        return Err(AppError::forbidden("Admin role required"));
    };

    // 3) Has admin/superadmin role?
    let has_admin = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT 1
        FROM user_role ur
        JOIN [role] r ON r.id = ur.role_id
        WHERE ur.user_id = ?1
          AND r.name IN ('admin', 'superadmin')
        LIMIT 1
        "#,
    )
    .bind(&user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::internal(&format!("failed to check roles: {e}")))?
    .is_some();

    if !has_admin {
        warn!(
            %path,
            ?user_id,
            external_user_id = user_session
                .external_user_id
                .as_deref()
                .unwrap_or("<none>"),
            client_ip = user_session
                .client_ip
                .as_deref()
                .unwrap_or("<unknown>"),
            "admin access denied: user lacks admin/superadmin role",
        );
        return Err(AppError::forbidden("admin role required"));
    }

    // 4) All good – continue to /admin handlers
    Ok(next.run(request).await)
}
