use axum::{
    extract::{Request, State},
    middleware::Next,
    response::IntoResponse,
};
use tracing::warn;

use crate::middleware::user_session::UserSession;
use crate::{errors::AppError, AppState}; // adjust path if needed

pub async fn admin_only_middleware(
    State(state): State<AppState>,
    user_session: UserSession,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, AppError> {
    let path = request.uri().path().to_string();

    // 1) Logged in? -> authoritative check
    if !user_session.is_logged_in {
        warn!(
            %path,
            username = user_session
                .username,
            client_ip = user_session
                .client_ip
                .as_deref()
                .unwrap_or("<unknown>"),
            "admin access denied: not logged in",
        );
        return Err(AppError::unauthorized("Not logged in"));
    }
    let user_id = user_session.user_id;

    // 2) Has admin/superadmin role?
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
            username = user_session
                .username,
            client_ip = user_session
                .client_ip
                .as_deref()
                .unwrap_or("<unknown>"),
            "admin access denied: user lacks admin/superadmin role",
        );
        return Err(AppError::forbidden("admin role required"));
    }

    // 3) All good – continue to /admin handlers
    Ok(next.run(request).await)
}
