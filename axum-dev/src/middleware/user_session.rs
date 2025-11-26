use axum::extract::{FromRequestParts, Request};
use axum::http::{request::Parts, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use uuid::Uuid;

const SESSION_KEY: &str = "user_session_v1";

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
/// User session object contains a few global session data points per guest.
pub struct UserSession {
    pub user_id: Option<String>,
    pub visit_count: u64,
    pub csrf_token: String,
}

impl UserSession {
    async fn persist(&self, session: &Session) -> Result<(), StatusCode> {
        session
            .insert(SESSION_KEY, self.clone())
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }
}

fn generate_csrf_token() -> String {
    Uuid::new_v4().to_string()
}

/// Middleware that runs on every request and keeps the user session up to date.
///
/// Responsibilities:
/// - Ensure a CSRF token is present.
/// - Increment visit_count.
/// - (For now) keep user_id as None even if the user is "authenticated" – mocked.
pub async fn user_session_middleware(
    session: Session,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Load existing typed session or start from default.
    let mut data: UserSession = session
        .get(SESSION_KEY)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .unwrap_or_default();

    // Ensure CSRF token.
    if data.csrf_token.is_empty() {
        data.csrf_token = generate_csrf_token();
    }

    // Bump visit count (saturating to avoid overflow).
    data.visit_count = data.visit_count.saturating_add(1);

    // Mock auth check: even if you had auth info, we *intentionally*
    // keep user_id as None for now.
    if data.user_id.is_none() {
        // In the future you might inspect some AuthenticatedUser extension here.
        // For now: do nothing.
    }

    // Persist back to the underlying tower_sessions::Session.
    data.persist(&session).await?;

    // Also stash the typed session in request extensions so handlers can
    // extract it cheaply without hitting storage again.
    req.extensions_mut().insert(data);

    // Continue down the stack.
    Ok(next.run(req).await)
}

// --- Extractor for handlers --------------------------------------------------

impl<S> FromRequestParts<S> for UserSession
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Prefer the value computed by the middleware, if present.
        if let Some(existing) = parts.extensions.get::<UserSession>() {
            return Ok(existing.clone());
        }

        // Fallback: load directly from the session (e.g. if a route isn’t
        // behind the middleware for some reason).
        let session = Session::from_request_parts(parts, state)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "session error"))?;

        let data: UserSession = session
            .get(SESSION_KEY)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "session load error"))?
            .unwrap_or_default();

        Ok(data)
    }
}
