use axum::extract::{FromRequestParts, Request};
use axum::http::{request::Parts, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use uuid::Uuid;

use crate::middleware::trusted_forwarded_for::ForwardedClientIp;
use crate::middleware::trusted_header_auth::ForwardAuthUser;
use crate::prelude::*;

const SESSION_KEY: &str = "user_session_v1";

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
/// User session object contains a few global session data points per guest.
pub struct UserSession {
    /// The raw TCP peer address as seen by our server.
    pub peer_ip: String,
    /// The authenticated user as reported by the trusted header (if any).
    pub forwarded_user_id: Option<ForwardAuthUser>,
    pub visit_count: u64,
    pub csrf_token: String,
    /// Trusted client IP from x-forwarded-for (if enabled/valid).
    pub forwarded_client_ip: Option<String>,
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
/// - Copy the trusted client IP (if available) into the session.
/// - Copy the forwarded user (if available) into the session.
/// - Record peer_ip as seen by our server.
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

    // Pull trusted IP info (if any) from extensions.
    if let Some(fwd) = req.extensions().get::<ForwardedClientIp>() {
        // Always record peer IP if we have it.
        data.peer_ip = fwd.peer_ip.to_string();
        // And client IP if present.
        data.forwarded_client_ip = fwd.client_ip.map(|ip| ip.to_string());
    }

    // Pull forwarded user (if any) from extensions.
    //
    // This will be:
    // - Some(ForwardAuthUser(...)) if `trusted_header_auth` is enabled and set a user
    // - None if it was disabled, the header was absent, or middleware not in stack
    //
    // We overwrite on every request so stale users don't linger in the session.
    data.forwarded_user_id = req.extensions().get::<ForwardAuthUser>().cloned();

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
