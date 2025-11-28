use axum::{
    extract::Request,
    http::{Method, StatusCode},
    middleware::Next,
    response::Response,
};
use tower_sessions::Session;

// Methods we consider "unsafe"
fn is_state_changing(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

// Simple CSRF middleware using X-CSRF-Token header
pub async fn csrf_middleware(
    session: Session,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if !is_state_changing(req.method()) {
        return Ok(next.run(req).await);
    }

    let expected = session
        .get::<String>("csrf_token")
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // You might instead pull from UserSession if that’s your canonical store
    // let expected = user_session.csrf_token.clone();

    let Some(expected) = expected else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let provided = req
        .headers()
        .get("X-CSRF-Token")
        .and_then(|v| v.to_str().ok());

    if provided != Some(expected.as_str()) {
        tracing::warn!(
            "CSRF header mismatch: provided={:?}, expected={}",
            provided,
            expected
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(req).await)
}
