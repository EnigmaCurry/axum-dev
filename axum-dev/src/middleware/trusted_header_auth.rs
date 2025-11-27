use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderName, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use log::warn;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

/// Config for trusting an auth header from a forward-auth proxy (user/email).
#[derive(Clone, Debug)]
pub struct TrustedHeaderAuthConfig {
    pub enabled: bool,
    pub header_name: HeaderName,
    pub trusted_proxy: IpAddr,
}

impl TrustedHeaderAuthConfig {
    /// Reasonable disabled default.
    #[allow(dead_code)]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            header_name: HeaderName::from_static("x-forwarded-user"),
            trusted_proxy: IpAddr::from([127, 0, 0, 1]),
        }
    }
}

/// Authenticated user email extracted from a trusted header.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ForwardAuthUser(pub String);

/// Middleware that enforces trusted-header auth for user/email.
///
/// Rules:
/// - If disabled: 403 if header present.
/// - If enabled: only trusted proxy may send it (403 otherwise).
/// - Header must be present and non-empty.
/// - First comma-separated token treated as email.
pub async fn trusted_header_auth(
    State(cfg): State<TrustedHeaderAuthConfig>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    if !cfg.enabled {
        if req.headers().contains_key(&cfg.header_name) {
            warn!(
                "trusted user header auth disabled, but header '{}' was present from peer {}",
                cfg.header_name,
                peer.ip()
            );
            return StatusCode::FORBIDDEN.into_response();
        }
        return next.run(req).await;
    }

    if peer.ip() != cfg.trusted_proxy {
        if req.headers().contains_key(&cfg.header_name) {
            warn!(
                "trusted user header auth: rejecting spoofed header '{}' from untrusted peer {} (expected {})",
                cfg.header_name,
                peer.ip(),
                cfg.trusted_proxy
            );
            return StatusCode::FORBIDDEN.into_response();
        }
        // If no spoofed header, allow request through.
        return next.run(req).await;
    }

    let email: String = {
        let raw = req
            .headers()
            .get(&cfg.header_name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty());

        let first = match raw {
            Some(v) => v.split(',').next().unwrap().trim(),
            None => return StatusCode::UNAUTHORIZED.into_response(),
        };

        first.to_string()
    };

    req.extensions_mut().insert(ForwardAuthUser(email));
    next.run(req).await
}
