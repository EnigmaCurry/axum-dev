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

use super::auth::AuthenticationMethod;

/// Config for trusting an auth header from a forward-auth proxy (user/email).
#[derive(Clone, Debug)]
pub struct AuthConfig {
    pub method: AuthenticationMethod,
    pub trusted_header_name: HeaderName,
    pub trusted_proxy: IpAddr,
}

impl AuthConfig {
    /// Reasonable disabled default.
    #[allow(dead_code)]
    pub fn disabled() -> Self {
        Self {
            // UsernamePassword auth method disables trusted header auth.
            // It must be set to ForwardAuth to enable.
            method: AuthenticationMethod::UsernamePassword,
            trusted_header_name: HeaderName::from_static("x-forwarded-user"),
            trusted_proxy: IpAddr::from([127, 0, 0, 1]),
        }
    }
}

/// Authenticated user email extracted from a trusted header.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ForwardAuthUser {
    pub external_id: String,
}

/// Middleware that enforces trusted-header auth for user/email.
///
/// Rules:
/// - If disabled: 403 if header present.
/// - If enabled: only trusted proxy may send it (403 otherwise).
/// - Header must be present and non-empty.
/// - First comma-separated token treated as email.
pub async fn trusted_header_auth(
    State(cfg): State<AuthConfig>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    match cfg.method {
        AuthenticationMethod::ForwardAuth => {
            if req.headers().contains_key(&cfg.trusted_header_name) {
                warn!(
                    "trusted user header auth disabled, but header '{}' was present from peer {}",
                    cfg.trusted_header_name,
                    peer.ip()
                );
                return StatusCode::FORBIDDEN.into_response();
            }
            if peer.ip() != cfg.trusted_proxy {
                if req.headers().contains_key(&cfg.trusted_header_name) {
                    warn!(
                        "trusted user header auth: rejecting spoofed header '{}' from untrusted peer {} (expected {})",
                        cfg.trusted_header_name,
                        peer.ip(),
                        cfg.trusted_proxy
                    );
                    return StatusCode::FORBIDDEN.into_response();
                }
                let external_id: String = {
                    let raw = req
                        .headers()
                        .get(&cfg.trusted_header_name)
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty());

                    let first = match raw {
                        Some(v) => v.split(',').next().unwrap().trim(),
                        None => return StatusCode::UNAUTHORIZED.into_response(),
                    };

                    first.to_string()
                };
                req.extensions_mut().insert(ForwardAuthUser { external_id });
                return next.run(req).await;
            }

            next.run(req).await
        }
        AuthenticationMethod::UsernamePassword => {
            // skip header; rely on your login flow
            next.run(req).await
        }
    }
}
