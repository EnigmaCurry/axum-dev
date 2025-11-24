use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderName, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use log::warn;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

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

/// Config for trusting a forwarded-for header from a proxy (client IP).
#[derive(Clone, Debug)]
pub struct TrustedForwardedForConfig {
    pub enabled: bool,
    pub header_name: HeaderName,
    pub trusted_proxy: IpAddr,
}

impl TrustedForwardedForConfig {
    /// Reasonable disabled default.
    #[allow(dead_code)]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            header_name: HeaderName::from_static("x-forwarded-for"),
            trusted_proxy: IpAddr::from([127, 0, 0, 1]),
        }
    }
}

/// Authenticated user email extracted from a trusted header.
#[derive(Clone, Debug)]
pub struct AuthenticatedUser(#[allow(dead_code)] pub String);

/// Client IP extracted from trusted forwarded-for header.
#[derive(Clone, Debug)]
pub struct ClientIp(#[allow(dead_code)] pub IpAddr);

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

    req.extensions_mut().insert(AuthenticatedUser(email));
    next.run(req).await
}

/// Middleware that enforces trusted forwarded-for header for client IP.
///
/// Rules:
/// - If disabled: 403 if header present.
/// - If enabled: only trusted proxy may send it (403 otherwise).
/// - If trusted proxy sends it, parse first IP and store as ClientIp.
pub async fn trusted_forwarded_for(
    State(cfg): State<TrustedForwardedForConfig>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    if !cfg.enabled {
        if req.headers().contains_key(&cfg.header_name) {
            warn!(
                "trusted forwarded-for disabled, but header '{}' was present from peer {}",
                cfg.header_name,
                peer.ip()
            );
            return StatusCode::FORBIDDEN.into_response();
        }
        return next.run(req).await;
    }

    // Enabled mode: if header is present from untrusted peer, reject.
    if peer.ip() != cfg.trusted_proxy {
        if req.headers().contains_key(&cfg.header_name) {
            warn!(
                "trusted forwarded-for: rejecting spoofed header '{}' from untrusted peer {} (expected {})",
                cfg.header_name,
                peer.ip(),
                cfg.trusted_proxy
            );
            return StatusCode::FORBIDDEN.into_response();
        }
        return next.run(req).await;
    }

    // Trusted proxy: if header present, parse it.
    let client_ip: Option<IpAddr> = {
        let raw = req
            .headers()
            .get(&cfg.header_name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty());

        raw.and_then(|v| {
            let first = v.split(',').next().unwrap().trim();
            IpAddr::from_str(first).ok()
        })
    };

    if let Some(ip) = client_ip {
        req.extensions_mut().insert(ClientIp(ip));
    } else if req.headers().contains_key(&cfg.header_name) {
        // Header existed but was unparsable.
        return StatusCode::BAD_REQUEST.into_response();
    }

    next.run(req).await
}
