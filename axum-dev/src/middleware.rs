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
pub struct ClientIp(#[allow(dead_code)] pub Option<IpAddr>);

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

/// Insert the `ClientIp` extension **exactly once** per request.
/// When the feature is disabled we always insert `ClientIp(None)`.
pub async fn trusted_forwarded_for(
    State(cfg): State<TrustedForwardedForConfig>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    // ------------------------------------------------------------------------
    // 1️⃣  Disabled mode – *never* expose a client IP.
    // ------------------------------------------------------------------------
    if !cfg.enabled {
        // If a caller tries to cheat by sending the header, reject outright.
        if req.headers().contains_key(&cfg.header_name) {
            tracing::warn!(
                "trusted forwarded‑for disabled, but header '{}' was present from peer {}",
                cfg.header_name,
                peer.ip()
            );
            return StatusCode::FORBIDDEN.into_response();
        }

        // Explicitly hide the peer address.
        req.extensions_mut().insert(ClientIp(None));
        return next.run(req).await;
    }

    // ------------------------------------------------------------------------
    // 2️⃣  Enabled mode – sanity‑check the sender.
    // ------------------------------------------------------------------------
    // Header sent by *any* untrusted source → reject.
    if peer.ip() != cfg.trusted_proxy && req.headers().contains_key(&cfg.header_name) {
        tracing::warn!(
            "trusted forwarded‑for: rejecting spoofed header '{}' from untrusted peer {} (expected {})",
            cfg.header_name,
            peer.ip(),
            cfg.trusted_proxy
        );
        return StatusCode::FORBIDDEN.into_response();
    }

    // ------------------------------------------------------------------------
    // 3️⃣  Trusted proxy – try to parse the header (if any).
    // ------------------------------------------------------------------------
    let client_ip: Option<IpAddr> = {
        // Grab the raw header value, if present.
        let raw = req
            .headers()
            .get(&cfg.header_name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty());

        // Extract the *first* comma‑separated entry and attempt to turn it into an IpAddr.
        raw.and_then(|value| {
            let first = value.split(',').next().unwrap().trim();
            IpAddr::from_str(first).ok()
        })
    };

    // --------------------------------------------------------------
    // 4️⃣  Store the result in the request extensions.
    // --------------------------------------------------------------
    match client_ip {
        Some(ip) => {
            // Valid header → we know the original client IP.
            req.extensions_mut().insert(ClientIp(Some(ip)));
        }
        None => {
            // Header absent → we explicitly *hide* the IP.
            // Header present but unparsable → 400 Bad Request.
            if req.headers().contains_key(&cfg.header_name) {
                tracing::debug!(
                    "trusted forwarded‑for: header '{}' from trusted proxy {} could not be parsed",
                    cfg.header_name,
                    peer.ip()
                );
                return StatusCode::BAD_REQUEST.into_response();
            }
            req.extensions_mut().insert(ClientIp(None));
        }
    }

    // --------------------------------------------------------------
    // 5️⃣  Continue down the stack.
    // --------------------------------------------------------------
    next.run(req).await
}
