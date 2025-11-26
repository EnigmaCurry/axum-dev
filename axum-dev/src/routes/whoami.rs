use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
};

use axum::{
    extract::{ConnectInfo, Extension},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Serialize;

use crate::middleware::user_session::UserSession;
use crate::prelude::*;

/// All routes that live under `/hello`.
pub fn router() -> Router<AppState> {
    Router::<AppState>::new().route("/", get(whoami_json))
}

/// The subset of session data we want to expose publicly.
#[derive(Debug, Serialize)]
struct SessionPayload {
    pub visit_count: u64,
    pub csrf_token: String,
}

/// The shape of the JSON we send back.
#[derive(Debug, Serialize)]
struct ResponsePayload {
    /// Authenticated external user id.
    external_user_id: Option<String>,
    /// The raw TCP peer address (always present).
    peer_ip: String,
    /// The *client* address that the trusted-proxy middleware stored.
    /// `null` means the request didn’t come through a trusted proxy (or the
    /// proxy didn’t supply a usable header).
    forwarded_client_ip: Option<String>,
    /// All request headers as a map `header_name → header_value`.
    headers: BTreeMap<String, String>,
    /// Public session info.
    session: SessionPayload,
}

/// Handler that returns a **JSON** payload instead of plain text.
async fn whoami_json(
    user: Option<Extension<ForwardAuthUser>>,
    forwarded_client_ip: Option<Extension<ForwardedClientIp>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user_session: UserSession,
) -> impl IntoResponse {
    let external_user_id = match user {
        Some(Extension(ForwardAuthUser(id))) => Some(id),
        None => None,
    };

    let maybe_forwarded_client_ip: Option<IpAddr> =
        forwarded_client_ip.and_then(|Extension(ForwardedClientIp(inner))| inner);
    let forwarded_client_ip_json: Option<String> =
        maybe_forwarded_client_ip.map(|ip| ip.to_string());

    // --- Reflect headers - except redact the session cookie
    let mut hdr_map: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in headers.iter() {
        let val_str = if name == "cookie" {
            "<redacted>"
        } else {
            value.to_str().unwrap_or("<non-utf8>")
        };
        hdr_map.insert(name.as_str().to_string(), val_str.to_string());
    }

    // Build the public session payload from the internal UserSession.
    let session = SessionPayload {
        visit_count: user_session.visit_count,
        csrf_token: user_session.csrf_token.clone(),
    };

    let payload = ResponsePayload {
        external_user_id,
        peer_ip: peer.ip().to_string(),
        forwarded_client_ip: forwarded_client_ip_json,
        headers: hdr_map,
        session,
    };

    (StatusCode::OK, Json(payload))
}
