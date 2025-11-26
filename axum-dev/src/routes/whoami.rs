use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
};
use tower_sessions::Session;

const WHOAMI_VISIT_COUNT_KEY: &str = "whoami_visit_count";

use axum::{
    extract::{ConnectInfo, Extension, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, // <-- JSON extractor/serializer
    Router,
};

use serde::Serialize; // <-- for the response struct

use crate::middleware::{AuthenticatedUser, ClientIp};
use crate::prelude::*;

/// All routes that live under `/hello`.
pub fn router() -> Router<AppState> {
    Router::<AppState>::new().route("/", get(whoami_json))
}

/// The shape of the JSON we send back.
///
/// Fields are deliberately named the same as in the original plain‑text
/// version so you can recognise them easily.
#[derive(Debug, Serialize)]
struct ResponsePayload {
    /// Authenticated user e‑mail (or the placeholder string).
    user: String,
    /// The raw TCP peer address (always present).
    peer_ip: String,
    /// The *client* address that the trusted‑proxy middleware stored.
    /// `null` means the request didn’t come through a trusted proxy (or the
    /// proxy didn’t supply a usable header).
    client_ip: Option<String>,
    /// All request headers as a map `header_name → header_value`.
    headers: std::collections::BTreeMap<String, String>,
    whoami_visit_count: u64,
}

/// Handler that returns a **JSON** payload instead of plain text.
///

async fn whoami_json(
    user: Option<Extension<AuthenticatedUser>>,
    client_ip: Option<Extension<ClientIp>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    let email = match user {
        Some(Extension(AuthenticatedUser(email))) => email,
        None => "<unauthenticated>".to_string(),
    };

    let maybe_client_ip: Option<IpAddr> = client_ip.and_then(|Extension(ClientIp(inner))| inner);
    let client_ip_json: Option<String> = maybe_client_ip.map(|ip| ip.to_string());

    // --- Reflect headers - except redact the session cookie
    let mut hdr_map: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in headers.iter() {
        let val_str;
        if name == "cookie" {
            val_str = "<redacted>";
        } else {
            val_str = value.to_str().unwrap_or("<non-utf8>");
        }
        hdr_map.insert(name.as_str().to_string(), val_str.to_string());
    }

    // --- Visit counter (per session / per browser login) ---
    let current: u64 = session
        .get(WHOAMI_VISIT_COUNT_KEY)
        .await
        .unwrap_or(None)
        .unwrap_or(0);

    // --- update session counter
    let next = current.saturating_add(1);
    let _ = session.insert(WHOAMI_VISIT_COUNT_KEY, next).await;

    let payload = ResponsePayload {
        user: email,
        peer_ip: peer.ip().to_string(),
        client_ip: client_ip_json,
        headers: hdr_map,
        whoami_visit_count: next,
    };

    (StatusCode::OK, Json(payload))
}
