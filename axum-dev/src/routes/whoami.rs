use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, Extension},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, // <-- JSON extractor/serializer
    Router,
};

use serde::Serialize; // <-- for the response struct

use crate::{
    middleware::{AuthenticatedUser, ClientIp},
    AppState,
};

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
    headers: std::collections::HashMap<String, String>,
}

/// Handler that returns a **JSON** payload instead of plain text.
///
/// The semantics are the same as before:
/// * `user` comes from the optional `AuthenticatedUser` extension.
/// * `client_ip` is the `Option<IpAddr>` that the middleware stored:
///   * `Some(ip)` → request really passed through the trusted proxy.
///   * `None`      → request didn’t (or the header was missing/invalid).
/// * `peer_ip` is always the raw TCP socket address of the connection.
/// * All request headers are echoed back as a map.
async fn whoami_json(
    user: Option<Extension<AuthenticatedUser>>,
    client_ip: Option<Extension<ClientIp>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // -----------------------------------------------------------------
    // 1️⃣ Resolve the authenticated user (or a placeholder)
    // -----------------------------------------------------------------
    let email = match user {
        Some(Extension(AuthenticatedUser(email))) => email,
        None => "<unauthenticated>".to_string(),
    };

    // -----------------------------------------------------------------
    // 2️⃣ Pull the inner Option<IpAddr> that the middleware stored.
    // -----------------------------------------------------------------
    // `and_then` unwraps the outer `Option<Extension<…>>` *and* the inner
    // `ClientIp(Option<IpAddr>)` in one go, giving us exactly what the
    // middleware decided.
    let maybe_client_ip: Option<IpAddr> = client_ip.and_then(|Extension(ClientIp(inner))| inner);

    // Turn the Option<IpAddr> into a JSON‑friendly `Option<String>`.
    // `None` stays `null` in the JSON output.
    let client_ip_json: Option<String> = maybe_client_ip.map(|ip| ip.to_string());

    // -----------------------------------------------------------------
    // 3️⃣  Turn the request headers into a HashMap<String,String>
    // -----------------------------------------------------------------
    let mut hdr_map = std::collections::HashMap::new();
    for (name, value) in headers.iter() {
        // Header values are not guaranteed to be valid UTF‑8,
        // so we fall back to a readable placeholder.
        let val_str = value.to_str().unwrap_or("<non‑utf8>");
        hdr_map.insert(name.as_str().to_string(), val_str.to_string());
    }

    // -----------------------------------------------------------------
    // 4️⃣  Assemble the response struct
    // -----------------------------------------------------------------
    let payload = ResponsePayload {
        user: email,
        peer_ip: peer.ip().to_string(),
        client_ip: client_ip_json,
        headers: hdr_map,
    };

    // Axum will automatically set `Content‑Type: application/json`.
    (StatusCode::OK, Json(payload))
}
