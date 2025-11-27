use std::{collections::BTreeMap, net::SocketAddr};

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
    pub client_ip: Option<String>,
    pub external_user_id: Option<ForwardAuthUser>,
}

/// The shape of the JSON we send back.
#[derive(Debug, Serialize)]
struct ResponsePayload {
    /// All request headers as a map `header_name → header_value`.
    headers: BTreeMap<String, String>,
    /// Public session info.
    session: SessionPayload,
}

/// Handler that returns a **JSON** payload instead of plain text.
async fn whoami_json(headers: HeaderMap, user_session: UserSession) -> impl IntoResponse {
    // --- Reflect request headers - except redact the session cookie:
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
        client_ip: match user_session.forwarded_client_ip {
            Some(ip) => Some(ip),
            None => Some(user_session.peer_ip),
        },
        external_user_id: user_session.forwarded_user_id,
        visit_count: user_session.visit_count,
        csrf_token: user_session.csrf_token.clone(),
    };

    let payload = ResponsePayload {
        headers: hdr_map,
        session,
    };

    (StatusCode::OK, Json(payload))
}
