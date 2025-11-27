use std::collections::BTreeMap;

use axum::{
    http::{
        header::{HOST, USER_AGENT},
        HeaderMap, StatusCode,
    },
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Serialize;

use crate::middleware::user_session::UserSession;
use crate::prelude::*;

/// All routes that live under `/whoami`.
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
    /// Selected request headers as a map `header_name → header_value`.
    request_headers: BTreeMap<String, String>,
    /// Public session info.
    session: SessionPayload,
}

/// Handler that returns a **JSON** payload instead of plain text.
async fn whoami_json(headers: HeaderMap, user_session: UserSession) -> impl IntoResponse {
    // --- Reflect only selected request headers (host, user-agent)
    let mut hdr_map: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in headers.iter() {
        // Only keep Host and User-Agent (case-insensitive via constants)
        if name != HOST && name != USER_AGENT {
            continue;
        }

        let val_str = value.to_str().unwrap_or("<non-utf8>");
        hdr_map.insert(name.as_str().to_string(), val_str.to_string());
    }

    // Build the public session payload from the internal UserSession.
    let session = SessionPayload {
        client_ip: match &user_session.forwarded_client_ip {
            Some(ip) => Some(ip.clone()),
            None => Some(user_session.peer_ip.clone()),
        },
        external_user_id: user_session.forwarded_user_id,
        visit_count: user_session.visit_count,
        // IMPORTANT: /whoami must never be exposed via permissive CORS,
        // because it returns a CSRF token bound to the session.
        csrf_token: user_session.csrf_token.clone(),
    };

    let payload = ResponsePayload {
        request_headers: hdr_map,
        session,
    };

    (StatusCode::OK, Json(payload))
}
