use std::collections::BTreeMap;

use axum::{
    extract::{OriginalUri, Request},
    http::{
        header::{HOST, USER_AGENT}, StatusCode,
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
    pub external_user_id: Option<String>,
    pub client_ip: Option<String>,
    pub csrf_token: String,
    pub visit_count: u64,
}

/// The shape of the JSON we send back.
#[derive(Debug, Serialize)]
struct ResponsePayload {
    request: BTreeMap<String, String>,
    session: SessionPayload,
}

async fn whoami_json(
    user_session: UserSession,
    original_uri: OriginalUri,
    req: Request,
) -> impl IntoResponse {
    let mut req_map: BTreeMap<String, String> = BTreeMap::new();

    req_map.insert("path".to_string(), original_uri.0.path().to_string());
    req_map.insert("method".to_string(), req.method().as_str().to_string());

    // Reflect only a subset of all request headers:
    let headers = req.headers();
    for (name, value) in headers.iter() {
        if name != HOST && name != USER_AGENT {
            continue;
        }
        let val_str = value.to_str().unwrap_or("<non-utf8>");
        req_map.insert(name.as_str().to_string(), val_str.to_string());
    }

    let session = SessionPayload {
        client_ip: match &user_session.client_ip {
            Some(ip) => Some(ip.clone()),
            None => Some(user_session.peer_ip.clone()),
        },
        external_user_id: user_session.external_user_id,
        visit_count: user_session.visit_count,
        csrf_token: user_session.csrf_token.clone(),
    };

    let payload = ResponsePayload {
        request: req_map,
        session,
    };

    (StatusCode::OK, Json(payload))
}
