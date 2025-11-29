use std::collections::HashMap;

use crate::prelude::*;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum::{routing::get, Router};
use indexmap::IndexMap;
use rmp_serde::from_slice;
use serde::Serialize;
use serde_json::Value as JsonValue;
use time::OffsetDateTime;
use tower_sessions::session::Record;

pub fn router() -> Router<AppState> {
    Router::<AppState>::new().route("/list_sessions", get(list_sessions))
}

const SESSIONS_TABLE: &str = "tower_sessions";

#[derive(Serialize)]
struct SessionRecord {
    data: HashMap<String, JsonValue>,
    /// Number of seconds until this session expires (clamped at 0).
    validity_seconds: i64,
}

impl SessionRecord {
    fn from_record(r: Record, now: OffsetDateTime) -> Option<Self> {
        let secs_left = (r.expiry_date - now).whole_seconds();

        if secs_left <= 0 {
            return None;
        }

        Some(SessionRecord {
            data: r.data,
            validity_seconds: secs_left,
        })
    }
}

pub async fn list_sessions(State(state): State<AppState>) -> impl IntoResponse {
    let query = format!(
        "select id, data from {table} order by expiry_date asc",
        table = SESSIONS_TABLE,
    );

    let rows: Vec<(String, Vec<u8>)> = match sqlx::query_as(&query).fetch_all(&state.db).await {
        Ok(rows) => rows,
        Err(e) => {
            eprintln!("failed to fetch sessions: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let now = OffsetDateTime::now_utc();
    let mut out: IndexMap<String, SessionRecord> = IndexMap::with_capacity(rows.len());

    for (id_str, blob) in rows {
        let record: Record = match from_slice(&blob) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("failed to decode session {id_str}: {e}");
                continue;
            }
        };

        if let Some(session) = SessionRecord::from_record(record, now) {
            out.insert(id_str, session);
        }
    }

    Json(out).into_response()
}
