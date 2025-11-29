use crate::prelude::*;
use axum::{routing::get, Router};

use super::{hello, user, whoami};

pub fn router() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/healthz", get(healthz))
        .nest("/hello", hello::router())
        .nest("/whoami", whoami::router())
        .nest("/user", user::router())
}

async fn healthz() -> &'static str {
    "healthy"
}
