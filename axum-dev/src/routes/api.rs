use aide::axum::ApiRouter;

use super::{config, healthz, hello, user, whoami};
use crate::prelude::*;

pub fn router(state: AppState) -> ApiRouter<AppState> {
    ApiRouter::<AppState>::new()
        .nest("/config", config::router())
        .nest("/healthz", healthz::router())
        .nest("/hello", hello::router())
        .nest("/whoami", whoami::router())
        .nest("/user", user::router(state))
}
