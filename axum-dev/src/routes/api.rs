use aide::axum::ApiRouter;

use super::{healthz, hello, user, whoami};
use crate::prelude::*;

pub fn router() -> ApiRouter<AppState> {
    ApiRouter::<AppState>::new()
        .nest("/healthz", healthz::router())
        .nest("/hello", hello::router())
        .nest("/whoami", whoami::router())
        .nest("/user", user::router())
}
