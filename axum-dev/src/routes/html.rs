use axum::{response::IntoResponse, routing::get, Router};

use crate::{
    prelude::UserSession,
    views::{HtmlTemplate, IndexTemplate, LoginTemplate},
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/login", get(show_login))
}

// GET / -> whatever you already had
async fn index() -> impl IntoResponse {
    HtmlTemplate(IndexTemplate {
        title: "Home".to_string(),
    })
}

// GET /login -> show either login or logout state
async fn show_login(user_session: UserSession) -> impl IntoResponse {
    let (logged_in, user_name) = if let Some(ext_id) = &user_session.external_user_id {
        (true, ext_id.clone())
    } else {
        (false, String::new())
    };

    HtmlTemplate(LoginTemplate {
        title: "Login".to_string(),
        logged_in,
        user_name,
        csrf_token: user_session.csrf_token.clone(),
    })
}
