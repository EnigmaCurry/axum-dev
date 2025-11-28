use crate::views::{HtmlTemplate, IndexTemplate, LoginTemplate};
use crate::AppState;
use axum::{routing::get, Router};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/login", get(login))
}

async fn index() -> HtmlTemplate<IndexTemplate> {
    HtmlTemplate(IndexTemplate {
        title: "Home".to_string(),
    })
}

async fn login() -> HtmlTemplate<LoginTemplate> {
    HtmlTemplate(LoginTemplate {
        title: "Login".to_string(),
    })
}
