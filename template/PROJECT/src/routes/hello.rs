use axum::{extract::Path, routing::get, Router};

use crate::AppState;

pub fn router() -> Router<AppState> {
    // this router is responsible for everything under `/hello`
    Router::<AppState>::new()
        .route("/{name}", get(hello))
        .route("/", get(hello_default))
}

async fn hello(Path(name): Path<String>) -> String {
    format!("Hello, {name}!")
}

async fn hello_default() -> &'static str {
    "Hello!"
}
