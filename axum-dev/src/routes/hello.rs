use axum::{extract::Path, routing::get, Json, Router};
use serde::Serialize;

use crate::AppState;

#[derive(Serialize)]
struct Greeting {
    message: String,
}

pub fn router() -> Router<AppState> {
    // this router is responsible for everything under `/hello`
    Router::<AppState>::new()
        .route("/{name}", get(hello))
        .route("/", get(hello_default))
}

async fn hello(Path(name): Path<String>) -> Json<Greeting> {
    let greeting = Greeting {
        message: format!("Hello, {name}"),
    };
    Json(greeting)
}

async fn hello_default() -> &'static str {
    "Hello!"
}
