use axum::{
    body::Body,
    extract::Path,
    http::{Response, StatusCode},
    response::IntoResponse,
};
use mime_guess;
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
// Path is relative to axum-dev/Cargo.toml
#[folder = "../frontend/build"]
struct Frontend;

pub async fn spa_handler(maybe_path: Option<Path<String>>) -> impl IntoResponse {
    // For "/": no wildcard param → None → use "index.html"
    // For "/{*path}": Some("foo/bar") → try that first.
    let requested = maybe_path
        .map(|Path(p)| p)
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "index.html".to_string());

    // Try the requested file; if it doesn't exist, fall back to index.html.
    let (content, mime_path) = if let Some(c) = Frontend::get(&requested) {
        (c, requested.as_str())
    } else if let Some(c) = Frontend::get("index.html") {
        (c, "index.html")
    } else {
        // If we ever hit this, the embed is broken
        return StatusCode::NOT_FOUND.into_response();
    };

    let mime = mime_guess::from_path(mime_path).first_or_octet_stream();

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", mime.as_ref())
        .body(Body::from(content.data))
        .unwrap()
}
