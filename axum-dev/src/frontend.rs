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
    // For "/": no wildcard param → None → we treat it as "index.html".
    // For "/{*path}": Some("foo/bar") → we try that.
    let requested: String = maybe_path
        .map(|Path(p)| p)
        .unwrap_or_else(|| "".to_string());

    // Normalize: strip leading/trailing slashes
    let requested = requested.trim_matches('/').to_string();

    // -------- 1) Static assets (_app, robots.txt, etc.) --------
    // If the browser requested something like "foo/_app/immutable/..."
    // because the page was at /foo/boo and assets were relative,
    // snap it back to "_app/immutable/..." which is how it's stored.
    let asset_path: &str = if let Some(idx) = requested.find("_app/") {
        &requested[idx..] // drop "foo/" prefix → "_app/immutable/..."
    } else if !requested.is_empty() {
        &requested
    } else {
        // For root `/`, don't treat it as an asset — we'll handle it as HTML.
        ""
    };

    if !asset_path.is_empty() {
        if let Some(content) = Frontend::get(asset_path) {
            let mime = mime_guess::from_path(asset_path).first_or_octet_stream();
            return Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", mime.as_ref())
                .body(Body::from(content.data))
                .unwrap();
        }
    }

    // -------- 2) HTML routes (pre-rendered pages) --------
    // Map paths to potential HTML files:
    //
    //   /          → index.html
    //   /about     → about/index.html
    //   /docs/api  → docs/api/index.html
    //
    // These are the patterns Svelte adapter-static uses.
    let html_candidate = if requested.is_empty() {
        "index.html".to_string()
    } else if requested.ends_with(".html") {
        requested.clone()
    } else {
        format!("{requested}/index.html")
    };

    if let Some(page) = Frontend::get(&html_candidate) {
        let mime = mime_guess::from_path(&html_candidate).first_or_octet_stream();
        return Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", mime.as_ref())
            .body(Body::from(page.data))
            .unwrap();
    }

    // -------- 3) Fallback to Svelte's 404.html --------
    if let Some(not_found) = Frontend::get("404.html") {
        let mime = mime_guess::from_path("404.html").first_or_octet_stream();
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", mime.as_ref())
            .body(Body::from(not_found.data))
            .unwrap();
    }

    // If 404.html is somehow missing, just send a plain 404.
    StatusCode::NOT_FOUND.into_response()
}
