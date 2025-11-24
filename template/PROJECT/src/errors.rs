use axum::http::StatusCode;

pub fn internal_error<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
#[allow(dead_code)]
pub fn not_found_error<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, e.to_string())
}
