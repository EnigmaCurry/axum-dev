use askama::Template;
pub mod index;
pub mod login;

use axum::{
    http::{Response, StatusCode},
    response::{Html, IntoResponse},
};
pub use index::IndexTemplate;
pub use login::LoginTemplate;

// Generic wrapper that turns any Askama template into an Axum response.
pub struct HtmlTemplate<T: Template>(pub T);

impl<T: Template> IntoResponse for HtmlTemplate<T> {
    fn into_response(self) -> Response<axum::body::Body> {
        match self.0.render() {
            Ok(body) => Html(body).into_response(),
            Err(err) => {
                tracing::error!("Template render error: {err}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}
