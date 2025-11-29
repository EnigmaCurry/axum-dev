use axum::{
    //response::IntoResponse, routing::get,
    Router,
};

use crate::{
    //    views::{HtmlTemplate, IndexTemplate},
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new() //.route("/", get(index))
}

// async fn index() -> impl IntoResponse {
//     HtmlTemplate(IndexTemplate {
//         title: "Home".to_string(),
//     })
// }
