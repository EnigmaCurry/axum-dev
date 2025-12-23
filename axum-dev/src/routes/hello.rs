use aide::axum::ApiRouter;
use api_doc_macros::{api_doc, post_with_docs};
use axum::Json;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    errors::ErrorBody,
    response::{json_ok, ApiJson, ApiResponse},
    AppState,
};

pub fn router() -> ApiRouter<AppState> {
    ApiRouter::<AppState>::new().api_route("/", post_with_docs!(hello))
}

#[derive(Deserialize, JsonSchema)]
struct HelloRequest {
    /// Name to greet.
    name: Option<String>,
}

#[derive(Serialize, JsonSchema)]
struct Greeting {
    message: String,
}

#[api_doc(
    id = "hello",
    tag = "example",
    ok = "Json<ApiResponse<Greeting>>",
    err = "Json<ErrorBody>"
)]
/// Say hello
///
/// Returns a greeting message, optionally personalized with the requested name.
async fn hello(Json(body): Json<HelloRequest>) -> ApiJson<Greeting> {
    let name = body.name.unwrap_or_else(|| "world".to_string());
    json_ok(Greeting {
        message: format!("Hello, {name}!"),
    })
}
