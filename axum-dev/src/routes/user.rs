use crate::{
    errors::ErrorBody,
    middleware::require_role::{RequireRoles, require_roles_middleware},
    models::{
        role::SystemRole,
        user::{self},
    },
    response::{ApiJson, ApiResponse, json_error, json_ok},
};
use aide::{NoApi, axum::ApiRouter};
use api_doc_macros::{api_doc, get_with_docs};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    middleware,
};
use axum_oidc::{EmptyAdditionalClaims, OidcClaims};
use schemars::JsonSchema;
use serde::Serialize;

use crate::models::user::PublicUser;
use crate::prelude::*;

pub fn router(state: AppState) -> ApiRouter<AppState> {
    ApiRouter::<AppState>::new()
        .api_route("/{user_id}", get_with_docs!(get_user))
        .layer(middleware::from_fn_with_state(
            (state.clone(), RequireRoles(&[SystemRole::Admin])),
            require_roles_middleware,
        ))
}

/// The shape of the JSON we send back from User API.
#[derive(Debug, Serialize, JsonSchema)]
pub struct UserResponse {
    user: PublicUser,
}

#[api_doc(
    id = "user",
    tag = "user",
    ok = "Json<ApiResponse<UserResponse>>",
    err = "Json<ErrorBody>"
)]
pub async fn get_user(
    State(state): State<AppState>,
    Path(username): Path<String>,
    NoApi(_claims): NoApi<OidcClaims<EmptyAdditionalClaims>>,
) -> ApiJson<UserResponse> {
    let maybe_user = user::select_user_by_username(&state.db, &username)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("database query error: {e}"),
            )
        })
        .unwrap();

    match maybe_user {
        Some(user) => {
            let username = user.username.unwrap_or("".to_string());
            if username.is_empty() {
                json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error")
            } else {
                json_ok(UserResponse {
                    user: PublicUser { username },
                })
            }
        }
        None => json_error(StatusCode::NOT_FOUND, "user not found"),
    }
}
