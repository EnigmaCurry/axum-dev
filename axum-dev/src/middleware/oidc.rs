use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderName, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use log::warn;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

use crate::errors::CliError;

use super::auth::AuthenticationMethod;

/// Config for OIDC
#[derive(Clone, Debug)]
pub struct OidcConfig {
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

impl OidcConfig {
    #[allow(dead_code)]
    pub fn disabled() -> Self {
        Self {
            issuer: None,
            client_id: None,
            client_secret: None,
        }
    }

    pub fn validate(&self) -> Result<(), CliError> {
        Ok(())
    }
}
