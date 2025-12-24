use axum::error_handling::HandleErrorLayer;
use axum::http::Uri;
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderName, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_oidc::error::MiddlewareError;
use axum_oidc::{EmptyAdditionalClaims, OidcAuthLayer};
use log::warn;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use tower::ServiceBuilder;

use crate::errors::CliError;

use super::auth::AuthenticationMethod;

/// Config for OIDC
#[derive(Clone, Debug)]
pub struct OidcConfig {
    pub enabled: bool,
    pub net_host: Option<String>,
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

impl OidcConfig {
    #[allow(dead_code)]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            net_host: None,
            issuer: None,
            client_id: None,
            client_secret: None,
        }
    }

    pub fn validate(&self) -> Result<(), CliError> {
        if !self.enabled {
            return Ok(());
        }

        let issuer = self.issuer.as_deref().unwrap_or("").trim();
        let client_id = self.client_id.as_deref().unwrap_or("").trim();
        let net_host = self.net_host.as_deref().unwrap_or("").trim();

        if issuer.is_empty() {
            return Err(CliError::InvalidArgs("Missing oidc_issuer".to_string()));
        }
        if client_id.is_empty() {
            return Err(CliError::InvalidArgs("Missing oidc_client_id".to_string()));
        }
        if net_host.is_empty() {
            return Err(CliError::InvalidArgs("Missing net_host".to_string()));
        }

        // client_secret can be optional for public clients, so don't require it.
        Ok(())
    }
}

pub async fn build_oidc_auth_layer(
    cfg: &OidcConfig,
) -> Result<OidcAuthLayer<EmptyAdditionalClaims>, anyhow::Error> {
    let net_host = Uri::from_str(
        cfg.net_host
            .clone()
            .expect("oidc needs valid net_host")
            .as_str(),
    )
    .expect("oidc needs valid uri");
    let issuer = cfg.issuer.clone().expect("validated");
    let client_id = cfg.client_id.clone().expect("validated");
    let client_secret = cfg.client_secret.clone();

    let scopes = vec!["profile".to_string(), "email".to_string()];

    Ok(OidcAuthLayer::<EmptyAdditionalClaims>::discover_client(
        net_host,
        issuer,
        client_id,
        client_secret,
        scopes,
    )
    .await?)
}
