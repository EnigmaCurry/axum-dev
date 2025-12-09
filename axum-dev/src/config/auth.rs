use crate::errors::CliError;
use crate::middleware::auth::AuthenticationMethod;
use clap::{self, Args};
use clap_serde_derive::ClapSerde;

#[derive(ClapSerde, Args, Debug, Clone)]
pub struct AuthConfig {
    /// Authentication method to use: forward_auth or username_password.
    #[arg(
        long = "auth-method",
        env = "AUTH_METHOD",
        value_name = "METHOD",
        default_value = "forward_auth",
        help_heading = "Authentication"
    )]
    pub authentication_method: AuthenticationMethod,

    /// Header to read the authenticated user email from.
    #[arg(
        long = "auth-trusted-header-name",
        env = "AUTH_TRUSTED_HEADER_NAME",
        value_name = "HEADER",
        default_value = "X-Forwarded-User",
        help_heading = "Authentication"
    )]
    pub trusted_header_name: String,

    /// Only trust the header when the TCP peer IP matches this proxy.
    #[arg(
        long = "auth-trusted-proxy",
        env = "AUTH_TRUSTED_PROXY",
        value_name = "IP",
        help_heading = "Authentication"
    )]
    pub trusted_proxy: Option<std::net::IpAddr>,

    /// Enable trusting X-Forwarded-For (or custom) from a trusted proxy.
    #[arg(
        long = "auth-trusted-forwarded-for",
        env = "AUTH_TRUSTED_FORWARDED_FOR",
        action = clap::ArgAction::SetTrue,
        help_heading = "Authentication"
    )]
    pub trusted_forwarded_for: bool,

    /// Header to read client IP from when trusted-forwarded-for is enabled.
    #[arg(
        long = "auth-trusted-forwarded-for-name",
        env = "AUTH_TRUSTED_FORWARDED_FOR_NAME",
        value_name = "HEADER",
        default_value = "X-Forwarded-For",
        help_heading = "Authentication"
    )]
    pub trusted_forwarded_for_name: String,
}

impl AuthConfig {
    pub fn validate(&self) -> Result<(), CliError> {
        if matches!(
            self.authentication_method,
            AuthenticationMethod::ForwardAuth
        ) {
            if self.trusted_proxy.is_none() {
                return Err(CliError::InvalidArgs(
                    "auth-trusted-proxy is required when auth-method=forward_auth".into(),
                ));
            }
        }

        // You might also enforce that if trusted_forwarded_for is true,
        // then trusted_proxy is Some(..) too, same pattern.

        Ok(())
    }
}
