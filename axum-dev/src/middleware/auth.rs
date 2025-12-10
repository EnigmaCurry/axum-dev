use clap::ValueEnum;
use serde::Deserialize;

#[derive(Clone, Copy, Debug, ValueEnum, Deserialize, Default)]
pub enum AuthenticationMethod {
    /// Use traditional username/password login.
    #[value(name = "username_password")]
    #[default]
    UsernamePassword,

    /// Use a forward-auth proxy (Traefik, etc.) via trusted header.
    #[value(name = "forward_auth")]
    ForwardAuth,
}
