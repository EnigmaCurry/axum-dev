use clap::ValueEnum;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum AuthenticationMethod {
    /// Use a forward-auth proxy (Traefik, etc.) via trusted header.
    #[value(name = "forward_auth")]
    ForwardAuth,

    /// Use traditional username/password login.
    #[value(name = "username_password")]
    UsernamePassword,
}
