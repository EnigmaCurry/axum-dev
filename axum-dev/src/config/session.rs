use clap::Args;
use clap_serde_derive::ClapSerde;

#[derive(ClapSerde, Args, Debug, Clone)]
pub struct SessionConfig {
    /// Whether to set the Secure flag on session cookies.
    /// (true/false or set SESSION_SECURE=true/false).
    #[arg(
        long = "session-secure",
        env = "SESSION_SECURE",
        value_name = "BOOL",
        help_heading = "Session"
    )]
    #[default(true)]
    pub session_secure: bool,

    /// Session cleanup interval in seconds.
    /// (default 60, or set SESSION_CHECK_SECONDS).
    #[arg(
        long = "session-check-seconds",
        env = "SESSION_CHECK_SECONDS",
        value_name = "SECONDS",
        help_heading = "Session"
    )]
    #[default(60)]
    pub session_check_seconds: u64,

    /// Session inactivity timeout in seconds.
    /// (default 604800 = 7 days, or set SESSION_EXPIRY_SECONDS).
    #[arg(
        long = "session-expiry-seconds",
        env = "SESSION_EXPIRY_SECONDS",
        value_name = "SECONDS",
        help_heading = "Session"
    )]
    #[default(60480)]
    pub session_expiry_seconds: u64,
}
