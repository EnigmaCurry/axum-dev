use clap::{value_parser, Arg, Command};

pub fn app() -> Command {
    Command::new("${APP}")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            Arg::new("log")
                .long("log")
                .global(true)
                .num_args(1)
                .value_name("LEVEL")
                .value_parser(["trace", "debug", "info", "warn", "error"])
                .help("Sets the log level, overriding the RUST_LOG environment variable."),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .global(true)
                .help("Sets the log level to debug.")
                .action(clap::ArgAction::SetTrue),
        )
        .subcommand(
            Command::new("completions")
                .about("Generates shell completions script (tab completion)")
                .arg(
                    Arg::new("shell")
                        .help("The shell to generate completions for")
                        .required(false)
                        .value_parser(["bash", "zsh", "fish"]),
                ),
        )
        .subcommand(
            Command::new("serve")
                .about("Run the HTTP API server")
                .arg(
                    Arg::new("listen_ip")
                        .long("listen-ip")
                        .value_name("IP")
                        .env("LISTEN_IP")
                        .default_value("127.0.0.1")
                        .help("IP to bind (or set LISTEN_IP)"),
                )
                .arg(
                    Arg::new("listen_port")
                        .long("listen-port")
                        .value_name("PORT")
                        .env("LISTEN_PORT")
                        .default_value("3000")
                        .value_parser(value_parser!(u16))
                        .help("Port to bind (or set LISTEN_PORT)"),
                )
                .arg(
                    Arg::new("trusted_header_auth")
                        .long("trusted-header-auth")
                        .env("TRUSTED_HEADER_AUTH")
                        .action(clap::ArgAction::SetTrue)
                        .help("Enable trusting an auth header from a forward-auth proxy"),
                )
                .arg(
                    Arg::new("trusted_header_name")
                        .long("trusted-header-name")
                        .env("TRUSTED_HEADER_NAME")
                        .value_name("HEADER")
                        .default_value("X-Forwarded-User")
                        .help("Header to read the authenticated user email from"),
                )
                .arg(
                    Arg::new("trusted_proxy")
                        .long("trusted-proxy")
                        .env("TRUSTED_PROXY")
                        .value_name("IP")
                        .default_value("127.0.0.1")
                        .value_parser(value_parser!(std::net::IpAddr))
                        .help("Only trust the header when the TCP peer IP matches this proxy"),
                )
                .arg(
                    Arg::new("trusted_forwarded_for")
                        .long("trusted-forwarded-for")
                        .env("TRUSTED_FORWARDED_FOR")
                        .action(clap::ArgAction::SetTrue)
                        .help("Enable trusting X-Forwarded-For (or custom) from a trusted proxy"),
                )
                .arg(
                    Arg::new("trusted_forwarded_for_name")
                        .long("trusted_forwarded_for_name")
                        .env("TRUSTED_FORWARDED_FOR_NAME")
                        .value_name("HEADER")
                        .default_value("X-Forwarded-For")
                        .help(
                            "Header to read client IP from when trusted-forwarded-for is enabled",
                        ),
                ),
        )
}
