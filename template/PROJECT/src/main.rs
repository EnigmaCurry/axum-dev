use axum::http::HeaderName;
use clap_complete::shells::Shell;
use sqlx::SqlitePool;
use std::env;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};

mod cli;
mod errors;
mod middleware;
mod models;
mod prelude;
mod routes;
mod server;

use prelude::*;

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
}

fn main() {
    let code = run_cli(
        std::env::args_os(),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    );
    std::process::exit(code);
}

pub fn run_cli<I, S, W1, W2>(args: I, out: &mut W1, err: &mut W2) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
    W1: Write,
    W2: Write,
{
    let cmd = cli::app();
    let matches = match cmd.clone().try_get_matches_from(args) {
        Ok(m) => m,
        Err(e) => {
            let _ = write!(err, "{e}");
            return 2;
        }
    };

    dispatch(cmd, matches, out, err)
}

fn dispatch<W1, W2>(
    mut cmd: clap::Command,
    matches: clap::ArgMatches,
    out: &mut W1,
    err: &mut W2,
) -> i32
where
    W1: Write,
    W2: Write,
{
    init_logging(&matches);

    // Print help if no subcommand is given.
    if matches.subcommand_name().is_none() {
        let _ = cmd.write_help(out);
        let _ = writeln!(out);
        return 0;
    }

    match matches.subcommand() {
        Some(("completions", sub_matches)) => completions(sub_matches, out, err),
        Some(("serve", sub_matches)) => serve(sub_matches, out, err),
        _ => 1,
    }
}

fn init_logging(matches: &clap::ArgMatches) {
    use std::str::FromStr;

    let log_level = if matches.get_flag("verbose") {
        Some("debug".to_string())
    } else {
        matches.get_one::<String>("log").cloned()
    };

    let log_level = log_level.or_else(|| std::env::var("RUST_LOG").ok());
    let log_level = log_level.unwrap_or_else(|| "info".to_string());

    let mut builder = env_logger::Builder::new();
    builder
        .filter_level(log::LevelFilter::from_str(&log_level).unwrap_or(log::LevelFilter::Info))
        .format_timestamp_secs();

    // Avoid panicking in tests if a logger is already set.
    let _ = builder.try_init();

    debug!("logging initialized.");
}

fn completions<W1: Write, W2: Write>(
    sub_matches: &clap::ArgMatches,
    out: &mut W1,
    err: &mut W2,
) -> i32 {
    if let Some(shell) = sub_matches.get_one::<String>("shell") {
        match shell.as_str() {
            "bash" => generate_completion_script(Shell::Bash, out),
            "zsh" => generate_completion_script(Shell::Zsh, out),
            "fish" => generate_completion_script(Shell::Fish, out),
            shell => {
                let _ = writeln!(err, "Unsupported shell: {shell}");
                return 1;
            }
        }
        0
    } else {
        let bin = env!("CARGO_BIN_NAME");

        let _ = writeln!(err, "### Instructions to enable tab completion for {bin}\n");
        let _ = writeln!(err, "### Bash (put this in ~/.bashrc:)");
        let _ = writeln!(err, "  source <({bin} completions bash)\n");
        let _ = writeln!(err, "### To make an alias (eg. 'h'), add this too:");
        let _ = writeln!(err, "  alias h={bin}");
        let _ = writeln!(err, "  complete -F _{bin} -o bashdefault -o default h\n");
        let _ = writeln!(
            err,
            "### If you don't use Bash, you can also use Fish or Zsh:"
        );
        let _ = writeln!(err, "### Fish (put this in ~/.config/fish/config.fish");
        let _ = writeln!(err, "  {bin} completions fish | source)\n");
        let _ = writeln!(err, "### Zsh (put this in ~/.zshrc)");
        let _ = writeln!(
            err,
            "  autoload -U compinit; compinit; source <({bin} completions zsh)"
        );

        1
    }
}

fn generate_completion_script<W: Write>(shell: Shell, out: &mut W) {
    clap_complete::generate(shell, &mut cli::app(), env!("CARGO_BIN_NAME"), out)
}

fn serve<W1: Write, W2: Write>(sub_matches: &clap::ArgMatches, out: &mut W1, err: &mut W2) -> i32 {
    let ip = sub_matches.get_one::<String>("listen_ip").unwrap();
    let port = sub_matches.get_one::<u16>("listen_port").unwrap();
    let addr_str = format!("{ip}:{port}");

    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            let _ = writeln!(err, "Invalid listen addr '{addr_str}': {e}");
            return 1;
        }
    };

    // ---- Trusted USER header options ----
    let enabled = sub_matches.get_flag("trusted_header_auth");

    let header_name_str = sub_matches
        .get_one::<String>("trusted_header_name")
        .map(|s| s.as_str())
        .unwrap_or("X-Forwarded-User");

    let header_name = match HeaderName::from_bytes(header_name_str.as_bytes()) {
        Ok(h) => h,
        Err(e) => {
            let _ = writeln!(err, "Invalid header name '{header_name_str}': {e}");
            return 1;
        }
    };

    let trusted_proxy = *sub_matches.get_one::<IpAddr>("trusted_proxy").unwrap();

    let auth_cfg = middleware::TrustedHeaderAuthConfig {
        enabled,
        header_name,
        trusted_proxy,
    };

    if enabled {
        let _ = writeln!(
            out,
            "Trusted USER header enabled: header='{header_name_str}', trusted_proxy={trusted_proxy}"
        );
    }

    // ---- Trusted FORWARDED-FOR (client IP) options ----
    let fwd_enabled = sub_matches.get_flag("trusted_forwarded_for");

    let fwd_header_str = sub_matches
        .get_one::<String>("forwarded_for_header_name")
        .map(|s| s.as_str())
        .unwrap_or("X-Forwarded-For");

    let fwd_header_name = match HeaderName::from_bytes(fwd_header_str.as_bytes()) {
        Ok(h) => h,
        Err(e) => {
            let _ = writeln!(
                err,
                "Invalid forwarded-for header name '{fwd_header_str}': {e}"
            );
            return 1;
        }
    };

    let fwd_cfg = middleware::TrustedForwardedForConfig {
        enabled: fwd_enabled,
        header_name: fwd_header_name,
        trusted_proxy,
    };

    if fwd_enabled {
        let _ = writeln!(
            out,
            "Trusted FORWARDED-FOR enabled: header='{fwd_header_str}', trusted_proxy={trusted_proxy}"
        );
    }

    let _ = writeln!(out, "Starting server on http://{addr}");

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "Failed to start Tokio runtime: {e}");
            return 1;
        }
    };

    match rt.block_on(server::run(addr, auth_cfg, fwd_cfg)) {
        Ok(()) => 0,
        Err(e) => {
            let _ = writeln!(err, "Server error: {e:#}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn help_prints_when_no_subcommand() {
        // Capture stdout/stderr
        let mut out = Vec::new();
        let mut err = Vec::new();

        // Run with just the bin name => no subcommand => help on stdout
        let code = run_cli(["app"], &mut out, &mut err);

        assert_eq!(code, 0, "expected exit code 0 when printing help");
        assert!(
            err.is_empty(),
            "expected no stderr output, got: {}",
            String::from_utf8_lossy(&err)
        );

        let actual = String::from_utf8(out).expect("stdout should be valid utf8");

        // Build expected help text the same way dispatch does.
        let mut expected_buf = Vec::new();
        let mut cmd = crate::cli::app();
        cmd.write_help(&mut expected_buf).unwrap();
        writeln!(&mut expected_buf).unwrap(); // dispatch adds a newline after help
        let expected = String::from_utf8(expected_buf).unwrap();

        assert_eq!(actual, expected);
    }
}
