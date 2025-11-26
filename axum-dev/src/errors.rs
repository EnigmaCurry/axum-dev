use axum::http::StatusCode;
use std::error::Error;
use std::{fmt, io};

#[derive(Debug)]
pub enum CliError {
    Io(io::Error),
    InvalidArgs(String),
    UnsupportedShell(String),
    RuntimeError(String),
}
impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Io(e) => write!(f, "I/O error: {e}"),
            CliError::UnsupportedShell(s) => write!(f, "Unsupported shell: {s}"),
            CliError::InvalidArgs(s) => write!(f, "Invalid args: {s}"),
            CliError::RuntimeError(s) => write!(f, "Runtime error: {s}"),
        }
    }
}
impl Error for CliError {}
impl From<io::Error> for CliError {
    fn from(e: io::Error) -> Self {
        CliError::Io(e)
    }
}

pub fn internal_error<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
#[allow(dead_code)]
pub fn not_found_error<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, e.to_string())
}
