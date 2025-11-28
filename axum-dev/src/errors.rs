use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::error::Error;
use std::{fmt, io};
use tracing::error;

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

#[derive(Debug)]
pub struct AppError {
    pub status: StatusCode,
    pub inner: anyhow::Error,
}

impl AppError {
    /// default 500 error
    pub fn new(err: impl Into<anyhow::Error>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            inner: err.into(),
        }
    }

    /// build an error with a specific HTTP status
    pub fn with_status(status: StatusCode, err: impl Into<anyhow::Error>) -> Self {
        Self {
            status,
            inner: err.into(),
        }
    }
}

// generic conversion for "normal" error types
impl<E> From<E> for AppError
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn from(err: E) -> Self {
        AppError::new(err)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // This is where the juicy backtrace gets logged
        error!("internal error (status={}): {:#}", self.status, self.inner);
        (self.status, "Internal Server Error").into_response()
    }
}

pub type AppResult<T> = std::result::Result<T, AppError>;
