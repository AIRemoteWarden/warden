use thiserror::Error;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("invalid arguments: {0}")]
    InvalidArguments(String),

    #[error("unsupported operation: {0}")]
    Unsupported(&'static str),

    #[error("runtime invariant violated: {0}")]
    Invariant(&'static str),

    #[error("operation failed: {0}")]
    Message(String),
}
