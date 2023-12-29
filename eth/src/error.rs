use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum RPCError {
    #[error("Resource not found on request: {0}")]
    NotFoundError(String),
    #[error("Rate limit error on request: {0}")]
    RateLimitError(String),
    #[error("Error sending request: {0}")]
    RequestError(String),
    #[error("UnknownError for request: {0}")]
    UnknownError(String),
    #[error("Error deserializing response: {0} {1}")]
    DeserializationError(String, String),
}
