use thiserror::Error;
use cita_trie::TrieError;

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("Receipt proof generation error")]
    Disconnect(#[from] TrieError),

}

#[derive(Error, Debug)]
pub enum StateProverError {
    #[error("Request failed: {0}")]
    RequestError(String),
    #[error("Failed to parse response: {0}")]
    ParseError(String),
    #[error("State or block not found: {0}")] 
    NotFoundError(String),
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}