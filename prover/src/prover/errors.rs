use cita_trie::TrieError;
use consensus_types::ssz_rs::MerkleizationError;
use eth::error::RPCError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProverError {
    #[error("TrieProof proof generation error")]
    TrieProofError(#[from] TrieError),

    #[error("State prover error: {0}")]
    StateProverError(#[from] StateProverError),

    #[error("Merkle proof generation error: {0}")]
    MerkleProofGenerationError(#[from] MerkleizationError),

    #[error("Invalid data error {0}")]
    InvalidDataError(String),

    #[error("RPC request failed {0}")]
    RPCError(#[from] RPCError),
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
