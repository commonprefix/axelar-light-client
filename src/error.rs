use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Update for this period already exists")]
    UpdateAlreadyExists {},

    #[error("Invalid period")]
    InvalidPeriod {},

    #[error("Not enough signatures")]
    NotEnoughSignatures {},
    // Add any other custom errors you like here.
    // Look at https://docs.rs/thiserror/1.0.21/thiserror/ for details.
}

#[derive(Error, Debug)]
pub enum ConsensusError {
    #[error("insufficient participation")]
    InsufficientParticipation,
    #[error("invalid timestamp")]
    InvalidTimestamp,
    #[error("invalid sync committee period")]
    InvalidPeriod,
    #[error("update not relevant")]
    NotRelevant,
    #[error("invalid finality proof")]
    InvalidFinalityProof,
    #[error("invalid next sync committee proof")]
    InvalidNextSyncCommitteeProof,
    #[error("invalid current sync committee proof")]
    InvalidCurrentSyncCommitteeProof,
    #[error("invalid sync committee signature")]
    InvalidSignature,
    #[error("invalid header hash found: {0}, expected: {1}")]
    InvalidHeaderHash(String, String),
    #[error("payload not found for slot: {0}")]
    PayloadNotFound(u64),
    #[error("checkpoint is too old")]
    CheckpointTooOld,
    #[error("consensus rpc is for the incorrect network")]
    IncorrectRpcNetwork,
}

// Wrap consensus error to contract error
impl From<ConsensusError> for ContractError {
    fn from(err: ConsensusError) -> Self {
        ContractError::Std(StdError::GenericErr {
            msg: err.to_string(),
        })
    }
}
