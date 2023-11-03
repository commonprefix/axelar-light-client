use cosmwasm_std::StdError;
use lightclient::error::ConsensusError;
use thiserror::Error;

use crate::lightclient;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Update for this period already exists")]
    UpdateAlreadyExists {},

    #[error("No sync committee for this period")]
    NoSyncCommittee { period: u64 },

    #[error("Consensus error: {:?}", error)]
    ConsensusError { error: ConsensusError },

    #[error("Empty Messages")]
    EmptyMessages {},

    #[error("message {0} mismatch with verified message")]
    MessageMismatch(String),
    // Add any other custom errors you like here.
    // Look at https://docs.rs/thiserror/1.0.21/thiserror/ for details.
}

impl From<ContractError> for StdError {
    fn from(value: ContractError) -> Self {
        Self::generic_err(value.to_string())
    }
}

// Wrap consensus error to contract error
impl From<ConsensusError> for ContractError {
    fn from(err: ConsensusError) -> Self {
        ContractError::Std(StdError::GenericErr {
            msg: err.to_string(),
        })
    }
}
