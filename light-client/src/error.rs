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

    #[error("Invalid BlockRoots proof")]
    InvalidBlockRootsProof,

    #[error("Invalid BlockRoots branch")]
    InvalidBlockRootsBranch,

    #[error("Invalid receipt proof")]
    InvalidReceiptProof,

    #[error("Invalid execution branch")]
    InvalidExecutionBranch,
    // Add any other custom errors you like here.
    // Look at https://docs.rs/thiserror/1.0.21/thiserror/ for details.
}

// Wrap consensus error to contract error
impl From<ConsensusError> for ContractError {
    fn from(err: ConsensusError) -> Self {
        ContractError::Std(StdError::GenericErr {
            msg: err.to_string(),
        })
    }
}
