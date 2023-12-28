pub mod prover;
pub mod types;

use eth::consensus::ConsensusRPC;
use prover::{
    consensus::ConsensusProver, execution::ExecutionProver, state_prover::StateProver,
    types::ProverConfig,
};
use std::sync::Arc;

pub use prover::Prover;