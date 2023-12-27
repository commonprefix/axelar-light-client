pub mod prover;
pub mod types;

use eth::consensus::ConsensusRPC;
use prover::{
    consensus::ConsensusProver, execution::ExecutionProver, state_prover::StateProver,
    types::ProverConfig,
};
use std::sync::Arc;

pub fn init_prover(prover_config: ProverConfig) -> prover::Prover {
    let consensus = Arc::new(ConsensusRPC::new(prover_config.consensus_rpc.clone()));

    let state_prover = StateProver::new(prover_config.state_prover_rpc.clone());
    let consensus_prover = ConsensusProver::new(consensus.clone(), state_prover.clone());
    let execution_prover = ExecutionProver::new();

    prover::Prover::new(Box::new(consensus_prover), Box::new(execution_prover))
}
