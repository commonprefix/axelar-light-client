pub mod prover;
pub mod types;

use std::sync::Arc;
use eth::consensus::ConsensusRPC;
use prover::{types::ProverConfig, state_prover::StateProver, consensus::ConsensusProver, execution::ExecutionProver};

pub fn init_prover(prover_config: ProverConfig) -> prover::Prover {
    let consensus = Arc::new(ConsensusRPC::new(prover_config.consensus_rpc.clone()));

    let state_prover = Arc::new(StateProver::new(prover_config.state_prover_rpc.clone()));
    let consensus_prover = ConsensusProver::new(consensus.clone(), state_prover.clone());
    let execution_prover = ExecutionProver::new();

    prover::Prover::new(Box::new(consensus_prover), Box::new(execution_prover))
}