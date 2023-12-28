pub mod prover;
pub mod types;

use eth::consensus::ConsensusRPC;
use prover::{
    consensus::ConsensusProver, execution::ExecutionProver, state_prover::StateProver,
    types::ProverConfig,
};
use std::sync::Arc;

type ProverAlias = prover::Prover<ConsensusProver<ConsensusRPC, StateProver>, ExecutionProver>;

pub fn init_prover(consensus_rpc: Arc<ConsensusRPC>, prover_config: ProverConfig) -> ProverAlias {
    let state_prover = StateProver::new(prover_config.state_prover_rpc.clone());
    let consensus_prover = ConsensusProver::new(consensus_rpc, state_prover.clone());
    let execution_prover = ExecutionProver::new();

    prover::Prover::new(consensus_prover, execution_prover)
}
