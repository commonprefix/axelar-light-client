mod prover;
mod types;
mod wasm;

use crate::prover::state_prover::StateProver;
use crate::prover::Prover;
use consensus_types::lightclient::UpdateVariant;
use eth::consensus::EthBeaconAPI;
use eth::{consensus::ConsensusRPC, constants::*, execution::ExecutionRPC, gateway::Gateway};
use std::time::Instant;
use sync_committee_rs::constants::SLOTS_PER_HISTORICAL_ROOT;

#[tokio::main]
async fn main() {
    let consensus: ConsensusRPC = ConsensusRPC::new(CONSENSUS_RPC);
    let execution: ExecutionRPC = ExecutionRPC::new(EXECUTION_RPC);
    let state_prover = StateProver::new(STATE_PROVER_RPC);

    let gateway: Gateway = Gateway::new(EXECUTION_RPC, GATEWAY_ADDR);
    let prover = Prover::new(execution, consensus, state_prover);

    let consensus: ConsensusRPC = ConsensusRPC::new(CONSENSUS_RPC);

    let finality_update = consensus.get_finality_update().await.unwrap();
    let finality_header_slot = finality_update.finalized_header.beacon.slot;
    let min_slot_in_block_roots = finality_header_slot - SLOTS_PER_HISTORICAL_ROOT as u64 + 1;
    let interested_messages = gateway
        .get_messages_in_slot_range(min_slot_in_block_roots, finality_header_slot)
        .await
        .unwrap();

    let first_message = interested_messages.first().unwrap();

    let now = Instant::now();

    let proof = prover
        .prove_event(
            first_message.clone(),
            UpdateVariant::Finality(finality_update),
        )
        .await
        .unwrap();

    let proof_json = serde_json::to_string(&proof).unwrap();
    println!("{}", proof_json);

    println!(
        "Generated full proof in {} seconds",
        now.elapsed().as_secs_f64()
    );
}
