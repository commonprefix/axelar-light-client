mod prover;
mod types;
mod wasm;

use crate::prover::consensus::ConsensusProver;
use crate::prover::execution::ExecutionProver;
use crate::prover::state_prover::StateProver;
use crate::prover::Prover;
use crate::prover::types::BatchMessageGroups;
use crate::prover::utils::debug_print_batch_message_groups;
use consensus_types::proofs::UpdateVariant;

use dotenv::dotenv;
use eth::consensus::EthBeaconAPI;
use eth::{consensus::ConsensusRPC, execution::ExecutionRPC, gateway::Gateway};
use prover::types::Config;

use std::env;
use std::sync::Arc;

use sync_committee_rs::constants::SLOTS_PER_HISTORICAL_ROOT;

#[tokio::main]
async fn main() {
    let config = load_prover_config();

    let consensus= Arc::new(ConsensusRPC::new(config.consensus_rpc.clone()));
    let execution= Arc::new(ExecutionRPC::new(config.execution_rpc.clone()));
    let state_prover = Arc::new(StateProver::new(config.state_prover_rpc.clone()));

    let gateway: Gateway = Gateway::new(consensus.clone(), execution.clone(), config.gateway_addr);
    let consensus_prover = ConsensusProver::new(consensus.clone(), state_prover.clone());
    let execution_prover = ExecutionProver::new();

    let finality_update = consensus.get_finality_update().await.unwrap();
    let update = UpdateVariant::Finality(finality_update.clone());
    let finality_header_slot = finality_update.finalized_header.beacon.slot;

    let min_slot_in_block_roots = finality_header_slot - SLOTS_PER_HISTORICAL_ROOT as u64 + 1;

    let messages = gateway
        .get_messages_in_slot_range(min_slot_in_block_roots, finality_header_slot)
        .await
        .unwrap();

    let prover = Prover::new(&consensus_prover, &execution_prover);

    // Get only first ten
    let res = prover.batch_messages(&messages[0..10], &update.clone()).await.unwrap();
    debug_print_batch_message_groups(&res);

    let proofs = prover.batch_generate_proofs(res, update.clone()).await.unwrap();
    let proofs_json = serde_json::to_string(&proofs).unwrap();
    println!("{}", proofs_json);

    println!("Proofs: {:?}", proofs);
}

fn load_prover_config() -> Config {
    dotenv().ok();

    Config {
        consensus_rpc: env::var("CONSENSUS_RPC").expect("Missing CONSENSUS_RPC from .env"),
        execution_rpc: env::var("EXECUTION_RPC").expect("Missing EXECUTION_RPC from .env"),
        state_prover_rpc: env::var("STATE_PROVER_RPC").expect("Missing STATE_PROVER from .env"),
        gateway_addr: env::var("GATEWAY_ADDR").expect("Missing GATEWAY_ADDR from .env"),
        historical_roots_enabled: true,
        historical_roots_block_roots_batch_size: 1000,
    }
}
