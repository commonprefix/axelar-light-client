mod prover;
mod types;
mod wasm;

use crate::prover::state_prover::StateProver;
use crate::prover::Prover;
use consensus_types::proofs::UpdateVariant;
use dotenv::dotenv;
use eth::consensus::EthBeaconAPI;
use eth::{consensus::ConsensusRPC, execution::ExecutionRPC, gateway::Gateway};
use prover::types::Config;
use std::env;
use std::time::Instant;
use sync_committee_rs::constants::SLOTS_PER_HISTORICAL_ROOT;

#[tokio::main]
async fn main() {
    let config = load_prover_config();

    let consensus: ConsensusRPC = ConsensusRPC::new(config.consensus_rpc.clone());
    let execution: ExecutionRPC = ExecutionRPC::new(config.execution_rpc.clone());
    let state_prover = StateProver::new(config.state_prover_rpc.clone());
    let gateway: Gateway = Gateway::new(config.execution_rpc, config.gateway_addr);
    let prover = Prover::new(&consensus, &execution, &state_prover);

    let finality_update = consensus.get_finality_update().await.unwrap();
    let finality_header_slot = finality_update.finalized_header.beacon.slot;
    let min_slot_in_block_roots = finality_header_slot - SLOTS_PER_HISTORICAL_ROOT as u64 + 1;
    let interested_messages = gateway
        .get_messages_in_slot_range(&execution, min_slot_in_block_roots, finality_header_slot)
        .await
        .unwrap();

    let mut first_message = interested_messages.first().unwrap().clone();

    let now = Instant::now();

    let proof = prover
        .prove_event(&mut first_message, UpdateVariant::Finality(finality_update))
        .await
        .unwrap();

    let proof_json = serde_json::to_string(&proof).unwrap();
    println!("{}", proof_json);

    println!(
        "Generated full proof in {} seconds",
        now.elapsed().as_secs_f64()
    );
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
