mod consumer;
mod types;
mod wasm;

use consensus_types::proofs::UpdateVariant;
use consumer::Gateway;
use dotenv::dotenv;
use eth::consensus::EthBeaconAPI;
use eth::{consensus::ConsensusRPC, execution::ExecutionRPC};
use prover::prover::types::{EnrichedMessage, ProverConfig};
use prover::prover::utils::debug_print_batch_message_groups;
use prover::Prover;
use std::env;
use std::str::FromStr;
use std::sync::Arc;
use sync_committee_rs::constants::SLOTS_PER_HISTORICAL_ROOT;
use types::{Config, VerificationMethod};

#[tokio::main]
async fn main() {
    let config = load_prover_config();
    let prover_config = ProverConfig::from(config.clone());

    let consensus = Arc::new(ConsensusRPC::new(config.consensus_rpc.clone()));
    let execution = Arc::new(ExecutionRPC::new(config.execution_rpc.clone()));
    let gateway: Gateway = Gateway::new(consensus.clone(), execution.clone(), config.gateway_addr);

    let prover = Prover::with_config(consensus.clone(), prover_config);

    let finality_update = consensus.get_finality_update().await.unwrap();
    let update = UpdateVariant::Finality(finality_update.clone());
    let finality_header_slot = finality_update.finalized_header.beacon.slot;

    let min_slot_in_block_roots = finality_header_slot - SLOTS_PER_HISTORICAL_ROOT as u64 + 1;
    let messages = consume_messages(
        &gateway,
        min_slot_in_block_roots - 1000,
        min_slot_in_block_roots,
        5,
    )
    .await;

    // Get only first ten
    let res = prover
        .batch_messages(&messages, &update.clone())
        .await
        .unwrap();
    debug_print_batch_message_groups(&res);

    let proofs = prover
        .batch_generate_proofs(res, update.clone())
        .await
        .unwrap();
    let proofs_json = serde_json::to_string(&proofs).unwrap();

    println!("Proofs: {}", proofs_json);
}

async fn consume_messages(
    gateway: &Gateway,
    from: u64,
    to: u64,
    limit: u64,
) -> Vec<EnrichedMessage> {
    gateway
        .get_messages_in_slot_range(from, to, limit)
        .await
        .unwrap()[0..limit as usize]
        .to_vec()
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
        verification_method: VerificationMethod::from_str(
            env::var("VERIFICATION_METHOD")
                .expect("VERIFICATION not found")
                .as_str(),
        )
        .unwrap(),
    }
}
