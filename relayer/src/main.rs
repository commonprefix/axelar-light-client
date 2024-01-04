mod consumer;
mod parser;
mod relayer;
mod types;
mod utils;
mod wasm;

use consumer::LapinConsumer;
use eth::types::EthConfig;
use eth::{consensus::ConsensusRPC, execution::ExecutionRPC};

use prover::prover::types::ProverConfig;
use prover::Prover;
use std::sync::Arc;

use crate::relayer::Relayer;
use crate::utils::load_config;

#[tokio::main]
async fn main() {
    // TODO: Move file limit to config
    rlimit::increase_nofile_limit(u64::MAX).unwrap();
    let config = load_config();
    let prover_config = ProverConfig::from(config.clone());
    let eth_config = EthConfig::from(config.clone());

    let consensus = Arc::new(ConsensusRPC::new(config.consensus_rpc.clone(), eth_config));
    let execution = Arc::new(ExecutionRPC::new(config.execution_rpc.clone()));
    let prover = Arc::new(Prover::with_config(consensus.clone(), prover_config));
    let consumer =
        LapinConsumer::new(&config.sentinel_queue_addr, &config.sentinel_queue_name).await;

    let mut relayer = Relayer::new(
        config.clone(),
        consumer,
        consensus.clone(),
        execution.clone(),
        prover,
    )
    .await;

    relayer.start().await;

    //let enriched_logs = vec![get_json().unwrap()];
    // let consumer = consumer::Gateway::new(consensus.clone(), execution.clone(), config.gateway_addr.clone());
    // let finality_update = consensus.get_finality_update().await.unwrap();
    // let latest_slot = finality_update.attested_header.beacon.slot;
    // println!("Processing logs for slot {}", latest_slot);
    // let enriched_logs = consumer.get_logs_in_slot_range(latest_slot - 7000, latest_slot, 5).await.unwrap();
    // println!("Got logs {:#?}", enriched_logs.len());
    // let res = relayer.digest_messages(&enriched_logs).await;
    // println!("Res {:?}", res);
}
