extern crate relayer;

use eth::{consensus::ConsensusRPC, execution::ExecutionRPC, types::EthConfig};
use prover::{prover::types::ProverConfig, Prover};
use relayer::{
    consumers::{EthersConsumer, LapinConsumer},
    relayer::Relayer,
    utils::load_config,
    verifier::Verifier,
};
use std::sync::Arc;

/// Main entry point for the relayer.
#[tokio::main]
async fn main() {
    env_logger::init();
    rlimit::increase_nofile_limit(u64::MAX).unwrap();

    let config = load_config();
    let prover_config = ProverConfig::from(config.clone());
    let eth_config = EthConfig::from(config.clone());

    let consensus = Arc::new(ConsensusRPC::new(config.consensus_rpc.clone(), eth_config));
    let execution = Arc::new(ExecutionRPC::new(config.execution_rpc.clone()));
    let prover = Arc::new(Prover::with_config(consensus.clone(), prover_config));
    let verifier = Verifier::new(config.wasm_rpc.clone(), config.verifier_addr.clone());

    let consumer =
        LapinConsumer::new(&config.sentinel_queue_addr, &config.sentinel_queue_name).await;

    // let consumer = EthersConsumer::new(execution.clone(), config.gateway_addr.clone());

    let mut relayer = Relayer::new(
        config.clone(),
        consumer,
        consensus.clone(),
        execution.clone(),
        prover,
        verifier,
    )
    .await;

    relayer.start().await;
}
