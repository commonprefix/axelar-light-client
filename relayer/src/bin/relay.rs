extern crate relayer;

use std::sync::Arc;
use eth::{types::EthConfig, consensus::ConsensusRPC, execution::ExecutionRPC};
use prover::{prover::types::ProverConfig, Prover};
use relayer::{load_config, consumer::LapinConsumer, relayer::Relayer};

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
}
