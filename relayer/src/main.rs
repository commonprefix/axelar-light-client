mod consumer;
mod types;
mod utils;
mod wasm;
mod parser;
mod relayer;

use eth::consensus::EthBeaconAPI;
use eth::types::EthConfig;
use eth::{consensus::ConsensusRPC, execution::ExecutionRPC};
use prover::prover::types::ProverConfig;
use prover::Prover;
use std::fs::File;
use std::sync::Arc;
use types::EnrichedLog;

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
    let prover = Prover::with_config(consensus.clone(), prover_config);
    let relayer = Relayer::new(config.clone(), consensus.clone(), execution.clone(), prover);

    //let enriched_logs = vec![get_json().unwrap()];
    let consumer = consumer::Gateway::new(consensus.clone(), execution.clone(), config.gateway_addr.clone());
    let finality_update = consensus.get_finality_update().await.unwrap();
    let latest_slot = finality_update.attested_header.beacon.slot;
    println!("Processing logs for slot {}", latest_slot);
    let enriched_logs = consumer.get_logs_in_slot_range(latest_slot - 7000, latest_slot, 5).await.unwrap();
    println!("Got logs {:#?}", enriched_logs.len());
    let res = relayer.digest_messages(&enriched_logs).await;
    println!("Res {:?}", res);

    // let conn = Connection::connect(config.sentinel_queue_addr.as_str(), ConnectionProperties::default()).await.unwrap();
    // let channel = conn.create_channel().await.unwrap();
    
    // let mut consumer = channel
    //     .basic_consume(
    //         config.sentinel_queue_name.as_str(),
    //         "my_consumer",
    //         BasicConsumeOptions::default(),
    //         FieldTable::default(),
    //     )
    //     .await.unwrap();

    // println!("Waiting for messages... {:?}", consumer.state());

    // while let Some(delivery) = consumer.next().await {
    //     if let Ok((_channel, delivery)) = delivery {
    //         let str = std::str::from_utf8(&delivery.data).unwrap();
    //         let enriched_log: Result<EnrichedLog, _> = serde_json::from_str(str);
    //     }
    // }
}

fn get_json() -> Option<EnrichedLog>   {
    let file = File::open("./src/test.json").unwrap();
    let res: Option<EnrichedLog> = serde_json::from_reader(file).unwrap();
    res
}