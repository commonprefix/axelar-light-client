mod consumer;
mod types;
mod wasm;
mod parser;

use dotenv::dotenv;
use eth::types::EthConfig;
use eth::utils::get_full_block_details;
use eth::{consensus::ConsensusRPC, execution::ExecutionRPC};
use futures::StreamExt;
use lapin::options::BasicConsumeOptions;
use lapin::types::FieldTable;
use parser::parse_enriched_log;
use prover::prover::types::ProverConfig;
use prover::Prover;
use std::env;
use std::fs::File;
use std::str::FromStr;
use std::sync::Arc;
use types::{Config, VerificationMethod, EnrichedLog};
use lapin::{Connection, ConnectionProperties};

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

    let conn = Connection::connect(config.sentinel_queue_addr.as_str(), ConnectionProperties::default()).await.unwrap();
    let channel = conn.create_channel().await.unwrap();
    
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
    //         println!("Received message: {:?}", std::str::from_utf8(&delivery.data).unwrap());
    //     }
    // }
    let json = get_json();

    match json {
        Some(json) => {
            println!("JSON: {:?}", json);
        },
        None => {
            println!("No JSON");
        }
    }

    // let consensus = Arc::new(ConsensusRPC::new(config.consensus_rpc.clone()));
    // let execution = Arc::new(ExecutionRPC::new(config.execution_rpc.clone()));
    // let gateway: Gateway = Gateway::new(consensus.clone(), execution.clone(), config.gateway_addr);

    // let prover = Prover::with_config(consensus.clone(), prover_config);

    // let finality_update = consensus.get_finality_update().await.unwrap();
    // let update = UpdateVariant::Finality(finality_update.clone());
    // let finality_header_slot = finality_update.finalized_header.beacon.slot;

    // let min_slot_in_block_roots = finality_header_slot - SLOTS_PER_HISTORICAL_ROOT as u64 + 1;
    // let messages = consume_messages(
    //     &gateway,
    //     min_slot_in_block_roots - 1000,
    //     min_slot_in_block_roots,
    //     5,
    // )
    // .await;

    // // Get only first ten
    // let res = prover
    //     .batch_messages(&messages, &update.clone())
    //     .await
    //     .unwrap();
    // debug_print_batch_message_groups(&res);

    // let proofs = prover
    //     .batch_generate_proofs(res, update.clone())
    //     .await
    //     .unwrap();
    // let proofs_json = serde_json::to_string(&proofs).unwrap();
    // println!("{}", proofs_json);

    // println!("Proofs: {:?}", proofs);
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
        sentinel_queue_addr: env::var("SENTINEL_QUEUE_ADDR").expect("Missing SENTINEL_QUEUE_ADDR from .env"),
        sentinel_queue_name: env::var("SENTINEL_QUEUE_NAME").expect("Missing SENTINEL_QUEUE_NAME from .env"),
        historical_roots_enabled: true,
        historical_roots_block_roots_batch_size: 1000,
        verification_method: VerificationMethod::from_str(
            env::var("VERIFICATION_METHOD")
                .expect("VERIFICATION not found")
                .as_str(),
        ).unwrap(),
    }
}



fn get_json() -> Option<EnrichedLog>   {
    let file = File::open("./src/test.json").unwrap();
    let res: Option<EnrichedLog> = serde_json::from_reader(file).unwrap();
    res
}