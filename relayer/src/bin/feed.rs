extern crate relayer;

use eth::{
    consensus::{ConsensusRPC, EthBeaconAPI},
    types::EthConfig,
};
use relayer::{load_config, verifier::Verifier};
use std::{sync::Arc, time::Duration};
use sync_committee_rs::constants::SLOTS_PER_EPOCH;
use tokio::time::interval;

const MAX_UPDATES_PER_LOOP: u8 = 100;

#[tokio::main]
async fn main() {
    let config = load_config();
    let eth_config = EthConfig::from(config.clone());
    let mut interval = interval(Duration::from_secs(config.process_interval));

    let consensus = Arc::new(ConsensusRPC::new(config.consensus_rpc.clone(), eth_config));
    let mut verifier = Verifier::new(config.wasm_rpc, config.verifier_addr);

    loop {
        interval.tick().await; // This should go first.

        let period = verifier.get_period().await;
        if period.is_err() {
            println!("Error getting period from wasm: {:?}", period);
            continue;
        }
        let period = period.unwrap();

        let updates = consensus
            .get_updates(period + 1, MAX_UPDATES_PER_LOOP)
            .await;
        if updates.is_err() {
            println!("Error getting updates from consensus: {:?}", updates.err());
            continue;
        }
        let updates = updates.unwrap();
        if updates.is_empty() {
            println!("No updates to process");
            continue;
        }
        let first_update_period = updates[0].attested_header.beacon.slot / SLOTS_PER_EPOCH / 256;
        println!(
            "Processing {} updates starting from period {}",
            updates.len(),
            first_update_period
        );

        for update in updates {
            let result = verifier.update(update).await;
            if result.is_err() {
                println!("Error updating wasm: {:?}", result.err());
                break;
            }
        }
    }
}
