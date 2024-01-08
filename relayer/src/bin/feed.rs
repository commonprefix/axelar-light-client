extern crate relayer;

use eth::{
    consensus::{ConsensusRPC, EthBeaconAPI},
    types::EthConfig,
};
use relayer::{utils::{load_config, calc_sync_period}, verifier::Verifier};
use std::{sync::Arc, time::Duration};
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
        interval.tick().await;

        let latest_header = consensus.get_latest_beacon_block_header().await;
        if latest_header.is_err() {
            println!("Error getting latest header from consensus: {:?}", latest_header.err());
            continue;
        }
        let latest_header = latest_header.unwrap();

        let latest_period = calc_sync_period(latest_header.slot);
        let verifier_period = verifier.get_period().await;
        if verifier_period.is_err() {
            println!("Error getting period from wasm: {:?}", verifier_period);
            continue;
        }
        let verifier_period = verifier_period.unwrap();

        println!(
            "Latest period: {}, Verifier period: {}",
            latest_period, verifier_period
        );
        if latest_period == verifier_period {
            println!("No updates to process");
            continue;
        }

        let updates = consensus
            .get_updates(verifier_period + 1, MAX_UPDATES_PER_LOOP)
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
        println!(
            "Processing {} updates starting from period {}",
            updates.len(),
            verifier_period + 1
        );

        for update in updates {
            let update_period = calc_sync_period(update.attested_header.beacon.slot);
            let result = verifier.update(update).await;
            if result.is_err() {
                println!("Error updating wasm: {:?}", result.err());
                break;
            }

            println!("Update {} successfully", update_period);
        }
    }
}
