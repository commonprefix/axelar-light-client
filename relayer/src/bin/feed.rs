extern crate relayer;

use eth::{
    consensus::{ConsensusRPC, EthBeaconAPI},
    types::EthConfig,
};
use log::{debug, error, info};
use relayer::{
    utils::{calc_sync_period, load_config},
    verifier::{Verifier, VerifierAPI},
};
use std::{sync::Arc, time::Duration};
use tokio::time::sleep;

const MAX_UPDATES_PER_LOOP: u8 = 100;

#[tokio::main]
async fn main() {
    env_logger::init();

    let config = load_config();
    let eth_config = EthConfig::from(config.clone());
    let sleep_duration = Duration::from_secs(config.feed_interval);

    let consensus = Arc::new(ConsensusRPC::new(
        config.consensus_rpc.clone(),
        config.block_roots_rpc,
        eth_config,
    ));
    let mut verifier = Verifier::new(config.wasm_rpc, config.verifier_addr, config.wasm_wallet);

    loop {
        let latest_header = consensus.get_latest_beacon_block_header().await;
        if latest_header.is_err() {
            error!(
                "Error getting latest header from consensus: {:?}",
                latest_header.err()
            );
            continue;
        }
        let latest_header = latest_header.unwrap();
        let latest_period = calc_sync_period(latest_header.slot);

        let state = verifier.get_state().await;
        if state.is_err() {
            error!("Error getting state from wasm: {:?}", state.err());
            continue;
        }
        let state = state.unwrap();
        let verifier_period = calc_sync_period(state.update_slot);
        let is_on_bootstrap = state.next_sync_committee.is_none();

        info!(
            "Latest period: {}, Verifier period: {}",
            latest_period, verifier_period
        );
        if latest_period == verifier_period {
            debug!("No updates to process");
            continue;
        }

        let start_update_period = if is_on_bootstrap {
            info!(
                "Verifier is on bootstrap. Will apply updates starting from period {}",
                verifier_period
            );
            verifier_period
        } else {
            verifier_period + 1
        };

        let updates = consensus
            .get_updates(start_update_period, MAX_UPDATES_PER_LOOP)
            .await;
        if updates.is_err() {
            error!("Error getting updates from consensus: {:?}", updates.err());
            continue;
        }
        let updates = updates.unwrap();
        info!(
            "Processing {} updates starting from period {}",
            updates.len(),
            start_update_period
        );

        for update in updates {
            let update_period = calc_sync_period(update.attested_header.beacon.slot);
            let result = verifier.update(update).await;
            if result.is_err() {
                error!("Error updating wasm: {:?}", result.err());
                break;
            }
            let new_verifier_period = verifier.get_period().await.unwrap();

            info!(
                "Update {} succeeded. New verifier period: {}",
                update_period, new_verifier_period
            );
        }

        debug!("Sleeping for {}", sleep_duration.as_secs());
        sleep(sleep_duration).await;
    }
}
