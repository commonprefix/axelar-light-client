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
use std::time::Duration;
use tokio::time::sleep;

const MAX_UPDATES_PER_LOOP: u8 = 100;

pub struct Feeder<V, CR> {
    verifier: V,
    consensus: CR,
}

impl<V: VerifierAPI, CR: EthBeaconAPI> Feeder<V, CR> {
    pub fn new(verifier: V, consensus: CR) -> Self {
        Feeder {
            verifier,
            consensus,
        }
    }

    pub async fn tick(&self) {
        let latest_header = self.consensus.get_latest_beacon_block_header().await;
        if latest_header.is_err() {
            error!(
                "Error getting latest header from consensus: {:?}",
                latest_header.err()
            );
            return;
        }
        let latest_header = latest_header.unwrap();
        let latest_period = calc_sync_period(latest_header.slot);

        let state = self.verifier.get_state().await;
        if state.is_err() {
            error!("Error getting state from wasm: {:?}", state.err());
            return;
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
            return;
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

        let updates = self
            .consensus
            .get_updates(start_update_period, MAX_UPDATES_PER_LOOP)
            .await;
        if updates.is_err() {
            error!("Error getting updates from consensus: {:?}", updates.err());
            return;
        }
        let updates = updates.unwrap();
        info!(
            "Processing {} updates starting from period {}",
            updates.len(),
            start_update_period
        );

        for update in updates {
            let update_period = calc_sync_period(update.attested_header.beacon.slot);
            let result = self.verifier.update(update).await;
            if result.is_err() {
                error!("Error updating wasm: {:?}", result.err());
                break;
            }
            let new_verifier_period = self.verifier.get_period().await.unwrap();

            info!(
                "Update {} succeeded. New verifier period: {}",
                update_period, new_verifier_period
            );
        }
    }

    pub async fn start(&self, sleep_duration: Duration) {
        loop {
            self.tick().await;

            debug!("Sleeping for {}", sleep_duration.as_secs());
            sleep(sleep_duration).await;
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let config = load_config();
    let eth_config = EthConfig::from(config.clone());
    let sleep_duration = Duration::from_secs(config.feed_interval);

    let consensus = ConsensusRPC::new(
        config.consensus_rpc.clone(),
        config.block_roots_rpc,
        eth_config,
    );
    let verifier = Verifier::new(config.wasm_rpc, config.verifier_addr, config.wasm_wallet);

    let feeder = Feeder::new(verifier, consensus);
    feeder.start(sleep_duration).await;
}

#[cfg(test)]
mod tests {
    use consensus_types::{
        consensus::{BeaconBlockHeader, Update},
        lightclient::LightClientState,
        sync_committee_rs::consensus_types::SyncCommittee,
    };
    use eth::consensus::MockConsensusRPC;
    use mockall::predicate;
    use relayer::verifier::MockVerifier;

    use crate::{Feeder, MAX_UPDATES_PER_LOOP};

    fn mock_dependencies(
        verifier_period: u64,
        beacon_period: u64,
    ) -> (
        MockVerifier,
        MockConsensusRPC,
        BeaconBlockHeader,
        LightClientState,
    ) {
        let mock_verifier = MockVerifier::new();
        let mock_consensus = MockConsensusRPC::new();

        let mut mock_header = BeaconBlockHeader::default();
        mock_header.slot = beacon_period * 256 * 32;

        let mut mock_state = LightClientState::default();
        mock_state.update_slot = verifier_period * 256 * 32;
        mock_state.next_sync_committee = None;

        (mock_verifier, mock_consensus, mock_header, mock_state)
    }

    #[tokio::test]
    async fn test_verifier_updated() {
        let (mut mock_verifier, mut mock_consensus, mock_header, mock_state) =
            mock_dependencies(1000, 1000);

        mock_consensus
            .expect_get_latest_beacon_block_header()
            .times(1)
            .returning(move || Ok(mock_header.clone()));

        mock_verifier
            .expect_get_state()
            .times(1)
            .returning(move || Ok(mock_state.clone()));

        let feeder = Feeder::new(mock_verifier, mock_consensus);

        let res = feeder.tick().await;
        assert_eq!(res, ()); // does not proceed if verifier slot == beacon slot
    }

    #[tokio::test]
    async fn test_verifier_on_bootstrap() {
        let verifier_period = 900;
        let beacon_period = 1000;
        let (mut mock_verifier, mut mock_consensus, mock_header, mock_state) =
            mock_dependencies(verifier_period, beacon_period);

        mock_consensus
            .expect_get_latest_beacon_block_header()
            .times(1)
            .returning(move || Ok(mock_header.clone()));

        let updates = vec![
            Update {
                signature_slot: 1,
                ..Update::default()
            },
            Update {
                signature_slot: 2,
                ..Update::default()
            },
        ];

        mock_verifier
            .expect_get_state()
            .times(1)
            .returning(move || Ok(mock_state.clone()));

        mock_verifier
            .expect_get_period()
            .times(2)
            .returning(|| Ok(0)); // ignore this value

        mock_verifier
            .expect_update()
            .with(predicate::eq(updates[0].clone()))
            .times(1)
            .returning(|_| Ok(()));
        mock_verifier
            .expect_update()
            .with(predicate::eq(updates[1].clone()))
            .times(1)
            .returning(|_| Ok(()));

        // will apply update from same period
        mock_consensus
            .expect_get_updates()
            .with(
                predicate::eq(verifier_period),
                predicate::eq(MAX_UPDATES_PER_LOOP),
            )
            .times(1)
            .returning(move |_, _| Ok(updates.clone()));

        let feeder = Feeder::new(mock_verifier, mock_consensus);

        let res = feeder.tick().await;
        assert_eq!(res, ());
    }

    #[tokio::test]
    async fn test_verifier_normal_update() {
        let verifier_period = 900;
        let beacon_period = 1000;
        let (mut mock_verifier, mut mock_consensus, mock_header, mut mock_state) =
            mock_dependencies(verifier_period, beacon_period);
        mock_state.next_sync_committee = Some(SyncCommittee::default());

        mock_consensus
            .expect_get_latest_beacon_block_header()
            .times(1)
            .returning(move || Ok(mock_header.clone()));

        let updates = vec![
            Update {
                signature_slot: 1,
                ..Update::default()
            },
            Update {
                signature_slot: 2,
                ..Update::default()
            },
        ];

        mock_verifier
            .expect_get_period()
            .times(2)
            .returning(|| Ok(0)); // ignore this value

        mock_verifier
            .expect_get_state()
            .times(1)
            .returning(move || Ok(mock_state.clone()));

        mock_verifier
            .expect_update()
            .with(predicate::eq(updates[0].clone()))
            .times(1)
            .returning(|_| Ok(()));
        mock_verifier
            .expect_update()
            .with(predicate::eq(updates[1].clone()))
            .times(1)
            .returning(|_| Ok(()));

        // will apply update from same period
        mock_consensus
            .expect_get_updates()
            .with(
                predicate::eq(verifier_period + 1),
                predicate::eq(MAX_UPDATES_PER_LOOP),
            )
            .times(1)
            .returning(move |_, _| Ok(updates.clone()));

        let feeder = Feeder::new(mock_verifier, mock_consensus);

        let res = feeder.tick().await;
        assert_eq!(res, ());
    }
}
