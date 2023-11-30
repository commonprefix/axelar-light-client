use crate::eth::consensus::CustomConsensusApi;
use async_trait::async_trait;
use consensus_types::consensus::BeaconBlockAlias;
use eyre::Result;
use serde_json;
use ssz_rs::Vector;
use std::fs::File;
use sync_committee_rs::{
    consensus_types::BeaconBlockHeader,
    constants::{Root, SLOTS_PER_HISTORICAL_ROOT},
};

pub struct MockCustomBeaconAPI;

impl MockCustomBeaconAPI {
    pub fn new() -> Self {
        MockCustomBeaconAPI {}
    }
}

#[async_trait]
impl CustomConsensusApi for MockCustomBeaconAPI {
    async fn get_block_roots_tree(
        &self,
        start_slot: u64,
    ) -> Result<Vector<Root, SLOTS_PER_HISTORICAL_ROOT>> {
        let file = File::open("./src/prover/testdata/block_roots.json").unwrap();
        let tree: Vector<Root, SLOTS_PER_HISTORICAL_ROOT> = serde_json::from_reader(file).unwrap();
        return Ok(tree);
    }

    async fn get_latest_beacon_block_header(&self) -> Result<BeaconBlockHeader> {
        unimplemented!();
    }

    async fn get_latest_beacon_block(&self) -> Result<BeaconBlockAlias> {
        unimplemented!();
    }
}
