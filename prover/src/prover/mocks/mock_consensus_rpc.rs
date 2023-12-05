use crate::eth::consensus::{CustomConsensusApi, EthBeaconAPI};
use async_trait::async_trait;
use consensus_types::consensus::{
    BeaconBlockAlias, Bootstrap, FinalityUpdate, OptimisticUpdate, Update,
};
use eyre::Result;
use serde_json;
use ssz_rs::Vector;
use std::fs::File;
use sync_committee_rs::{
    consensus_types::BeaconBlockHeader,
    constants::{Root, SLOTS_PER_HISTORICAL_ROOT},
};

pub struct MockConsensusRPC;

#[allow(dead_code)]
impl MockConsensusRPC {
    pub fn new() -> Self {
        MockConsensusRPC {}
    }
}

#[async_trait]
impl CustomConsensusApi for MockConsensusRPC {
    async fn get_block_roots_tree(
        &self,
        _start_slot: u64,
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

#[async_trait]
impl EthBeaconAPI for MockConsensusRPC {
    async fn get_beacon_block_header(&self, slot: u64) -> Result<BeaconBlockHeader> {
        let filename = format!("./src/prover/testdata/beacon_block_headers/{}.json", slot);
        let file = File::open(filename).unwrap();
        let res: BeaconBlockHeader = serde_json::from_reader(file).unwrap();
        Ok(res)
    }

    async fn get_beacon_block(&self, slot: u64) -> Result<BeaconBlockAlias> {
        let filename = format!("./src/prover/testdata/beacon_blocks/{}.json", slot);
        let file = File::open(filename).unwrap();
        let res: BeaconBlockAlias = serde_json::from_reader(file).unwrap();
        Ok(res)
    }

    async fn get_block_root(&self, _slot: u64) -> Result<Root> {
        unimplemented!();
    }

    async fn get_bootstrap(&self, _block_root: &'_ [u8]) -> Result<Bootstrap> {
        unimplemented!();
    }

    async fn get_updates(&self, _period: u64, _count: u8) -> Result<Vec<Update>> {
        unimplemented!();
    }

    async fn get_finality_update(&self) -> Result<FinalityUpdate> {
        unimplemented!();
    }

    async fn get_optimistic_update(&self) -> Result<OptimisticUpdate> {
        unimplemented!();
    }
}
