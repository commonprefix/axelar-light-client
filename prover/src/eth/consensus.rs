use crate::error::RpcError;
use crate::eth::utils::get;
use crate::types::*;
use async_trait::async_trait;
use consensus_types::consensus::{
    BeaconBlockAlias, Bootstrap, FinalityUpdate, OptimisticUpdate, Update,
};
use eyre::Result;
use futures::future;
use ssz_rs::Vector;
use std::cmp;
use sync_committee_rs::{
    consensus_types::BeaconBlockHeader,
    constants::{Root, SLOTS_PER_HISTORICAL_ROOT},
};

#[async_trait]
pub trait EthBeaconAPI {
    async fn get_block_root(&self, slot: u64) -> Result<Root>;
    async fn get_bootstrap(&self, block_root: &'_ [u8]) -> Result<Bootstrap>;
    async fn get_updates(&self, period: u64, count: u8) -> Result<Vec<Update>>;
    async fn get_finality_update(&self) -> Result<FinalityUpdate>;
    async fn get_optimistic_update(&self) -> Result<OptimisticUpdate>;
    async fn get_beacon_block_header(&self, slot: u64) -> Result<BeaconBlockHeader>;
    async fn get_beacon_block(&self, slot: u64) -> Result<BeaconBlockAlias>;
}

#[async_trait]
pub trait CustomConsensusApi {
    async fn get_block_roots_tree(
        &self,
        start_slot: u64,
    ) -> Result<Vector<Root, SLOTS_PER_HISTORICAL_ROOT>>;
    async fn get_latest_beacon_block_header(&self) -> Result<BeaconBlockHeader>;
    async fn get_latest_beacon_block(&self) -> Result<BeaconBlockAlias>;
}

#[derive(Debug)]
pub struct ConsensusRPC {
    rpc: String,
}

#[allow(dead_code)]
impl ConsensusRPC {
    pub fn new(rpc: &str) -> Self {
        ConsensusRPC {
            rpc: rpc.to_string(),
        }
    }
}

#[async_trait]
impl EthBeaconAPI for ConsensusRPC {
    async fn get_block_root(&self, slot: u64) -> Result<Root> {
        let req = format!("{}/eth/v1/beacon/blocks/{}/root", self.rpc, slot);

        let res: BlockRootResponse = get(&req)
            .await
            .map_err(|e| RpcError::new("block_root", e))?;

        Ok(res.data.root)
    }

    async fn get_bootstrap(&self, block_root: &'_ [u8]) -> Result<Bootstrap> {
        let root_hex = hex::encode(block_root);
        let req = format!(
            "{}/eth/v1/beacon/light_client/bootstrap/0x{}",
            self.rpc, root_hex
        );

        let res: BootstrapResponse = get(&req).await.map_err(|e| RpcError::new("bootstrap", e))?;

        Ok(res.data)
    }

    async fn get_updates(&self, period: u64, count: u8) -> Result<Vec<Update>> {
        let count = cmp::min(count, 10);
        let req = format!(
            "{}/eth/v1/beacon/light_client/updates?start_period={}&count={}",
            self.rpc, period, count
        );

        let res: UpdateResponse = get(&req).await.map_err(|e| RpcError::new("updates", e))?;

        Ok(res.into_iter().map(|d| d.data).collect())
    }

    async fn get_finality_update(&self) -> Result<FinalityUpdate> {
        let req = format!("{}/eth/v1/beacon/light_client/finality_update", self.rpc);

        let res: FinalityUpdateData = get(&req).await.map_err(|e| RpcError::new("updates", e))?;

        Ok(res.data)
    }

    async fn get_optimistic_update(&self) -> Result<OptimisticUpdate> {
        let req = format!("{}/eth/v1/beacon/light_client/optimistic_update", self.rpc);

        let res: OptimisticUpdateData = get(&req).await.map_err(|e| RpcError::new("updates", e))?;

        Ok(res.data)
    }

    async fn get_beacon_block_header(&self, slot: u64) -> Result<BeaconBlockHeader> {
        let req = format!("{}/eth/v1/beacon/headers/{}", self.rpc, slot);

        let res: BeaconBlockHeaderResponse = get(&req)
            .await
            .map_err(|e| RpcError::new("beacon_header", e))?;

        Ok(res.data.header.message)
    }
    async fn get_beacon_block(&self, slot: u64) -> Result<BeaconBlockAlias> {
        let req = format!("{}/eth/v2/beacon/blocks/{}", self.rpc, slot);

        let res: BeaconBlockResponse = get(&req)
            .await
            .map_err(|e| RpcError::new("beacon_block", e))?;

        Ok(res.data.message)
    }
}

#[async_trait]
impl CustomConsensusApi for ConsensusRPC {
    async fn get_latest_beacon_block(&self) -> Result<BeaconBlockAlias> {
        let req = format!("{}/eth/v1/beacon/blocks/7834081", self.rpc);

        let res: BeaconBlockResponse = get(&req)
            .await
            .map_err(|e| RpcError::new("latest_beacon_block", e))?;

        println!("Got latest beacon block {:#?}", res);

        Ok(res.data.message)
    }

    async fn get_latest_beacon_block_header(&self) -> Result<BeaconBlockHeader> {
        let req = format!("{}/eth/v1/beacon/headers/head", self.rpc);

        let res: BeaconBlockHeaderResponse = get(&req)
            .await
            .map_err(|e| RpcError::new("latest_beacon_header", e))?;

        Ok(res.data.header.message)
    }

    async fn get_block_roots_tree(
        &self,
        start_slot: u64,
    ) -> Result<Vector<Root, SLOTS_PER_HISTORICAL_ROOT>> {
        const BATCH_SIZE: usize = 1000;

        let mut block_roots = vec![];

        for batch_start in (0..SLOTS_PER_HISTORICAL_ROOT).step_by(BATCH_SIZE) {
            let batch_end = std::cmp::min(batch_start + BATCH_SIZE, SLOTS_PER_HISTORICAL_ROOT);
            let mut futures = Vec::new();

            for i in batch_start..batch_end {
                let future = self.get_block_root(start_slot + i as u64);
                futures.push(future);
            }

            let resolved = future::join_all(futures).await;
            println!("Resolved batch {}", batch_start / BATCH_SIZE);

            // Block root tree includes the last block root if no block was minted in the slot
            for block_root in resolved.iter() {
                match block_root {
                    Ok(block_root) => block_roots.push(*block_root),
                    Err(_) => block_roots.push(*block_roots.last().unwrap()),
                }
            }
        }

        let block_roots = Vector::<Root, SLOTS_PER_HISTORICAL_ROOT>::try_from(block_roots).unwrap();

        Ok(block_roots)
    }
}
