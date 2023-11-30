use std::{cmp, time::Instant};

use crate::error::RpcError;
use crate::eth::utils::get;
use crate::types::*;
use consensus_types::consensus::{
    BeaconBlockAlias, Bootstrap, FinalityUpdate, OptimisticUpdate, Update,
};
use eyre::Result;
use futures::future;
use ssz_rs::Node;
use sync_committee_rs::{consensus_types::BeaconBlockHeader, constants::Root};

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

    pub async fn fetch_block_roots(
        &self,
        start_slot: u64,
        count: usize,
    ) -> Result<Vec<Option<Root>>> {
        const BATCH_SIZE: usize = 1000;

        let mut block_roots = vec![];

        for batch_start in (0..count).step_by(BATCH_SIZE) {
            let batch_end = std::cmp::min(batch_start + BATCH_SIZE, count);
            let mut futures = Vec::new();

            for i in batch_start..batch_end {
                let future = self.get_block_root(start_slot + i as u64);
                futures.push(future);
            }

            // Wait for all futures in the batch to resolve
            let resolved = future::join_all(futures).await;
            println!("Resolved batch {}", batch_start / BATCH_SIZE);

            // Process resolved futures and add to the main vector
            for res in resolved {
                match res {
                    Ok(block_root) => block_roots.push(Some(block_root)),
                    Err(_) => block_roots.push(None),
                }
            }
        }

        Ok(block_roots)
    }

    pub async fn get_block_root(&self, slot: u64) -> Result<Root> {
        let req = format!("{}/eth/v1/beacon/blocks/{}/root", self.rpc, slot);

        let res: BlockRootResponse = get(&req)
            .await
            .map_err(|e| RpcError::new("block_root", e))?;

        println!("Requesting for slot {}", slot);

        Ok(res.data.root)
    }

    pub async fn get_bootstrap(&self, block_root: &'_ [u8]) -> Result<Bootstrap> {
        let root_hex = hex::encode(block_root);
        let req = format!(
            "{}/eth/v1/beacon/light_client/bootstrap/0x{}",
            self.rpc, root_hex
        );

        let res: BootstrapResponse = get(&req).await.map_err(|e| RpcError::new("bootstrap", e))?;

        Ok(res.data)
    }

    pub async fn get_updates(&self, period: u64, count: u8) -> Result<Vec<Update>> {
        let count = cmp::min(count, 10);
        let req = format!(
            "{}/eth/v1/beacon/light_client/updates?start_period={}&count={}",
            self.rpc, period, count
        );

        let res: UpdateResponse = get(&req).await.map_err(|e| RpcError::new("updates", e))?;

        Ok(res.into_iter().map(|d| d.data).collect())
    }

    pub async fn get_finality_update(&self) -> Result<FinalityUpdate> {
        let req = format!("{}/eth/v1/beacon/light_client/finality_update", self.rpc);

        let res: FinalityUpdateData = get(&req).await.map_err(|e| RpcError::new("updates", e))?;

        Ok(res.data)
    }

    pub async fn get_optimistic_update(&self) -> Result<OptimisticUpdate> {
        let req = format!("{}/eth/v1/beacon/light_client/optimistic_update", self.rpc);

        let res: OptimisticUpdateData = get(&req).await.map_err(|e| RpcError::new("updates", e))?;

        Ok(res.data)
    }

    pub async fn get_beacon_block_header(&self, slot: u64) -> Result<BeaconBlockHeader> {
        let req = format!("{}/eth/v1/beacon/headers/{}", self.rpc, slot);

        let res: BeaconBlockHeaderResponse = get(&req)
            .await
            .map_err(|e| RpcError::new("beacon_header", e))?;

        Ok(res.data.header.message)
    }

    pub async fn get_latest_beacon_block_header(&self) -> Result<BeaconBlockHeader> {
        let req = format!("{}/eth/v1/beacon/headers/head", self.rpc);

        let res: BeaconBlockHeaderResponse = get(&req)
            .await
            .map_err(|e| RpcError::new("latest_beacon_header", e))?;

        Ok(res.data.header.message)
    }

    pub async fn get_beacon_block(&self, slot: u64) -> Result<BeaconBlockAlias> {
        let req = format!("{}/eth/v2/beacon/blocks/{}", self.rpc, slot);

        let res: BeaconBlockResponse = get(&req)
            .await
            .map_err(|e| RpcError::new("beacon_block", e))?;

        Ok(res.data.message)
    }

    pub async fn get_latest_beacon_block(&self) -> Result<BeaconBlockAlias> {
        let req = format!("{}/eth/v1/beacon/blocks/7834081", self.rpc);

        let res: BeaconBlockResponse = get(&req)
            .await
            .map_err(|e| RpcError::new("latest_beacon_block", e))?;

        println!("Got latest beacon block {:#?}", res);

        Ok(res.data.message)
    }
}
