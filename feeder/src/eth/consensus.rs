use std::cmp;

use crate::error::RpcError;
use crate::types::*;
use consensus_types::consensus::{
    BeaconStateType, Bootstrap, FinalityUpdate, OptimisticUpdate, Update,
};
use eyre::Result;
use reqwest;
use retri::{retry, BackoffSettings};
use serde::de::DeserializeOwned;
use sync_committee_rs::consensus_types::BeaconBlockHeader;

#[derive(Debug)]
pub struct ConsensusRPC {
    rpc: String,
}

async fn get<R: DeserializeOwned>(req: &str) -> Result<R> {
    let bytes = retry(
        || async { Ok::<_, eyre::Report>(reqwest::get(req).await?.bytes().await?) },
        BackoffSettings::default(),
    )
    .await?;

    Ok(serde_json::from_slice::<R>(&bytes)?)
}

#[allow(dead_code)]
impl ConsensusRPC {
    pub fn new(rpc: &str) -> Self {
        ConsensusRPC {
            rpc: rpc.to_string(),
        }
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

    pub async fn get_state(&self, slot: u64) -> Result<BeaconStateType> {
        let req = format!("{}/eth/v2/debug/beacon/states/{}", self.rpc, slot);

        // Setting the header for the request
        let client = reqwest::Client::new();
        let res = client
            .get(&req)
            .header("accept", "application/octet-stream")
            .send()
            .await
            .map_err(|e| RpcError::new("get_state", e))?;

        let state: BeaconStateType = ssz_rs::deserialize(&res.bytes().await?)?;

        return Ok(state);
    }

    pub async fn get_beacon_block_header(&self, slot: u64) -> Result<BeaconBlockHeader> {
        let req = format!("{}/eth/v1/beacon/headers/{}", self.rpc, slot);

        let res: BeaconBlockResponse = get(&req)
            .await
            .map_err(|e| RpcError::new("beacon_header", e))?;

        Ok(res.data.header.message)
    }
}
