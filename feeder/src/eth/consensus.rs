use std::cmp;

use crate::error::RpcError;
use crate::types::*;
use eyre::Result;
use reqwest;
use retri::{retry, BackoffSettings};
use serde::de::DeserializeOwned;
use types::consensus::{Bootstrap, Update};

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
}
