use crate::prover::types::{GindexOrPath, ProofResponse};
use async_trait::async_trait;
use eyre::{anyhow, Result};
use retri::{retry, BackoffSettings};
use serde::de::DeserializeOwned;

use super::utils::parse_path;

pub async fn get<R: DeserializeOwned>(req: &str) -> Result<R> {
    let bytes = retry(
        || async { Ok::<_, eyre::Report>(reqwest::get(req).await?.bytes().await?) },
        BackoffSettings::default(),
    )
    .await?;

    Ok(serde_json::from_slice::<R>(&bytes)?)
}

#[async_trait]
pub trait StateProverAPI {
    async fn get_state_proof(
        &self,
        state_id: &String,
        gindex_or_path: &GindexOrPath,
    ) -> Result<ProofResponse>;
    async fn get_block_proof(
        &self,
        block_id: &String,
        gindex_or_path: GindexOrPath,
    ) -> Result<ProofResponse>;
}

pub struct StateProver {
    rpc: String,
}

impl StateProver {
    pub fn new(rpc: &str) -> Self {
        StateProver {
            rpc: rpc.to_string(),
        }
    }
}

#[async_trait]
impl StateProverAPI for StateProver {
    async fn get_state_proof(
        &self,
        state_id: &String,
        gindex_or_path: &GindexOrPath,
    ) -> Result<ProofResponse> {
        let req = match gindex_or_path {
            GindexOrPath::Gindex(gindex) => format!(
                "{}/state_proof/?state_id={}&gindex={}",
                self.rpc, state_id, gindex
            ),
            GindexOrPath::Path(path) => format!(
                "{}/state_proof/?state_id={}&path={}",
                self.rpc,
                state_id,
                parse_path(path)
            ),
        };

        let res = get::<ProofResponse>(&req).await;
        if res.is_err() {
            return Err(anyhow!("Failed to get block proof: {:?} {:?}", req, res));
        }

        res
    }

    async fn get_block_proof(
        &self,
        block_id: &String,
        gindex_or_path: GindexOrPath,
    ) -> Result<ProofResponse> {
        let req = match gindex_or_path {
            GindexOrPath::Gindex(gindex) => format!(
                "{}/block_proof/?block_id={}&gindex={}",
                self.rpc, block_id, gindex
            ),
            GindexOrPath::Path(path) => format!(
                "{}/block_proof/?block_id={}&path={}",
                self.rpc,
                block_id,
                parse_path(&path)
            ),
        };

        let res = get::<ProofResponse>(&req).await;
        if res.is_err() {
            return Err(anyhow!("Failed to get block proof: {:?} {:?}", req, res));
        }

        res
    }
}
