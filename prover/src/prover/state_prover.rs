use crate::prover::types::{GindexOrPath, ProofResponse};
use async_trait::async_trait;
use eyre::{anyhow, Result};
use mockall::automock;
use retri::{retry, BackoffSettings};

use super::utils::parse_path;

#[automock]
#[async_trait]
pub trait StateProverAPI: Sync + Send + 'static {
    async fn get_state_proof(
        &self,
        state_id: &str,
        gindex_or_path: &GindexOrPath,
    ) -> Result<ProofResponse>;
    async fn get_block_proof(
        &self,
        block_id: &str,
        gindex_or_path: GindexOrPath,
    ) -> Result<ProofResponse>;
}

#[derive(Clone)]
pub struct StateProver {
    rpc: String,
}

impl StateProver {
    pub fn new(rpc: String) -> Self {
        StateProver { rpc }
    }
}

#[automock]
#[async_trait]
impl StateProverAPI for StateProver {
    async fn get_state_proof(
        &self,
        state_id: &str,
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

        get(&req).await.or_else(|e| Err(anyhow!("Failed to get state proof: {:?} {:?}", req, e)))
    }

    async fn get_block_proof(
        &self,
        block_id: &str,
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

        get(&req).await.or_else(|e| Err(anyhow!("Failed to get block proof: {:?} {:?}", req, e)))
    }
}

async fn get(req: &str) -> Result<ProofResponse> {
    let bytes = retry(
        || async { Ok::<_, eyre::Report>(reqwest::get(req).await?.bytes().await?) },
        BackoffSettings::default(),
    )
    .await?;

    serde_json::from_slice::<ProofResponse>(&bytes)
        .or_else(|_| Err(anyhow!("Failed to parse response: {:?}", std::str::from_utf8(&bytes))))
}
