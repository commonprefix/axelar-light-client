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

        get(&req)
            .await
            .map_err(|e| anyhow!("Failed to get state proof: {:?} {:?}", req, e))
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

        get(&req)
            .await
            .map_err(|e| anyhow!("Failed to get block proof: {:?} {:?}", req, e))
    }
}

async fn get(req: &str) -> Result<ProofResponse> {
    let bytes = retry(
        || async { Ok::<_, eyre::Report>(reqwest::get(req).await?.bytes().await?) },
        BackoffSettings::default(),
    )
    .await?;

    serde_json::from_slice::<ProofResponse>(&bytes).map_err(|_| {
        anyhow!(
            "Failed to parse response: {:?}",
            std::str::from_utf8(&bytes)
        )
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::prover::{
        state_prover::{MockStateProver, StateProverAPI},
        types::{GindexOrPath, ProofResponse},
    };
    use mockall::predicate::eq;

    #[tokio::test]
    async fn test_get_state_proof() {
        let mut mock = MockStateProver::new();

        let expected_response = Arc::new(ProofResponse::default());

        mock.expect_get_state_proof()
            .with(eq("state_id"), eq(GindexOrPath::Gindex(1)))
            .times(1)
            .returning({
                let expected_response = expected_response.clone();
                move |_, _| Ok((*expected_response).clone())
            });

        let result = mock
            .get_state_proof("state_id", &GindexOrPath::Gindex(1))
            .await
            .unwrap();
        assert_eq!(result, *expected_response);
    }

    #[tokio::test]
    async fn test_get_state_proof_error() {
        let mut mock = MockStateProver::new();

        // Simulate an error response
        let error_message = "State proof error";
        mock.expect_get_state_proof()
            .with(eq("state_id"), eq(GindexOrPath::Gindex(1)))
            .times(1)
            .returning(move |_, _| Err(eyre::eyre!(error_message)));

        let result = mock
            .get_state_proof("state_id", &GindexOrPath::Gindex(1))
            .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), error_message);
    }

    #[tokio::test]
    async fn test_get_block_proof() {
        let mut mock = MockStateProver::new();

        let expected_response = Arc::new(ProofResponse::default());

        mock.expect_get_block_proof()
            .with(eq("block_id"), eq(GindexOrPath::Gindex(1)))
            .times(1)
            .returning({
                let expected_response = expected_response.clone();
                move |_, _| Ok((*expected_response).clone())
            });

        let result = mock
            .get_block_proof("block_id", GindexOrPath::Gindex(1))
            .await
            .unwrap();
        assert_eq!(result, *expected_response);
    }

    #[tokio::test]
    async fn test_get_block_proof_error() {
        let mut mock = MockStateProver::new();

        // Simulate an error response
        let error_message = "Block proof error";
        mock.expect_get_block_proof()
            .with(eq("block_id"), eq(GindexOrPath::Gindex(1)))
            .times(1)
            .returning(move |_, _| Err(eyre::eyre!(error_message)));

        // Test the function and expect an error
        let result = mock
            .get_block_proof("block_id", GindexOrPath::Gindex(1))
            .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), error_message);
    }
}
