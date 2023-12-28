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

    async fn get(&self, req: &str) -> Result<ProofResponse> {
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
                "{}/state_proof?state_id={}&gindex={}",
                self.rpc, state_id, gindex
            ),
            GindexOrPath::Path(path) => format!(
                "{}/state_proof?state_id={}&path={}",
                self.rpc,
                state_id,
                parse_path(path)
            ),
        };

        self.get(&req)
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

        self.get(&req)
            .await
            .map_err(|e| anyhow!("Failed to get block proof: {:?} {:?}", req, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httptest::{matchers::*, responders::*, Expectation, Server};
    use ssz_rs::SszVariableOrIndex;

    fn setup_server_and_prover() -> (Server, StateProver) {
        let server = Server::run();
        let url = server.url("");
        let rpc = StateProver::new(url.to_string());
        (server, rpc)
    }

    #[tokio::test]
    async fn test_get_state_proof() {
        let (server, prover) = setup_server_and_prover();
        let expected_response = ProofResponse::default();
        let json_response = serde_json::to_string(&expected_response).unwrap();

        server.expect(
            Expectation::matching(all_of![
                request::query(url_decoded(contains(("state_id", "state_id")))),
                request::query(url_decoded(contains(("gindex", "1")))),
            ])
            .respond_with(status_code(200).body(json_response)),
        );

        let result = prover
            .get_state_proof("state_id", &GindexOrPath::Gindex(1))
            .await
            .unwrap();
        assert_eq!(result, expected_response);
    }

    #[tokio::test]
    async fn test_get_state_proof_with_path() {
        let (server, prover) = setup_server_and_prover();
        let expected_response = ProofResponse::default();
        let json_response = serde_json::to_string(&expected_response).unwrap();

        server.expect(
            Expectation::matching(all_of![
                request::query(url_decoded(contains(("state_id", "state_id")))),
                request::query(url_decoded(contains(("path", "test,lala")))),
            ])
            .respond_with(status_code(200).body(json_response)),
        );

        let path = vec![
            SszVariableOrIndex::Name("test"),
            SszVariableOrIndex::Name("lala"),
        ];
        let result = prover
            .get_state_proof("state_id", &GindexOrPath::Path(path))
            .await
            .unwrap();
        assert_eq!(result, expected_response);
    }

    #[tokio::test]
    async fn test_get_state_proof_error() {
        let (server, prover) = setup_server_and_prover();

        server.expect(
            Expectation::matching(all_of![
                request::query(url_decoded(contains(("state_id", "state_id")))),
                request::query(url_decoded(contains(("gindex", "1")))),
            ])
            .respond_with(status_code(400).body("Error")),
        );

        let result = prover
            .get_state_proof("state_id", &GindexOrPath::Gindex(1))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_block_proof() {
        let (server, prover) = setup_server_and_prover();
        let json_response = serde_json::to_string(&ProofResponse::default()).unwrap();

        server.expect(
            Expectation::matching(all_of![
                request::query(url_decoded(contains(("block_id", "block_id")))),
                request::query(url_decoded(contains(("gindex", "1")))),
            ])
            .respond_with(status_code(200).body(json_response)),
        );

        let result = prover
            .get_block_proof("block_id", GindexOrPath::Gindex(1))
            .await
            .unwrap();
        assert_eq!(result, ProofResponse::default());
    }

    #[tokio::test]
    async fn test_get_block_proof_with_path() {
        let (server, prover) = setup_server_and_prover();
        let json_response = serde_json::to_string(&ProofResponse::default()).unwrap();

        server.expect(
            Expectation::matching(all_of![
                request::query(url_decoded(contains(("block_id", "block_id")))),
                request::query(url_decoded(contains(("path", "test,lala")))),
            ])
            .respond_with(status_code(200).body(json_response)),
        );

        let path = vec![
            SszVariableOrIndex::Name("test"),
            SszVariableOrIndex::Name("lala"),
        ];
        let result = prover
            .get_block_proof("block_id", GindexOrPath::Path(path))
            .await
            .unwrap();
        assert_eq!(result, ProofResponse::default());
    }

    #[tokio::test]
    async fn test_get_block_proof_error() {
        let (server, prover) = setup_server_and_prover();

        server.expect(
            Expectation::matching(all_of![
                request::query(url_decoded(contains(("block_id", "block_id")))),
                request::query(url_decoded(contains(("gindex", "1")))),
            ])
            .respond_with(status_code(400)),
        );

        let result = prover
            .get_block_proof("block_id", GindexOrPath::Gindex(1))
            .await;

        assert!(result.is_err());
    }
}
