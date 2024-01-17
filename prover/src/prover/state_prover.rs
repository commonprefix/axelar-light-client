use crate::prover::types::{GindexOrPath, ProofResponse};
use async_trait::async_trait;
use mockall::automock;

use super::{errors::StateProverError, utils::parse_path};

/// A wrapper around the state [`prover`](https://github.com/commonprefix/state-prover)
#[automock]
#[async_trait]
pub trait StateProverAPI: Sync + Send + 'static {
    /// Fetches a proof from a specific g_index or a path to the beacon state of a specific block.
    async fn get_state_proof(
        &self,
        state_id: &str,
        gindex_or_path: &GindexOrPath,
    ) -> Result<ProofResponse, StateProverError>;

    /// Fetches a proof from a specific g_index or a path to the beacon root of a specific block.
    async fn get_block_proof(
        &self,
        block_id: &str,
        gindex_or_path: GindexOrPath,
    ) -> Result<ProofResponse, StateProverError>;
}

#[derive(Clone)]
pub struct StateProver {
    network: String,
    rpc: String,
}

impl StateProver {
    pub fn new(network: String, rpc: String) -> Self {
        StateProver { network, rpc }
    }

    async fn get(&self, req: &str) -> Result<ProofResponse, StateProverError> {
        let response = reqwest::get(req)
            .await
            .map_err(StateProverError::NetworkError)?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(StateProverError::NotFoundError(req.into()));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(StateProverError::NetworkError)?;

        serde_json::from_slice(&bytes).map_err(StateProverError::SerializationError)
    }
}

#[automock]
#[async_trait]
impl StateProverAPI for StateProver {
    async fn get_state_proof(
        &self,
        state_id: &str,
        gindex_or_path: &GindexOrPath,
    ) -> Result<ProofResponse, StateProverError> {
        let req = match gindex_or_path {
            GindexOrPath::Gindex(gindex) => format!(
                "{}/state_proof?state_id={}&gindex={}&network={}",
                self.rpc, state_id, gindex, self.network
            ),
            GindexOrPath::Path(path) => format!(
                "{}/state_proof?state_id={}&path={}&network={}",
                self.rpc,
                state_id,
                parse_path(path),
                self.network
            ),
        };

        self.get(&req).await
    }

    async fn get_block_proof(
        &self,
        block_id: &str,
        gindex_or_path: GindexOrPath,
    ) -> Result<ProofResponse, StateProverError> {
        let req = match gindex_or_path {
            GindexOrPath::Gindex(gindex) => format!(
                "{}/block_proof/?block_id={}&gindex={}&network={}",
                self.rpc, block_id, gindex, self.network
            ),
            GindexOrPath::Path(path) => format!(
                "{}/block_proof/?block_id={}&path={}&network={}",
                self.rpc,
                block_id,
                parse_path(&path),
                self.network
            ),
        };

        self.get(&req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus_types::ssz_rs::SszVariableOrIndex;
    use httptest::{matchers::*, responders::*, Expectation, Server};

    fn setup_server_and_prover() -> (Server, StateProver) {
        let server = Server::run();
        let url = server.url("");
        let rpc = StateProver::new("mainnet".to_string(), url.to_string());
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
