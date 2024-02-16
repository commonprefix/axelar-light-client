use crate::{error::RPCError, types::*};
use async_trait::async_trait;
use futures::future;
use mockall::automock;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};
use std::{cmp, time::Duration};
use types::consensus::{BeaconBlockAlias, Bootstrap, FinalityUpdate, OptimisticUpdate, Update};
use types::ssz_rs::Vector;
use types::sync_committee_rs::{
    consensus_types::BeaconBlockHeader,
    constants::{Root, SLOTS_PER_HISTORICAL_ROOT},
};

/// The thin wrapper around the BeaconAPI overloaded with custom methods
#[async_trait]
pub trait EthBeaconAPI: Sync + Send + 'static {
    /// Get the block root for a given slot.
    async fn get_block_root(&self, slot: u64) -> Result<Root, RPCError>;
    /// Get the light client bootstrap for a given block root.
    async fn get_bootstrap(&self, block_root: &'_ [u8]) -> Result<Bootstrap, RPCError>;
    /// Get the light client updates for a given period range.
    async fn get_updates(&self, period: u64, count: u8) -> Result<Vec<Update>, RPCError>;
    /// Get the latest light client finality update.
    async fn get_finality_update(&self) -> Result<FinalityUpdate, RPCError>;
    /// Get the latest light client optimistic update.
    async fn get_optimistic_update(&self) -> Result<OptimisticUpdate, RPCError>;
    /// Get the beacon block header for a given slot.
    async fn get_latest_beacon_block_header(&self) -> Result<BeaconBlockHeader, RPCError>;
    /// Get the beacon block header for a given slot.
    async fn get_beacon_block_header(&self, slot: u64) -> Result<BeaconBlockHeader, RPCError>;
    /// Get the beacon block for a given slot.
    async fn get_beacon_block(&self, slot: u64) -> Result<BeaconBlockAlias, RPCError>;
    /// Get the block roots tree for a given period. This will return a vector of length
    /// `SLOTS_PER_HISTORICAL_ROOT`. If any of the block roots fail to resolve,
    /// the previous root will be used instead. It uses the Block Roots Archive.
    async fn get_block_roots_for_period(
        &self,
        period: u64,
    ) -> Result<Vector<Root, SLOTS_PER_HISTORICAL_ROOT>, RPCError>;
}

/// A client for interacting with the Ethereum consensus layer.
pub struct ConsensusRPC {
    rpc: String,
    block_roots_rpc: String,
    client: ClientWithMiddleware,
}

#[allow(dead_code)]
impl ConsensusRPC {
    /// Create a new consensus rpc client. The client is configured with a
    /// retry policy that will retry transient errors up to 3 times.
    pub fn new(rpc: String, block_roots_rpc: String, config: EthConfig) -> Self {
        let retry_policy =
            ExponentialBackoff::builder().build_with_max_retries(config.rpc_max_retries as u32);

        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .connect_timeout(Duration::from_secs(config.timeout_secs))
            .timeout(Duration::from_secs(60))
            .build()
            .unwrap();

        let client = ClientBuilder::new(client)
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();

        ConsensusRPC {
            rpc,
            block_roots_rpc,
            client,
        }
    }
}

#[automock]
#[async_trait]
impl EthBeaconAPI for ConsensusRPC {
    async fn get_block_root(&self, slot: u64) -> Result<Root, RPCError> {
        let req = format!("{}/eth/v1/beacon/blocks/{}/root", self.rpc, slot);

        let res = self
            .client
            .get(&req)
            .send()
            .await
            .map_err(|e| RPCError::RequestError(e.to_string()))?;

        if res.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RPCError::NotFoundError(slot.to_string()));
        }
        if res.status() != reqwest::StatusCode::OK {
            return Err(RPCError::RequestError(format!(
                "Unexpected status code: {}",
                res.status()
            )));
        }

        let data = res
            .json::<BlockRootResponse>()
            .await
            .map_err(|e| RPCError::DeserializationError(req, e.to_string()))?;

        Ok(data.data.root)
    }

    async fn get_bootstrap(&self, block_root: &'_ [u8]) -> Result<Bootstrap, RPCError> {
        let root_hex = hex::encode(block_root);
        let req = format!(
            "{}/eth/v1/beacon/light_client/bootstrap/0x{}",
            self.rpc, root_hex
        );

        let res = self
            .client
            .get(&req)
            .send()
            .await
            .map_err(|e| RPCError::RequestError(e.to_string()))?;

        if res.status() != reqwest::StatusCode::OK {
            return Err(RPCError::RequestError(format!(
                "Unexpected status code: {}",
                res.status()
            )));
        }

        let data = res
            .json::<BootstrapResponse>()
            .await
            .map_err(|e| RPCError::DeserializationError(req, e.to_string()))?;

        Ok(data.data)
    }

    async fn get_updates(&self, period: u64, count: u8) -> Result<Vec<Update>, RPCError> {
        let count = cmp::min(count, 10);
        let req = format!(
            "{}/eth/v1/beacon/light_client/updates?start_period={}&count={}",
            self.rpc, period, count
        );

        let res = self
            .client
            .get(&req)
            .send()
            .await
            .map_err(|e| RPCError::RequestError(e.to_string()))?;

        if res.status() != reqwest::StatusCode::OK {
            return Err(RPCError::RequestError(format!(
                "Unexpected status code: {}",
                res.status()
            )));
        }

        let data = res
            .json::<Vec<UpdateData>>()
            .await
            .map_err(|e| RPCError::DeserializationError(req, e.to_string()))?;

        Ok(data.into_iter().map(|d| d.data).collect())
    }

    async fn get_finality_update(&self) -> Result<FinalityUpdate, RPCError> {
        let req = format!("{}/eth/v1/beacon/light_client/finality_update", self.rpc);

        let res = self
            .client
            .get(&req)
            .send()
            .await
            .map_err(|e| RPCError::RequestError(e.to_string()))?;

        if res.status() != reqwest::StatusCode::OK {
            return Err(RPCError::RequestError(format!(
                "Unexpected status code: {}",
                res.status()
            )));
        }

        let data = res
            .json::<FinalityUpdateData>()
            .await
            .map_err(|e| RPCError::DeserializationError(req, e.to_string()))?;

        Ok(data.data)
    }

    async fn get_optimistic_update(&self) -> Result<OptimisticUpdate, RPCError> {
        let req = format!("{}/eth/v1/beacon/light_client/optimistic_update", self.rpc);

        let res = self
            .client
            .get(&req)
            .send()
            .await
            .map_err(|e| RPCError::RequestError(e.to_string()))?;

        if res.status() != reqwest::StatusCode::OK {
            return Err(RPCError::RequestError(format!(
                "Unexpected status code: {}",
                res.status()
            )));
        }

        let data = res
            .json::<OptimisticUpdateData>()
            .await
            .map_err(|e| RPCError::DeserializationError(req, e.to_string()))?;

        Ok(data.data)
    }

    async fn get_latest_beacon_block_header(&self) -> Result<BeaconBlockHeader, RPCError> {
        let req = format!("{}/eth/v1/beacon/headers/head", self.rpc);

        let res = self
            .client
            .get(&req)
            .send()
            .await
            .map_err(|e| RPCError::RequestError(e.to_string()))?;

        if res.status() != reqwest::StatusCode::OK {
            return Err(RPCError::RequestError(format!(
                "Unexpected status code: {}",
                res.status()
            )));
        }

        let data = res
            .json::<BeaconBlockHeaderResponse>()
            .await
            .map_err(|e| RPCError::DeserializationError(req, e.to_string()))?;

        Ok(data.data.header.message)
    }

    async fn get_beacon_block_header(&self, slot: u64) -> Result<BeaconBlockHeader, RPCError> {
        let req = format!("{}/eth/v1/beacon/headers/{}", self.rpc, slot);

        let res = self
            .client
            .get(&req)
            .send()
            .await
            .map_err(|e| RPCError::RequestError(e.to_string()))?;

        if res.status() != reqwest::StatusCode::OK {
            return Err(RPCError::RequestError(format!(
                "Unexpected status code: {}",
                res.status()
            )));
        }

        let data = res
            .json::<BeaconBlockHeaderResponse>()
            .await
            .map_err(|e| RPCError::DeserializationError(req, e.to_string()))?;

        Ok(data.data.header.message)
    }

    async fn get_beacon_block(&self, slot: u64) -> Result<BeaconBlockAlias, RPCError> {
        let req = format!("{}/eth/v2/beacon/blocks/{}", self.rpc, slot);

        let res = self
            .client
            .get(&req)
            .send()
            .await
            .map_err(|e| RPCError::RequestError(e.to_string()))?;

        if res.status() != reqwest::StatusCode::OK {
            return Err(RPCError::RequestError(format!(
                "Unexpected status code: {}",
                res.status()
            )));
        }

        let data = res
            .json::<BeaconBlockResponse>()
            .await
            .map_err(|e| RPCError::DeserializationError(req, e.to_string()))?;

        Ok(data.data.message)
    }

    async fn get_block_roots_for_period(
        &self,
        period: u64,
    ) -> Result<Vector<Root, SLOTS_PER_HISTORICAL_ROOT>, RPCError> {
        let req = format!("{}/block_summary?period={}", self.block_roots_rpc, period);

        let res = self
            .client
            .get(&req)
            .send()
            .await
            .map_err(|e| RPCError::RequestError(e.to_string()))?;

        if res.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RPCError::NotFoundError(period.to_string()));
        }

        if res.status() != reqwest::StatusCode::OK {
            return Err(RPCError::RequestError(format!(
                "Unexpected status code: {}",
                res.status()
            )));
        }

        let response = res
            .json::<BlockRootsArchiveResponse>()
            .await
            .map_err(|e| RPCError::DeserializationError(req, e.to_string()))?;

        Ok(response.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httptest::{
        matchers::{request::query, *},
        responders::*,
        Expectation, Server,
    };

    fn setup_server_and_rpc() -> (Server, ConsensusRPC) {
        let server = Server::run();
        let url = server.url("");
        let rpc = ConsensusRPC::new(url.to_string(), url.to_string(), EthConfig::default());
        (server, rpc)
    }
    #[tokio::test]
    async fn test_get_block_root() {
        let (server, rpc) = setup_server_and_rpc();
        let result = BlockRootResponse::default();
        let json_res = serde_json::to_string(&result).unwrap();

        server.expect(
            Expectation::matching(request::path(matches("/eth/v1/beacon/blocks/12345/root")))
                .respond_with(status_code(200).body(json_res)),
        );

        let result = rpc.get_block_root(12345).await;
        assert_eq!(result.unwrap(), Root::default());
    }

    #[tokio::test]
    async fn test_get_updates() {
        let (server, rpc) = setup_server_and_rpc();
        let expected_updates = vec![Update::default(); 3];
        let period = 10u64;
        let count = 3u8;

        let response = expected_updates
            .iter()
            .map(|u| UpdateData { data: u.clone() })
            .collect::<Vec<_>>();
        let json_res = serde_json::to_string(&response).unwrap();

        server.expect(
            Expectation::matching(all_of(vec![
                Box::new(request::path(matches(
                    "/eth/v1/beacon/light_client/updates",
                ))),
                Box::new(request::query(url_decoded(contains((
                    "count",
                    count.to_string(),
                ))))),
                Box::new(request::query(url_decoded(contains((
                    "start_period",
                    period.to_string(),
                ))))),
            ]))
            .respond_with(status_code(200).body(json_res)),
        );

        let result = rpc.get_updates(period, count).await;
        assert_eq!(result.unwrap(), expected_updates);

        server.expect(Expectation::matching(any()).respond_with(status_code(404)));

        let res: Result<Vec<Update>, _> = rpc.get_updates(period, count).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_get_finality_update() {
        let (server, rpc) = setup_server_and_rpc();
        let expected_update = FinalityUpdate::default();

        let response = FinalityUpdateData {
            data: expected_update.clone(),
        };
        let json_res = serde_json::to_string(&response).unwrap();

        server.expect(
            Expectation::matching(request::path(matches(
                "/eth/v1/beacon/light_client/finality_update",
            )))
            .respond_with(status_code(200).body(json_res)),
        );

        let result = rpc.get_finality_update().await;
        assert_eq!(result.unwrap(), expected_update);

        server.expect(Expectation::matching(any()).respond_with(status_code(404)));

        let res: Result<FinalityUpdate, _> = rpc.get_finality_update().await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_get_optimistic_update() {
        let (server, rpc) = setup_server_and_rpc();
        let expected_update = OptimisticUpdate::default();

        let response = OptimisticUpdateData {
            data: expected_update.clone(),
        };
        let json_res = serde_json::to_string(&response).unwrap();

        server.expect(
            Expectation::matching(request::path(matches(
                "/eth/v1/beacon/light_client/optimistic_update",
            )))
            .respond_with(status_code(200).body(json_res)),
        );

        let result = rpc.get_optimistic_update().await;
        assert_eq!(result.unwrap(), expected_update);

        server.expect(Expectation::matching(any()).respond_with(status_code(404)));

        let res: Result<OptimisticUpdate, _> = rpc.get_optimistic_update().await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_get_beacon_block_header() {
        let (server, rpc) = setup_server_and_rpc();

        let slot = 12345;
        let expected_header = BeaconBlockHeader::default();
        let response = BeaconBlockHeaderResponse {
            data: BeaconBlockHeaderContainer {
                header: BeaconBlockHeaderMessage {
                    message: expected_header.clone(),
                },
            },
        };
        let json_res = serde_json::to_string(&response).unwrap();

        server.expect(
            Expectation::matching(request::path(matches(format!(
                "/eth/v1/beacon/headers/{}",
                slot
            ))))
            .respond_with(status_code(200).body(json_res)),
        );

        let result = rpc.get_beacon_block_header(slot).await;
        assert_eq!(result.unwrap(), expected_header);

        server.expect(Expectation::matching(any()).respond_with(status_code(404)));

        let res: Result<BeaconBlockHeader, _> = rpc.get_beacon_block_header(slot).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_get_latest_beacon_block_header() {
        let (server, rpc) = setup_server_and_rpc();

        let expected_header = BeaconBlockHeader::default();
        let response = BeaconBlockHeaderResponse {
            data: BeaconBlockHeaderContainer {
                header: BeaconBlockHeaderMessage {
                    message: expected_header.clone(),
                },
            },
        };
        let json_res = serde_json::to_string(&response).unwrap();

        server.expect(
            Expectation::matching(request::path(matches("/eth/v1/beacon/headers/head")))
                .respond_with(status_code(200).body(json_res)),
        );

        let result = rpc.get_latest_beacon_block_header().await;
        assert_eq!(result.unwrap(), expected_header);

        server.expect(Expectation::matching(any()).respond_with(status_code(404)));

        let res: Result<BeaconBlockHeader, _> = rpc.get_latest_beacon_block_header().await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_get_bootstrap() {
        let (server, rpc) = setup_server_and_rpc();

        let expected_bootstrap = Bootstrap::default();
        let block_root = vec![0u8; 32]; // Mock block root

        let response = BootstrapResponse {
            data: expected_bootstrap.clone(),
        };
        let json_res = serde_json::to_string(&response).unwrap();

        server.expect(
            Expectation::matching(request::path(matches(format!(
                "/eth/v1/beacon/light_client/bootstrap/0x{}",
                hex::encode(block_root.clone())
            ))))
            .respond_with(status_code(200).body(json_res)),
        );

        let result = rpc.get_bootstrap(&block_root).await;
        assert_eq!(result.unwrap(), expected_bootstrap);

        server.expect(Expectation::matching(any()).respond_with(status_code(404)));

        let res: Result<Bootstrap, _> = rpc.get_bootstrap(&block_root).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_get_beacon_block() {
        let (server, rpc) = setup_server_and_rpc();

        let slot = 12345;
        let expected_block = BeaconBlockAlias::default();
        let response = BeaconBlockResponse {
            data: BeaconBlockContainer {
                message: expected_block.clone(),
            },
        };
        let json_res = serde_json::to_string(&response).unwrap();

        server.expect(
            Expectation::matching(request::path(matches(format!(
                "/eth/v2/beacon/blocks/{}",
                slot
            ))))
            .respond_with(status_code(200).body(json_res)),
        );

        let result = rpc.get_beacon_block(slot).await;
        assert_eq!(result.unwrap(), expected_block);

        server.expect(Expectation::matching(any()).respond_with(status_code(404)));

        let res: Result<BeaconBlockAlias, _> = rpc.get_beacon_block(slot).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_get_block_roots_for_period() {
        let (server, rpc) = setup_server_and_rpc();

        let response = BlockRootsArchiveResponse::default();
        let json_res = serde_json::to_string(&response).unwrap();

        let period = 1000;
        server.expect(
            Expectation::matching(all_of(vec![
                Box::new(request::path(matches("block_summary"))),
                Box::new(request::query(url_decoded(contains((
                    "period",
                    period.to_string(),
                ))))),
            ]))
            .respond_with(status_code(200).body(json_res)),
        );

        let result = rpc.get_block_roots_for_period(period).await;
        assert_eq!(result.unwrap(), response.data);

        server.expect(Expectation::matching(any()).respond_with(status_code(404)));

        let res: Result<Vector<Root, 8192>, _> = rpc.get_block_roots_for_period(period).await;
        assert!(res.is_err());
    }
}
