use crate::{error::RPCError, types::*};
use async_trait::async_trait;
use futures::future;
use mockall::automock;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};
use ssz_rs::Vector;
use std::{cmp, time::Duration};
use sync_committee_rs::{
    consensus_types::BeaconBlockHeader,
    constants::{Root, SLOTS_PER_HISTORICAL_ROOT},
};
use types::consensus::{BeaconBlockAlias, Bootstrap, FinalityUpdate, OptimisticUpdate, Update};

#[async_trait]
pub trait EthBeaconAPI: Sync + Send + 'static {
    async fn get_block_root(&self, slot: u64) -> Result<Root, RPCError>;
    async fn get_bootstrap(&self, block_root: &'_ [u8]) -> Result<Bootstrap, RPCError>;
    async fn get_updates(&self, period: u64, count: u8) -> Result<Vec<Update>, RPCError>;
    async fn get_finality_update(&self) -> Result<FinalityUpdate, RPCError>;
    async fn get_optimistic_update(&self) -> Result<OptimisticUpdate, RPCError>;
    async fn get_beacon_block_header(&self, slot: u64) -> Result<BeaconBlockHeader, RPCError>;
    async fn get_beacon_block(&self, slot: u64) -> Result<BeaconBlockAlias, RPCError>;
    async fn get_block_roots_tree(
        &self,
        start_slot: u64,
    ) -> Result<Vector<Root, SLOTS_PER_HISTORICAL_ROOT>, RPCError>;
}

#[derive(Clone)]
pub struct ConsensusRPC {
    rpc: String,
    client: ClientWithMiddleware,
}

#[allow(dead_code)]
impl ConsensusRPC {
    pub fn new(rpc: String, config: EthConfig) -> Self {
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(3);

        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .connect_timeout(Duration::from_secs(config.timeout_secs))
            .timeout(Duration::from_secs(60))
            .build()
            .unwrap();

        let client = ClientBuilder::new(client)
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();

        ConsensusRPC { rpc, client }
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

    async fn get_block_roots_tree(
        &self,
        start_slot: u64,
    ) -> Result<Vector<Root, SLOTS_PER_HISTORICAL_ROOT>, RPCError> {
        let mut futures = Vec::new();

        for i in 0..SLOTS_PER_HISTORICAL_ROOT {
            let future = self.get_block_root(start_slot + i as u64);
            futures.push(future);
        }

        let resolved = future::join_all(futures).await;

        // If any of the block roots failed to resolve, fill in the gaps with the last known root.
        let mut block_roots = Vec::with_capacity(SLOTS_PER_HISTORICAL_ROOT);
        for (i, block_root) in resolved.iter().enumerate() {
            match block_root {
                Ok(block_root) => block_roots.push(*block_root),
                Err(err) => match err {
                    RPCError::NotFoundError(_) => {
                        println!(
                            "There was a not found error for {} {:?}. Filling with previous",
                            i, err
                        );
                        if let Some(last_root) = block_roots.last().cloned() {
                            block_roots.push(last_root);
                        }
                    }
                    _ => {
                        println!("There was an rpc error for {} {:?}", i, err);
                        return Err(err.clone());
                    }
                },
            }
        }

        let block_roots = Vector::<Root, SLOTS_PER_HISTORICAL_ROOT>::try_from(block_roots).unwrap();

        Ok(block_roots)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httptest::{matchers::*, responders::*, Expectation, Server};

    fn setup_server_and_rpc() -> (Server, ConsensusRPC) {
        let server = Server::run();
        let url = server.url("");
        let rpc = ConsensusRPC::new(url.to_string(), EthConfig::default());
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

    #[ignore]
    #[tokio::test]
    async fn test_get_block_roots_tree() {
        let (server, rpc) = setup_server_and_rpc();
        let start_slot = 100;

        let response = BlockRootResponse {
            data: BlockRoot {
                root: Default::default(),
            },
        };
        let json_res = serde_json::to_string(&response).unwrap();

        server.expect(
            Expectation::matching(any())
                //TODO: Fix this to be SLOTS_PER_HISTORICAL_ROOT
                .times(1..)
                .respond_with(status_code(200).body(json_res.clone())),
        );

        let result = rpc.get_block_roots_tree(start_slot as u64).await;

        match result {
            Ok(roots_vector) => {
                assert_eq!(roots_vector.len(), SLOTS_PER_HISTORICAL_ROOT);
            }
            Err(e) => panic!("Failed to get block roots tree: {:?}", e),
        }
    }

    #[ignore]
    #[tokio::test]
    async fn test_get_block_roots_tree_with_fallback() {
        let (server, rpc) = setup_server_and_rpc();
        let start_slot = 100;

        let response = BlockRootResponse {
            data: BlockRoot {
                root: Default::default(),
            },
        };
        let response_json = serde_json::to_string(&response).unwrap();

        server.expect(Expectation::matching(any()).times(..).respond_with(cycle![
            status_code(200).body(response_json.clone()),
            status_code(404),
        ]));

        let result = rpc.get_block_roots_tree(start_slot as u64).await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), SLOTS_PER_HISTORICAL_ROOT);
        assert_eq!([Root::default(); 8192].to_vec(), result.to_vec());
    }
}
