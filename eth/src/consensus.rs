use crate::error::RPCError;
use crate::types::*;
use crate::utils::get;
use async_trait::async_trait;
use futures::future;
use mockall::automock;
use ssz_rs::Vector;
use std::cmp;
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
}

#[allow(dead_code)]
impl ConsensusRPC {
    pub fn new(rpc: String) -> Self {
        ConsensusRPC { rpc }
    }
}

#[automock]
#[async_trait]
impl EthBeaconAPI for ConsensusRPC {
    async fn get_block_root(&self, slot: u64) -> Result<Root, RPCError> {
        let req = format!("{}/eth/v1/beacon/blocks/{}/root", self.rpc, slot);

        let res: BlockRootResponse = get(&req).await?;

        Ok(res.data.root)
    }

    async fn get_bootstrap(&self, block_root: &'_ [u8]) -> Result<Bootstrap, RPCError> {
        let root_hex = hex::encode(block_root);
        let req = format!(
            "{}/eth/v1/beacon/light_client/bootstrap/0x{}",
            self.rpc, root_hex
        );

        let res: BootstrapResponse = get::<BootstrapResponse>(&req).await?;

        Ok(res.data)
    }

    async fn get_updates(&self, period: u64, count: u8) -> Result<Vec<Update>, RPCError> {
        let count = cmp::min(count, 10);
        let req = format!(
            "{}/eth/v1/beacon/light_client/updates?start_period={}&count={}",
            self.rpc, period, count
        );

        let res: UpdateResponse = get(&req).await?;

        Ok(res.into_iter().map(|d| d.data).collect())
    }

    async fn get_finality_update(&self) -> Result<FinalityUpdate, RPCError> {
        let req = format!("{}/eth/v1/beacon/light_client/finality_update", self.rpc);

        let res: FinalityUpdateData = get(&req).await?;

        Ok(res.data)
    }

    async fn get_optimistic_update(&self) -> Result<OptimisticUpdate, RPCError> {
        let req = format!("{}/eth/v1/beacon/light_client/optimistic_update", self.rpc);

        let res: OptimisticUpdateData = get(&req).await?;

        Ok(res.data)
    }

    async fn get_beacon_block_header(&self, slot: u64) -> Result<BeaconBlockHeader, RPCError> {
        let req = format!("{}/eth/v1/beacon/headers/{}", self.rpc, slot);

        let res: BeaconBlockHeaderResponse = get(&req).await?;

        Ok(res.data.header.message)
    }

    async fn get_beacon_block(&self, slot: u64) -> Result<BeaconBlockAlias, RPCError> {
        let req = format!("{}/eth/v2/beacon/blocks/{}", self.rpc, slot);

        let res: BeaconBlockResponse = get(&req).await?;

        Ok(res.data.message)
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
    
        let mut block_roots = Vec::with_capacity(SLOTS_PER_HISTORICAL_ROOT);
        for block_root in resolved {
            match block_root {
                Ok(block_root) => block_roots.push(block_root),
                Err(_) => {
                    if let Some(last_root) = block_roots.last().cloned() {
                        block_roots.push(last_root);
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
    use httptest::{Server, Expectation, matchers::*, responders::*};
    use super::*;

    fn setup_server_and_rpc() -> (Server, ConsensusRPC) {
        let server = Server::run();
        let url = server.url("");
        let rpc = ConsensusRPC::new(url.to_string());
        (server, rpc)
    }
    #[tokio::test]
    async fn test_get_block_root() {
        let (server, rpc) = setup_server_and_rpc();
        let result = BlockRootResponse::default();
        let json_res = serde_json::to_string(&result).unwrap();

        server.expect(
            Expectation::matching(
                request::path(matches("/eth/v1/beacon/blocks/12345/root")),
            )
            .respond_with(status_code(200).body(json_res)
        ));

        let result = rpc.get_block_root(12345).await;
        assert_eq!(result.unwrap(), Root::default());
    }

    #[tokio::test]
    async fn test_get_updates() {
        let (server, rpc) = setup_server_and_rpc();
        let expected_updates = vec![Update::default(); 3];
        let period = 10u64;
        let count = 3u8;

        let response = expected_updates.iter().map(|u| UpdateData {
            data: u.clone()
        }).collect::<Vec<_>>();
        let json_res = serde_json::to_string(&response).unwrap();

        server.expect(
            Expectation::matching(all_of(vec![
                Box::new(request::path(matches("/eth/v1/beacon/light_client/updates"))),
                Box::new(request::query(url_decoded(contains(("count", count.to_string()))))),
                Box::new(request::query(url_decoded(contains(("start_period", period.to_string())))))
            ]))
            .respond_with(status_code(200).body(json_res)),
        );

        let result = rpc.get_updates(period, count).await;
        assert_eq!(result.unwrap(), expected_updates);
    }

    #[tokio::test]
    async fn test_get_finality_update() {
        let (server, rpc) = setup_server_and_rpc();
        let expected_update = FinalityUpdate::default();

        let response = FinalityUpdateData { data: expected_update.clone() };
        let json_res = serde_json::to_string(&response).unwrap();

        server.expect(
            Expectation::matching(request::path(matches("/eth/v1/beacon/light_client/finality_update")))
                .respond_with(status_code(200).body(json_res)),
        );

        let result = rpc.get_finality_update().await;
        assert_eq!(result.unwrap(), expected_update);
    }

    #[tokio::test]
    async fn test_get_optimistic_update() {
        let (server, rpc) = setup_server_and_rpc();
        let expected_update = OptimisticUpdate::default();

        let response = OptimisticUpdateData { data: expected_update.clone() };
        let json_res = serde_json::to_string(&response).unwrap();

        server.expect(
            Expectation::matching(request::path(matches("/eth/v1/beacon/light_client/optimistic_update")))
                .respond_with(status_code(200).body(json_res)),
        );

        let result = rpc.get_optimistic_update().await;
        assert_eq!(result.unwrap(), expected_update);
    }

    #[tokio::test]
    async fn test_get_beacon_block_header() {
        let (server, rpc) = setup_server_and_rpc();

        let slot = 12345;
        let expected_header = BeaconBlockHeader::default();
        let response = BeaconBlockHeaderResponse {
            data: BeaconBlockHeaderContainer {
                header: BeaconBlockHeaderMessage { message: expected_header.clone() },
            },
        };
        let json_res = serde_json::to_string(&response).unwrap();

        server.expect(
            Expectation::matching(request::path(matches(format!("/eth/v1/beacon/headers/{}", slot))))
                .respond_with(status_code(200).body(json_res)),
        );

        let result = rpc.get_beacon_block_header(slot).await;
        assert_eq!(result.unwrap(), expected_header);
    }

    #[tokio::test]
    async fn test_get_bootstrap() {
        let (server, rpc) = setup_server_and_rpc();

        let expected_bootstrap = Bootstrap::default();
        let block_root = vec![0u8; 32]; // Mock block root

        let response = BootstrapResponse { data: expected_bootstrap.clone() };
        let json_res = serde_json::to_string(&response).unwrap();

        server.expect(
            Expectation::matching(request::path(matches(format!("/eth/v1/beacon/light_client/bootstrap/0x{}", hex::encode(block_root.clone())))))
                .respond_with(status_code(200).body(json_res)),
        );

        let result = rpc.get_bootstrap(&block_root).await;
        assert_eq!(result.unwrap(), expected_bootstrap);
    }

    #[tokio::test]
    async fn test_get_beacon_block() {
        let (server, rpc) = setup_server_and_rpc();

        let slot = 12345;
        let expected_block = BeaconBlockAlias::default();
        let response = BeaconBlockResponse {
            data: BeaconBlockContainer 
                { message: expected_block.clone() },
        };
        let json_res = serde_json::to_string(&response).unwrap();

        server.expect(
            Expectation::matching(request::path(matches(format!("/eth/v2/beacon/blocks/{}", slot))))
                .respond_with(status_code(200).body(json_res)),
        );

        let result = rpc.get_beacon_block(slot).await;
        assert_eq!(result.unwrap(), expected_block);
    }
}
