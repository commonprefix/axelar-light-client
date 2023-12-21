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
    async fn get_latest_beacon_block_header(&self) -> Result<BeaconBlockHeader, RPCError>;
    async fn get_latest_beacon_block(&self) -> Result<BeaconBlockAlias, RPCError>;
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

    async fn get_latest_beacon_block(&self) -> Result<BeaconBlockAlias, RPCError> {
        let req = format!("{}/eth/v2/beacon/blocks/head", self.rpc);
        let res: BeaconBlockResponse = get(&req).await?;

        Ok(res.data.message)
    }

    async fn get_latest_beacon_block_header(&self) -> Result<BeaconBlockHeader, RPCError> {
        let req = format!("{}/eth/v2/beacon/headers/head", self.rpc);

        let res: BeaconBlockHeaderResponse = get(&req).await?;

        Ok(res.data.header.message)
    }

    async fn get_block_roots_tree(
        &self,
        start_slot: u64,
    ) -> Result<Vector<Root, SLOTS_PER_HISTORICAL_ROOT>, RPCError> {
        const BATCH_SIZE: usize = 1000;

        let mut block_roots = vec![];

        for batch_start in (0..SLOTS_PER_HISTORICAL_ROOT).step_by(BATCH_SIZE) {
            let batch_end = std::cmp::min(batch_start + BATCH_SIZE, SLOTS_PER_HISTORICAL_ROOT);
            let mut futures = Vec::new();

            for i in batch_start..batch_end {
                let future = self.get_block_root(start_slot + i as u64);
                futures.push(future);
            }

            let resolved = future::join_all(futures).await;
            println!("Resolved batch {}", batch_start / BATCH_SIZE);

            // Block root tree includes the last block root if no block was minted in the slot
            for block_root in resolved.iter() {
                match block_root {
                    Ok(block_root) => block_roots.push(*block_root),
                    Err(_) => block_roots.push(*block_roots.last().unwrap()),
                }
            }
        }

        let block_roots = Vector::<Root, SLOTS_PER_HISTORICAL_ROOT>::try_from(block_roots).unwrap();

        Ok(block_roots)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use mockall::predicate::*;
    use mockall::*;

    // Utility function to create a vector of Results
    fn create_mock_roots(success_count: usize, error_count: usize) -> Vec<Result<Root, RPCError>> {
        let mut roots = Vec::new();

        for _ in 0..success_count {
            roots.push(Ok(Root::default()));
        }

        for _ in 0..error_count {
            roots.push(Err(RPCError::UnknownError("Mock Error".to_string())));
        }

        roots
    }

    mock! {
        ConsensusRPC {}
        #[async_trait]
        impl EthBeaconAPI for ConsensusRPC {
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
            async fn get_latest_beacon_block_header(&self) -> Result<BeaconBlockHeader, RPCError>;
            async fn get_latest_beacon_block(&self) -> Result<BeaconBlockAlias, RPCError>;
        }
    }

    #[tokio::test]
    async fn test_get_block_root() {
        let mut mock_rpc = MockConsensusRPC::new();
        let expected_root = Root::default();
        mock_rpc
            .expect_get_block_root()
            .with(predicate::eq(12345))
            .times(1)
            .returning(move |_| Ok(expected_root));

        let result = mock_rpc.get_block_root(12345).await;
        assert_eq!(result.unwrap(), Root::default());
    }

    #[tokio::test]
    async fn test_get_updates() {
        let mut mock_rpc = MockConsensusRPC::new();
        let expected_updates = vec![Update::default(); 3]; // Example updates
        let period = 10u64;
        let count = 3u8;

        let updates_for_mock = expected_updates.clone();

        mock_rpc
            .expect_get_updates()
            .with(predicate::eq(period), predicate::eq(count))
            .times(1)
            .returning(move |_, _| Ok(updates_for_mock.clone()));

        let result = mock_rpc.get_updates(period, count).await;
        assert_eq!(result.unwrap(), expected_updates);
    }

    #[tokio::test]
    async fn test_get_finality_update() {
        let mut mock_rpc = MockConsensusRPC::new();
        let expected_update = FinalityUpdate::default();

        let update_for_mock = expected_update.clone();

        mock_rpc
            .expect_get_finality_update()
            .times(1)
            .returning(move || Ok(update_for_mock.clone()));

        let result = mock_rpc.get_finality_update().await;
        assert_eq!(result.unwrap(), expected_update);
    }

    #[tokio::test]
    async fn test_get_optimistic_update() {
        let mut mock_rpc = MockConsensusRPC::new();
        let expected_update = OptimisticUpdate::default();
        let update_for_mock = expected_update.clone();

        mock_rpc
            .expect_get_optimistic_update()
            .times(1)
            .returning(move || Ok(update_for_mock.clone()));

        let result = mock_rpc.get_optimistic_update().await;
        assert_eq!(result.unwrap(), expected_update);
    }

    #[tokio::test]
    async fn test_get_beacon_block_header() {
        let mut mock_rpc = MockConsensusRPC::new();
        let expected_header = BeaconBlockHeader::default();
        let header_for_mock = expected_header.clone();
        let slot = 12345u64;

        mock_rpc
            .expect_get_beacon_block_header()
            .with(predicate::eq(slot))
            .times(1)
            .returning(move |_| Ok(header_for_mock.clone()));

        let result = mock_rpc.get_beacon_block_header(slot).await;
        assert_eq!(result.unwrap(), expected_header);
    }

    #[tokio::test]
    async fn test_get_bootstrap() {
        let mut mock_rpc = MockConsensusRPC::new();
        let expected_bootstrap = Bootstrap::default();
        let bootstrap_for_mock = expected_bootstrap.clone();
        // Create an owned version of block_root
        let block_root = vec![0u8; 32]; // Mock block root

        // Now `block_root` is owned and can be moved into the closure
        mock_rpc
            .expect_get_bootstrap()
            .with(predicate::eq(block_root.clone())) // Use clone to keep original `block_root`
            .times(1)
            .returning(move |_| Ok(bootstrap_for_mock.clone()));

        let result = mock_rpc.get_bootstrap(&block_root).await;
        assert_eq!(result.unwrap(), expected_bootstrap);
    }
}
