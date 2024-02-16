use ethers::types::{Block, Transaction, TransactionReceipt};
use types::consensus::{BeaconBlockAlias, Bootstrap, FinalityUpdate, OptimisticUpdate, Update};
use types::ssz_rs::{Node, Vector};
use types::sync_committee_rs::consensus_types::BeaconBlockHeader;
use types::sync_committee_rs::constants::{Root, SLOTS_PER_HISTORICAL_ROOT};
pub type UpdateResponse = Vec<UpdateData>;

/// The basic configuration of the Beacon ETH client
pub struct EthConfig {
    pub pool_max_idle_per_host: usize,
    pub rpc_max_retries: u64,
    pub timeout_secs: u64,
}

impl Default for EthConfig {
    fn default() -> Self {
        EthConfig {
            pool_max_idle_per_host: 10,
            timeout_secs: 10,
            rpc_max_retries: 5,
        }
    }
}

/// A type wrapping all block details in a single structure.
/// This is used to avoid having to pass around multiple
/// parameters.
#[derive(Debug, Default)]
pub struct FullBlockDetails {
    pub exec_block: Block<Transaction>,
    pub beacon_block: BeaconBlockAlias,
    pub receipts: Vec<TransactionReceipt>,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct UpdateData {
    pub data: Update,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct BootstrapResponse {
    pub data: Bootstrap,
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct BeaconBlockHeaderResponse {
    pub data: BeaconBlockHeaderContainer,
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct BeaconBlockHeaderContainer {
    pub header: BeaconBlockHeaderMessage,
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct BeaconBlockHeaderMessage {
    pub message: BeaconBlockHeader,
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct BeaconBlockResponse {
    pub data: BeaconBlockContainer,
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct BeaconBlockContainer {
    pub message: BeaconBlockAlias,
}
#[derive(serde::Deserialize, serde::Serialize)]
pub struct FinalityUpdateData {
    pub data: FinalityUpdate,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct OptimisticUpdateData {
    pub data: OptimisticUpdate,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default, Clone)]
pub struct BlockRootResponse {
    pub data: BlockRoot,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default, Clone)]
pub struct BlockRoot {
    pub root: Node,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Default)]
pub struct BlockRootsArchiveResponse {
    pub data: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,
}
