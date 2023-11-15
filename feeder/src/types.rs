use ethers::types::{H160, H256, U256};
use types::consensus::{BeaconHeader, Bootstrap, FinalityUpdate, OptimisticUpdate, Update};

#[derive(Debug, Clone)]
pub struct Message {
    pub block_number: u64,
    pub block_hash: H256,
    pub tx_id: H256,
    pub event_index: U256,
    pub destination_address: String,
    pub destination_chain: String,
    pub source_address: H160,
    pub payload_hash: H256,
}

#[derive(Debug, Clone)]
pub enum FinalityOrOptimisticUpdate {
    Finality(FinalityUpdate),
    Optimistic(OptimisticUpdate),
}

#[derive(serde::Deserialize, Debug)]
pub struct BeaconBlockResponse {
    pub data: BeaconBlockData,
}

pub type UpdateResponse = Vec<UpdateData>;

#[derive(serde::Deserialize, Debug)]
pub struct UpdateData {
    pub data: Update,
}

#[derive(serde::Deserialize, Debug)]
pub struct BootstrapResponse {
    pub data: Bootstrap,
}

#[derive(serde::Deserialize, Debug)]
pub struct BeaconBlockData {
    pub message: BeaconHeader,
}

#[derive(serde::Deserialize, Debug)]
pub struct FinalityUpdateData {
    pub data: FinalityUpdate,
}

#[derive(serde::Deserialize, Debug)]
pub struct OptimisticUpdateData {
    pub data: OptimisticUpdate,
}
