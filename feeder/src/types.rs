use consensus_types::{
    consensus::{Bootstrap, FinalityUpdate, OptimisticUpdate, Update},
    lightclient::Message,
};
use ethers::types::H256;
use sync_committee_rs::consensus_types::BeaconBlockHeader;

#[derive(Clone, Debug)]
pub struct InternalMessage {
    pub message: Message,
    pub block_hash: H256,
    pub block_number: u64,
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
pub struct BeaconBlockResponse {
    pub data: BeaconBlockHeaderResponse,
}

#[derive(serde::Deserialize, Debug)]
pub struct BeaconBlockHeaderResponse {
    pub header: BeaconBlockMessage,
}

#[derive(serde::Deserialize, Debug)]
pub struct BeaconBlockMessage {
    pub message: BeaconBlockHeader,
}

#[derive(serde::Deserialize, Debug)]
pub struct FinalityUpdateData {
    pub data: FinalityUpdate,
}

#[derive(serde::Deserialize, Debug)]
pub struct OptimisticUpdateData {
    pub data: OptimisticUpdate,
}
