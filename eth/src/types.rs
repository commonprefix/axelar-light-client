use ethers::types::H256;
use ssz_rs::Node;
use sync_committee_rs::consensus_types::BeaconBlockHeader;
use types::{
    consensus::{BeaconBlockAlias, Bootstrap, FinalityUpdate, OptimisticUpdate, Update},
    lightclient::Message,
};

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
pub struct BeaconBlockHeaderResponse {
    pub data: BeaconBlockHeaderContainer,
}

#[derive(serde::Deserialize, Debug)]
pub struct BeaconBlockHeaderContainer {
    pub header: BeaconBlockHeaderMessage,
}

#[derive(serde::Deserialize, Debug)]
pub struct BeaconBlockHeaderMessage {
    pub message: BeaconBlockHeader,
}

#[derive(serde::Deserialize, Debug)]
pub struct BeaconBlockResponse {
    pub data: BeaconBlockContainer,
}

#[derive(serde::Deserialize, Debug)]
pub struct BeaconBlockContainer {
    pub message: BeaconBlockAlias,
}
#[derive(serde::Deserialize, Debug)]
pub struct FinalityUpdateData {
    pub data: FinalityUpdate,
}

#[derive(serde::Deserialize, Debug)]
pub struct OptimisticUpdateData {
    pub data: OptimisticUpdate,
}

#[derive(serde::Deserialize, Debug)]
pub struct BlockRootResponse {
    pub data: BlockRoot,
}

#[derive(serde::Deserialize, Debug)]
pub struct BlockRoot {
    pub root: Node,
}
