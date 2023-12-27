use ethers::types::{Block, Transaction, TransactionReceipt, H256};
use ssz_rs::Node;
use sync_committee_rs::consensus_types::BeaconBlockHeader;
use types::{
    consensus::{BeaconBlockAlias, Bootstrap, FinalityUpdate, OptimisticUpdate, Update},
    lightclient::Message,
};
#[derive(Clone, Debug, PartialEq)]
pub struct InternalMessage {
    pub message: Message,
    pub tx_hash: H256,
    pub exec_block: Block<Transaction>,
    pub beacon_block: BeaconBlockAlias,
    pub receipts: Vec<TransactionReceipt>,
}

pub type UpdateResponse = Vec<UpdateData>;

#[derive(serde::Deserialize)]
pub struct UpdateData {
    pub data: Update,
}

#[derive(serde::Deserialize)]
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
#[derive(serde::Deserialize)]
pub struct FinalityUpdateData {
    pub data: FinalityUpdate,
}

#[derive(serde::Deserialize)]
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
