use types::consensus::{BeaconBlock, Bootstrap, Update};

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
    pub message: BeaconBlock,
}
