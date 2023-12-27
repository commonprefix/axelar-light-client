use ssz_rs::prelude::*;

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub genesis_time: u64,
    pub genesis_root: Node,
    pub forks: Forks,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug)]
pub struct Fork {
    pub epoch: u64,
    pub fork_version: [u8; 4],
}

#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug)]
pub struct Forks {
    pub genesis: Fork,
    pub altair: Fork,
    pub bellatrix: Fork,
    pub capella: Fork,
}
