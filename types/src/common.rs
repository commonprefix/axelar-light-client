use ssz_rs::prelude::*;

use crate::primitives::ByteVector;

pub type Bytes32 = ByteVector<32>;
pub type BLSPubKey = ByteVector<48>;
pub type SignatureBytes = ByteVector<96>;
pub type Address = ByteVector<20>;

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub genesis_time: u64,
    pub genesis_root: Vec<u8>,
    pub forks: Forks,
}

#[derive(SimpleSerialize, Default, Debug)]
pub struct ForkData {
    pub current_version: Vector<u8, 4>,
    pub genesis_validator_root: Bytes32,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Default, Clone)]
pub struct Fork {
    pub epoch: u64,
    pub fork_version: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Default, Clone)]
pub struct Forks {
    pub genesis: Fork,
    pub altair: Fork,
    pub bellatrix: Fork,
    pub capella: Fork,
}
