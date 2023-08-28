use cosmwasm_schema::cw_serde;
use serde::{Deserialize, Serialize};
use ssz_rs::Vector;

pub type Bytes32 = [u8; 32];
pub type BLSPubKey = Vector<u8, 48>;
pub type SignatureBytes = Vector<u8, 96>;

#[cw_serde]
pub struct Header {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: Bytes32,
    pub state_root: Bytes32,
    pub body_root: Bytes32,
}

#[derive(Deserialize, Serialize, PartialEq, Debug, Clone)]
pub struct Bootstrap {
    pub header: Header,
    pub current_sync_committee: SyncCommittee,
    pub current_sync_committee_branch: Vec<Bytes32>,
}

#[derive(Deserialize, Serialize, PartialEq, Debug, Clone)]
pub struct SyncCommittee {
    pub pubkeys: Vector<BLSPubKey, 512>,
    pub aggregate_pubkey: BLSPubKey,
}
