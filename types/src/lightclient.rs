use crate::proofs::MessageProof;
pub use connection_router::state::{
    Address as AddressType, ChainName, CrossChainId, Message, MessageHash,
};
use sync_committee_rs::{consensus_types::SyncCommittee, constants::SYNC_COMMITTEE_SIZE};

#[derive(serde::Serialize, serde::Deserialize, Default, PartialEq, Debug, Clone)]
pub struct LightClientState {
    pub update_slot: u64,
    pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub next_sync_committee: Option<SyncCommittee<SYNC_COMMITTEE_SIZE>>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct MessageVerification {
    pub message: Message,
    pub proofs: MessageProof,
}
