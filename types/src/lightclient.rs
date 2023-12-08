use crate::proofs::MessageProof;
pub use connection_router::state::{
    Address as AddressType, ChainName, CrossChainId, Message, MessageHash,
};
use sync_committee_rs::{
    consensus_types::{BeaconBlockHeader, SyncCommittee},
    constants::SYNC_COMMITTEE_SIZE,
};

#[derive(serde::Serialize, serde::Deserialize, Default)]
pub struct LightClientState {
    pub finalized_header: BeaconBlockHeader,
    pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub next_sync_committee: Option<SyncCommittee<SYNC_COMMITTEE_SIZE>>,
    pub previous_max_active_participants: u64,
    pub current_max_active_participants: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct MessageVerification {
    pub message: Message,
    pub proofs: MessageProof,
}
