use crate::consensus::{FinalityUpdate, OptimisticUpdate};
use crate::helpers::{from_hex_string, to_hex_string};
use connection_router::state::Message;
use ssz_rs::{Node, Vector};
use sync_committee_rs::consensus_types::{BeaconBlockHeader, SyncAggregate, SyncCommittee};
use sync_committee_rs::constants::{Root, SLOTS_PER_HISTORICAL_ROOT, SYNC_COMMITTEE_SIZE};
pub use sync_committee_rs::types::AncestryProof;

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone, Default)]
pub struct LightClientState {
    pub finalized_header: BeaconBlockHeader,
    pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub next_sync_committee: Option<SyncCommittee<SYNC_COMMITTEE_SIZE>>,
    pub previous_max_active_participants: u64,
    pub current_max_active_participants: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default)]
pub struct BlockVerificationData {
    pub target_block: BeaconBlockHeader,
    pub intermediate_chain: Vec<BeaconBlockHeader>,
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    pub sig_slot: u64,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone, Default)]
pub struct TopicInclusionRequest {
    #[serde(deserialize_with = "from_hex_string", serialize_with = "to_hex_string")]
    pub receipt: Vec<u8>,
    #[serde(deserialize_with = "from_hex_string", serialize_with = "to_hex_string")]
    pub topic: Vec<u8>,
}

#[derive(PartialEq, Debug, Clone)]
pub enum UpdateVariant {
    Finality(FinalityUpdate),
    Optimistic(OptimisticUpdate),
}

#[derive(PartialEq, Debug, Clone)]
pub struct EventVerificationData {
    pub message: Message,
    pub update: UpdateVariant,
    pub target_block: BeaconBlockHeader,
    pub block_roots: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,
    pub ancestry_proof: AncestryProof,
    pub receipt_proof: ReceiptProof,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone, Default)]
pub struct ReceiptProof {
    // Proof from receipt to receipts root
    pub receipt_branch: Vec<Node>,
    pub receipt_index: u64,
    pub receipts_root: Root,
    // Proof from receipts root to execution body
    pub receipts_root_branch: Vec<Node>,
    pub execution_payload_root: Root,
    // Proof from execution payload to body_root
    pub execution_payload_branch: Vec<Node>,
}
