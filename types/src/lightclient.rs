use crate::consensus::{BeaconBlockAlias, FinalityUpdate, OptimisticUpdate};
use crate::helpers::{from_hex_string, to_hex_string};
use crate::primitives::U64;
use ssz_rs::Vector;
use sync_committee_rs::consensus_types::{BeaconBlockHeader, SyncAggregate, SyncCommittee};
use sync_committee_rs::constants::{Root, SLOTS_PER_HISTORICAL_ROOT, SYNC_COMMITTEE_SIZE};
use sync_committee_rs::types::AncestryProof;

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
    pub target_block: BeaconBlockAlias,
    pub intermediate_chain: Vec<BeaconBlockHeader>,
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    pub sig_slot: U64,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone, Default)]
pub struct TopicInclusionRequest {
    #[serde(deserialize_with = "from_hex_string", serialize_with = "to_hex_string")]
    pub receipt: Vec<u8>,
    #[serde(deserialize_with = "from_hex_string", serialize_with = "to_hex_string")]
    pub topic: Vec<u8>,
}

pub enum UpdateVariant {
    Finality(FinalityUpdate),
    Optimistic(OptimisticUpdate),
}

pub struct EventVerificationData {
    pub update: UpdateVariant,
    pub target_block: BeaconBlockHeader,
    pub block_roots: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,
    pub ancestry_proof: AncestryProof,
}
