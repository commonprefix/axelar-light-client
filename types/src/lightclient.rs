use crate::consensus::{BeaconBlock, BeaconBlockHeader, SyncAggregate, SyncCommittee};
use crate::helpers::{from_hex_string, to_hex_string};
use crate::primitives::U64;

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone, Default)]
pub struct LightClientState {
    pub finalized_header: BeaconBlockHeader,
    pub current_sync_committee: SyncCommittee,
    pub next_sync_committee: Option<SyncCommittee>,
    pub previous_max_active_participants: u64,
    pub current_max_active_participants: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default)]
pub struct BlockVerificationData {
    pub target_block: BeaconBlock,
    pub intermediate_chain: Vec<BeaconBlockHeader>,
    pub sync_aggregate: SyncAggregate,
    pub sig_slot: U64,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone, Default)]
pub struct TopicInclusionRequest {
    #[serde(deserialize_with = "from_hex_string", serialize_with = "to_hex_string")]
    pub receipt: Vec<u8>,
    #[serde(deserialize_with = "from_hex_string", serialize_with = "to_hex_string")]
    pub topic: Vec<u8>,
}
