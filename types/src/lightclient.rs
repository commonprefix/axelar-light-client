use crate::consensus::{FinalityUpdate, OptimisticUpdate};
use crate::helpers::{from_hex_string, to_hex_string};
use crate::proofs::AncestryProof;
pub use connection_router::state::{Address as AddressType, ChainName, CrossChainId, Message};
use ssz_rs::Node;
use sync_committee_rs::constants::{Bytes32, Root, SYNC_COMMITTEE_SIZE};
use sync_committee_rs::{
    consensus_types::{BeaconBlockHeader, SyncAggregate, SyncCommittee, Transaction},
    constants::MAX_BYTES_PER_TRANSACTION,
};

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

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub enum UpdateVariant {
    Finality(FinalityUpdate),
    Optimistic(OptimisticUpdate),
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct EventVerificationData {
    pub message: Message,
    pub update: UpdateVariant,
    pub target_block: BeaconBlockHeader,
    pub block_roots_root: Root,
    pub ancestry_proof: AncestryProof,
    pub receipt_proof: ReceiptProof,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone, Default)]
pub struct ReceiptProof {
    // Same index of transaction to transaction trie and from receipt to receipt trie
    pub transaction_index: u64,
    // Proof from beacon block to transaction
    pub transaction_branch: Vec<Node>,
    // Actual transaction to keccak and test against tx_hash of message
    pub transaction: Transaction<MAX_BYTES_PER_TRANSACTION>,

    // Proof from receipts root to beacon block
    pub receipts_branch: Vec<Node>,
    // Proof from receipt to receipts root (TRIE)
    pub receipt_proof: Vec<Vec<u8>>,

    pub transactions_root: Bytes32,
    pub receipts_root: Bytes32,
}
