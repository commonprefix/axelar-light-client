use crate::consensus::{FinalityUpdate, OptimisticUpdate};
pub use connection_router::state::{
    Address as AddressType, ChainName, CrossChainId, Message, MessageHash,
};
use ssz_rs::Node;
use sync_committee_rs::{
    consensus_types::{BeaconBlockHeader, Transaction},
    constants::{Root, MAX_BYTES_PER_TRANSACTION},
};

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct MessageProof {
    // Proof from sync committee signed block to a recent block (either finalized or optimistic)
    pub update: UpdateVariant,
    // Proof from the recent block to the block that contains the event of the message
    pub ancestry_proof: AncestryProof,
    // The actual target block header
    pub target_block: BeaconBlockHeader,
    // Proof from the target block to the transaction that contains the event
    pub transaction_proof: TransactionProof,
    // Proof from the target block to the actual event
    pub receipt_proof: ReceiptProof,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub enum UpdateVariant {
    // LightClientFinalityUpdate from the beacon API spec.
    Finality(FinalityUpdate),
    // LightClientOptimisticUpdate from the beacon API spec.
    Optimistic(OptimisticUpdate),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AncestryProof {
    // This variant defines the proof data for a beacon chain header in the `state.block_roots`.
    BlockRoots {
        // Generalized index from the block_root that we care to the block_root to the state root.
        // No need to provide that, since it can be calculated on-chain.
        block_roots_index: u64,
        block_root_proof: Vec<Node>,
    },
    // This variant defines the neccessary proofs for a beacon chain header in the
    // `state.historical_roots`.
    HistoricalRoots {
        // Proof for the target_block in the historical_summaries[index].block_summary_root
        block_root_proof: Vec<Node>,
        // The hash of the specific block summary root that has the block
        block_summary_root: Root,
        // Proof that historical_summaries[index].block_summary_root is in recent block state
        block_summary_root_proof: Vec<Node>,
        // The generalized index for the historical_batch in state.historical_roots.
        block_summary_root_gindex: u64,
    },
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct TransactionProof {
    // Same index of transaction to transaction trie and from receipt to receipt trie
    pub transaction_index: u64,
    // Generalized index of transaction in target block
    pub transaction_gindex: u64,
    // Proof from target block to transaction
    pub transaction_branch: Vec<Node>,
    // Actual transaction to keccak and test against tx_hash of message
    pub transaction: Transaction<MAX_BYTES_PER_TRANSACTION>,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone, Default)]
pub struct ReceiptProof {
    // Actual receipt
    pub receipt: Vec<u8>,
    // Proof from receipts root to beacon block
    pub receipts_root_proof: Vec<Node>,
    // Proof from receipt to receipts root trie
    pub receipt_proof: Vec<Vec<u8>>,
    // Receipts root of execution payload of target block
    pub receipts_root: Root,
}
