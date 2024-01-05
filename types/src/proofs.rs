use crate::common::ContentVariant;
use crate::consensus::{FinalityUpdate, OptimisticUpdate};
pub use axelar_wasm_std::{nonempty, operators::Operators};
pub use connection_router::state::{Address as AddressType, ChainName, CrossChainId, Message};
use eyre::Result;
use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serializer};
use ssz_rs::Node;
use sync_committee_rs::{
    consensus_types::{BeaconBlockHeader, Transaction},
    constants::{Root, MAX_BYTES_PER_TRANSACTION},
};

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
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

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone, Eq)]
pub enum UpdateVariant {
    // LightClientFinalityUpdate from the beacon API spec.
    Finality(FinalityUpdate),
    // LightClientOptimisticUpdate from the beacon API spec.
    Optimistic(OptimisticUpdate),
}

impl Default for UpdateVariant {
    fn default() -> Self {
        UpdateVariant::Finality(FinalityUpdate::default())
    }
}

impl UpdateVariant {
    pub fn recent_block(&self) -> BeaconBlockHeader {
        match &self {
            UpdateVariant::Finality(update) => update.finalized_header.beacon.clone(),
            UpdateVariant::Optimistic(update) => update.attested_header.beacon.clone(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
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

impl Default for AncestryProof {
    fn default() -> Self {
        AncestryProof::BlockRoots {
            block_roots_index: 0,
            block_root_proof: vec![],
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone, Default)]
pub struct TransactionProof {
    // Same index of transaction to transaction trie and from receipt to receipt trie
    pub transaction_index: u64,
    // Generalized index of transaction in target block
    pub transaction_gindex: u64,
    // Proof from target block to transaction
    pub transaction_proof: Vec<Node>,
    // Actual transaction to keccak and test against tx_hash of message
    pub transaction: Transaction<MAX_BYTES_PER_TRANSACTION>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default)]
pub struct ReceiptProof {
    // Proof from receipts root to beacon block
    pub receipts_root_proof: Vec<Node>,
    // Proof from receipt to receipts root trie
    #[serde(
        serialize_with = "hex_array_serializer",
        deserialize_with = "hex_array_deserializer"
    )]
    pub receipt_proof: Vec<Vec<u8>>,
    // Receipts root of execution payload of target block
    pub receipts_root: Root,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct BatchVerificationData {
    pub update: UpdateVariant,
    pub target_blocks: Vec<BlockProofsBatch>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct BlockProofsBatch {
    pub ancestry_proof: AncestryProof,
    pub target_block: BeaconBlockHeader,
    pub transactions_proofs: Vec<TransactionProofsBatch>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct TransactionProofsBatch {
    pub transaction_proof: TransactionProof,
    pub receipt_proof: ReceiptProof,
    // Support multiple messages on a single tx, ie transaction level batching
    pub content: Vec<ContentVariant>,
}

fn hex_array_deserializer<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let strs = Vec::<String>::deserialize(deserializer)?;
    strs.into_iter()
        .map(|s| hex::decode(s).map_err(SerdeError::custom))
        .collect()
}

fn hex_array_serializer<S>(bytes_array: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_strings: Vec<String> = bytes_array.iter().map(hex::encode).collect();
    serializer.collect_seq(hex_strings)
}
