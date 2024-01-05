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

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone, Eq)]
pub enum UpdateVariant {
    /// LightClientFinalityUpdate from the beacon API spec.
    Finality(FinalityUpdate),
    /// LightClientOptimisticUpdate from the beacon API spec.
    Optimistic(OptimisticUpdate),
}

impl Default for UpdateVariant {
    fn default() -> Self {
        UpdateVariant::Finality(FinalityUpdate::default())
    }
}

impl UpdateVariant {
    /// Extracts the most recent (maybe) finalized block from the LightClientUpdate message.
    /// In the case of a FinalityUpdate, we are using the most recent finalized block stored in finalized_header.
    /// In the case of an OptimisticUpdate, we trust (optimistically) that the attested_header will be finalized.
    pub fn recent_block(&self) -> BeaconBlockHeader {
        match &self {
            UpdateVariant::Finality(update) => update.finalized_header.beacon.clone(),
            UpdateVariant::Optimistic(update) => update.attested_header.beacon.clone(),
        }
    }
}

/// Necessary proofs to verify that a given block is an ancestor of another block.
/// In our case, it proves that the block that contains the event we are looking for, is an ancestor of the recent block that we got from the LightClientUpdate message.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub enum AncestryProof {
    /// This variant defines the proof data to verify that a beacon chain block header is in the `state.block_roots` of another block.
    BlockRoots {
        /// Generalized index from a block_root that we care to the block_root to the state root.
        // No need to provide that, since it can be calculated on-chain.
        block_roots_index: u64,
        block_root_proof: Vec<Node>,
    },
    /// This variant defines the necessary proofs to verify that a beacon chain block header in the `state.historical_roots` of another block.
    HistoricalRoots {
        /// Proof for the target_block in the historical_summaries[index].block_summary_root
        block_root_proof: Vec<Node>,
        /// The hash of the specific block summary root that has the block
        block_summary_root: Root,
        /// Proof that historical_summaries[index].block_summary_root is in recent block state
        block_summary_root_proof: Vec<Node>,
        /// The generalized index for the historical_batch in state.historical_roots.
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

/// Proofs to verify that a transaction is part of a block
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone, Default)]
pub struct TransactionProof {
    pub transaction_index: u64,
    /// Generalized index of transaction in target block
    pub transaction_gindex: u64,
    /// Proof that a transaction is part of the block's transactions trie
    pub transaction_proof: Vec<Node>,
    /// Encoded transaction
    pub transaction: Transaction<MAX_BYTES_PER_TRANSACTION>,
}

/// Proofs to verify that a receipt is part of a block
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default)]
pub struct ReceiptProof {
    /// Proof that a receipts_root is part of a block
    pub receipts_root_proof: Vec<Node>,
    /// Proof that a receipt is part of the receipts_root
    #[serde(
        serialize_with = "hex_array_serializer",
        deserialize_with = "hex_array_deserializer"
    )]
    pub receipt_proof: Vec<Vec<u8>>,
    /// The root of the receipts trie
    pub receipts_root: Root,
}

/// High-level structure that contains the messages that need verification, along with the necessary proofs
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct BatchVerificationData {
    pub update: UpdateVariant,
    pub target_blocks: Vec<BlockProofsBatch>,
}

/// Batch containing the proofs and messages to verify from a specific block.
/// Each block might have multiple transactions with multiple messages for verification.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct BlockProofsBatch {
    pub ancestry_proof: AncestryProof,
    pub target_block: BeaconBlockHeader,
    pub transactions_proofs: Vec<TransactionProofsBatch>,
}

/// Batch containing the proofs and messages to verify from a specific transaction.
/// Each transaction might have multiple messages for verification.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct TransactionProofsBatch {
    pub transaction_proof: TransactionProof,
    pub receipt_proof: ReceiptProof,
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
