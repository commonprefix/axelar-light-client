use consensus_types::ssz_rs::{Node, SszVariableOrIndex};
use consensus_types::sync_committee_rs::consensus_types::BeaconBlockHeader;
use consensus_types::{common::ContentVariant, consensus::BeaconBlockAlias};
use ethers::types::{Block, Transaction, TransactionReceipt, H256};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

// Neccessary data for proving a message
#[derive(Debug)]
pub struct ProofAuxiliaryData {
    // Target execution block that contains the transaction/log.
    pub target_execution_block: Block<Transaction>,
    // Target beacon block that contains the target execution block.
    pub target_beacon_block: BeaconBlockAlias,
    // Receipts of the target execution block.
    pub receipts: Vec<TransactionReceipt>,
    // Block header of the most recent block. (Either finalized or attested depending or the UpdateVariant)
    pub recent_block_header: BeaconBlockHeader,
}

#[derive(PartialEq, Deserialize, Debug, Serialize, Default, Clone)]
pub struct ProofResponse {
    pub gindex: u64,
    pub witnesses: Vec<Node>,
    pub leaf: Node,
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct EnrichedContent {
    pub id: String,
    pub content: ContentVariant,
    pub tx_hash: H256,
    pub exec_block: Block<Transaction>,
    pub beacon_block: BeaconBlockAlias,
    pub receipts: Vec<TransactionReceipt>,
    pub delivery_tag: u64,
}

#[derive(Debug, PartialEq)]
pub enum GindexOrPath {
    Gindex(usize),
    Path(Vec<SszVariableOrIndex>),
}

pub struct ProverConfig {
    pub network: String,
    pub consensus_rpc: String,
    pub execution_rpc: String,
    pub state_prover_rpc: String,
    pub reject_historical_roots: bool,
    pub historical_roots_block_roots_batch_size: u64,
}

// A map from block number to a map from tx hash to messages
pub type BatchContentGroups = IndexMap<u64, IndexMap<H256, Vec<EnrichedContent>>>;
