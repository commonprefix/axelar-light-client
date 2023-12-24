use consensus_types::{consensus::BeaconBlockAlias, proofs::Message};
use ethers::types::{Block, Transaction, TransactionReceipt, H256};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use ssz_rs::{Node, SszVariableOrIndex};
use sync_committee_rs::consensus_types::BeaconBlockHeader;

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

#[derive(Deserialize, Debug, Serialize, Default, Clone)]
pub struct ProofResponse {
    pub gindex: u64,
    pub witnesses: Vec<Node>,
    pub leaf: Node,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EnrichedMessage {
    pub message: Message,
    pub tx_hash: H256,
    pub exec_block: Block<Transaction>,
    pub beacon_block: BeaconBlockAlias,
    pub receipts: Vec<TransactionReceipt>,
}

#[derive(Debug, PartialEq)]
pub enum GindexOrPath {
    Gindex(usize),
    Path(Vec<SszVariableOrIndex>),
}

pub struct ProverConfig {
    pub consensus_rpc: String,
    pub execution_rpc: String,
    pub state_prover_rpc: String,
    pub historical_roots_enabled: bool,
    pub historical_roots_block_roots_batch_size: u64,
}

// A map from block number to a map from tx hash to messages
pub type BatchMessageGroups = IndexMap<u64, IndexMap<H256, Vec<EnrichedMessage>>>;
