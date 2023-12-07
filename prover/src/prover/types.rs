use consensus_types::consensus::BeaconBlockAlias;
use ethers::types::{Block, Transaction, TransactionReceipt};
use serde::{Deserialize, Serialize};
use ssz_rs::{Node, SszVariableOrIndex};
use sync_committee_rs::consensus_types::BeaconBlockHeader;

// Neccessary data for proving a message
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

#[derive(Deserialize, Debug, Serialize, Default)]
pub struct ProofResponse {
    pub gindex: u64,
    pub witnesses: Vec<Node>,
    pub leaf: Node,
}

#[derive(Debug)]
pub enum GindexOrPath {
    Gindex(usize),
    Path(Vec<SszVariableOrIndex>),
}

pub struct Config {
    pub consensus_rpc: String,
    pub execution_rpc: String,
    pub state_prover_rpc: String,
    pub gateway_addr: String,
    pub historical_roots_enabled: bool,
    pub historical_roots_block_roots_batch_size: u64,
}
