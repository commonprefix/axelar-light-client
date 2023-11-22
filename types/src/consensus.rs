use ssz_rs::prelude::*;
use sync_committee_rs::consensus_types::{BeaconBlock, BeaconState, SyncAggregate, SyncCommittee};
use sync_committee_rs::constants::{
    Bytes32, BYTES_PER_LOGS_BLOOM, EPOCHS_PER_HISTORICAL_VECTOR, EPOCHS_PER_SLASHINGS_VECTOR,
    ETH1_DATA_VOTES_BOUND, HISTORICAL_ROOTS_LIMIT, MAX_ATTESTATIONS, MAX_ATTESTER_SLASHINGS,
    MAX_BLS_TO_EXECUTION_CHANGES, MAX_BYTES_PER_TRANSACTION, MAX_DEPOSITS, MAX_EXTRA_DATA_BYTES,
    MAX_PROPOSER_SLASHINGS, MAX_TRANSACTIONS_PER_PAYLOAD, MAX_VALIDATORS_PER_COMMITTEE,
    MAX_VOLUNTARY_EXITS, MAX_WITHDRAWALS_PER_PAYLOAD, SLOTS_PER_HISTORICAL_ROOT,
    SYNC_COMMITTEE_SIZE, VALIDATOR_REGISTRY_LIMIT,
};

pub use sync_committee_rs::consensus_types::BeaconBlockHeader;

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone, Default)]
pub struct BeaconHeader {
    pub beacon: BeaconBlockHeader,
}

pub type BeaconBlockAlias = BeaconBlock<
    MAX_PROPOSER_SLASHINGS,
    MAX_VALIDATORS_PER_COMMITTEE,
    MAX_ATTESTER_SLASHINGS,
    MAX_ATTESTATIONS,
    MAX_DEPOSITS,
    MAX_VOLUNTARY_EXITS,
    SYNC_COMMITTEE_SIZE,
    BYTES_PER_LOGS_BLOOM,
    MAX_EXTRA_DATA_BYTES,
    MAX_BYTES_PER_TRANSACTION,
    MAX_TRANSACTIONS_PER_PAYLOAD,
    MAX_WITHDRAWALS_PER_PAYLOAD,
    MAX_BLS_TO_EXECUTION_CHANGES,
>;

pub type BeaconStateType = BeaconState<
    SLOTS_PER_HISTORICAL_ROOT,
    HISTORICAL_ROOTS_LIMIT,
    ETH1_DATA_VOTES_BOUND,
    VALIDATOR_REGISTRY_LIMIT,
    EPOCHS_PER_HISTORICAL_VECTOR,
    EPOCHS_PER_SLASHINGS_VECTOR,
    MAX_VALIDATORS_PER_COMMITTEE,
    SYNC_COMMITTEE_SIZE,
    BYTES_PER_LOGS_BLOOM,
    MAX_EXTRA_DATA_BYTES,
    MAX_BYTES_PER_TRANSACTION,
    MAX_TRANSACTIONS_PER_PAYLOAD,
>;

pub type BlockRootsType = Vector<Node, SLOTS_PER_HISTORICAL_ROOT>;

pub fn to_beacon_header(block: &BeaconBlockAlias) -> eyre::Result<BeaconBlockHeader> {
    Ok(BeaconBlockHeader {
        slot: block.slot,
        parent_root: block.parent_root.clone(),
        proposer_index: block.proposer_index,
        state_root: block.state_root.clone(),
        body_root: (block.body.clone()).hash_tree_root()?,
    })
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone, Default)]
pub struct Bootstrap {
    pub header: BeaconHeader,
    pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub current_sync_committee_branch: Vec<Bytes32>,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct Update {
    pub attested_header: BeaconHeader,
    pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub next_sync_committee_branch: Vec<Bytes32>,
    pub finalized_header: BeaconHeader,
    pub finality_branch: Vec<Bytes32>,
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    #[serde(with = "sync_committee_rs::serde::as_string")]
    pub signature_slot: u64,
}

impl Update {
    pub fn into_finality_update(&self) -> FinalityUpdate {
        FinalityUpdate {
            attested_header: self.attested_header.clone(),
            finalized_header: self.finalized_header.clone(),
            finality_branch: self.finality_branch.clone(),
            sync_aggregate: self.sync_aggregate.clone(),
            signature_slot: self.signature_slot,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct FinalityUpdate {
    pub attested_header: BeaconHeader,
    pub finalized_header: BeaconHeader,
    pub finality_branch: Vec<Bytes32>,
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    #[serde(with = "sync_committee_rs::serde::as_string")]
    pub signature_slot: u64,
}

impl FinalityUpdate {
    pub fn into_optimistic_update(&self) -> OptimisticUpdate {
        OptimisticUpdate {
            attested_header: self.attested_header.clone(),
            sync_aggregate: self.sync_aggregate.clone(),
            signature_slot: self.signature_slot,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct OptimisticUpdate {
    pub attested_header: BeaconHeader,
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    #[serde(with = "sync_committee_rs::serde::as_string")]
    pub signature_slot: u64,
}
