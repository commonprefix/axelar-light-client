use ssz_rs::prelude::*;
use sync_committee_rs::consensus_types::{
    BeaconBlock, BeaconBlockHeader, SyncAggregate, SyncCommittee,
};
use sync_committee_rs::constants::{
    Bytes32, BYTES_PER_LOGS_BLOOM, MAX_ATTESTATIONS, MAX_ATTESTER_SLASHINGS,
    MAX_BLS_TO_EXECUTION_CHANGES, MAX_BYTES_PER_TRANSACTION, MAX_DEPOSITS, MAX_EXTRA_DATA_BYTES,
    MAX_PROPOSER_SLASHINGS, MAX_TRANSACTIONS_PER_PAYLOAD, MAX_VALIDATORS_PER_COMMITTEE,
    MAX_VOLUNTARY_EXITS, MAX_WITHDRAWALS_PER_PAYLOAD, SYNC_COMMITTEE_SIZE,
};

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

// impl TryFrom<&BeaconBlock> for BeaconBlockHeader {
//     type Error = eyre::Report;

//     fn try_from(block: &BeaconBlock) -> std::result::Result<Self, Self::Error> {
//         let body_root_node = (block.body.clone()).hash_tree_root()?;
//         let body_root_serialized = ssz_rs::serialize(&body_root_node.clone())?;

//         Ok(Self {
//             parent_root: block.parent_root.clone(),
//             slot: block.slot,
//             proposer_index: block.proposer_index,
//             state_root: block.state_root.clone(),
//             body_root: ByteVector::try_from(body_root_serialized)?,
//         })
//     }
// }

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
    pub signature_slot: u64,
}

impl Update {
    pub fn into_finality_update(&self) -> FinalityUpdate {
        FinalityUpdate {
            attested_header: self.attested_header.clone(),
            finalized_header: self.finalized_header.clone(),
            finality_branch: self.finality_branch.clone(),
            sync_aggregate: self.sync_aggregate.clone(),
            signature_slot: self.signature_slot.clone(),
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct FinalityUpdate {
    pub attested_header: BeaconHeader,
    pub finalized_header: BeaconHeader,
    pub finality_branch: Vec<Bytes32>,
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    pub signature_slot: u64,
}

impl FinalityUpdate {
    pub fn into_optimistic_update(&self) -> OptimisticUpdate {
        OptimisticUpdate {
            attested_header: self.attested_header.clone(),
            sync_aggregate: self.sync_aggregate.clone(),
            signature_slot: self.signature_slot.clone(),
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct OptimisticUpdate {
    pub attested_header: BeaconHeader,
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    pub signature_slot: u64,
}
