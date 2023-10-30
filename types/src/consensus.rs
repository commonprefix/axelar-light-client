use serde;
use ssz_rs::prelude::*;
use std::vec;

use crate::common::{Address, BLSPubKey, Bytes32, SignatureBytes};
use crate::execution::ExecutionPayload;
use crate::primitives::{ByteVector, U64};

#[derive(
    serde::Serialize, serde::Deserialize, SimpleSerialize, PartialEq, Debug, Clone, Default,
)]
pub struct BeaconBlockHeader {
    pub slot: U64,
    pub proposer_index: U64,
    pub parent_root: Bytes32,
    pub state_root: Bytes32,
    pub body_root: Bytes32,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone, Default)]
pub struct BeaconHeader {
    pub beacon: BeaconBlockHeader,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default, SimpleSerialize, Clone)]
struct IndexedAttestation {
    attesting_indices: List<U64, 2048>,
    data: AttestationData,
    signature: SignatureBytes,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default, SimpleSerialize, Clone)]
pub struct BeaconBlock {
    pub slot: U64,
    pub proposer_index: U64,
    pub parent_root: Bytes32,
    pub state_root: Bytes32,
    pub body: BeaconBlockBody,
}

impl TryFrom<&BeaconBlock> for BeaconBlockHeader {
    type Error = eyre::Report;

    fn try_from(block: &BeaconBlock) -> std::result::Result<Self, Self::Error> {
        let body_root_node = (block.body.clone()).hash_tree_root()?;
        let body_root_serialized = ssz_rs::serialize(&body_root_node.clone())?;

        Ok(Self {
            parent_root: block.parent_root.clone(),
            slot: block.slot,
            proposer_index: block.proposer_index,
            state_root: block.state_root.clone(),
            body_root: ByteVector::try_from(body_root_serialized)?,
        })
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default, SimpleSerialize, Clone)]
pub struct BeaconBlockBody {
    randao_reveal: SignatureBytes,
    eth1_data: Eth1Data,
    graffiti: Bytes32,
    proposer_slashings: List<ProposerSlashing, 16>,
    attester_slashings: List<AttesterSlashing, 2>,
    attestations: List<Attestation, 128>,
    deposits: List<Deposit, 16>,
    voluntary_exits: List<SignedVoluntaryExit, 16>,
    pub sync_aggregate: SyncAggregate,
    pub execution_payload: ExecutionPayload,
    bls_to_execution_changes: List<SignedBlsToExecutionChange, 16>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default, SimpleSerialize, Clone)]
pub struct SignedVoluntaryExit {
    message: VoluntaryExit,
    signature: SignatureBytes,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default, SimpleSerialize, Clone)]
pub struct Eth1Data {
    deposit_root: Bytes32,
    deposit_count: U64,
    block_hash: Bytes32,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default, SimpleSerialize, Clone)]
struct VoluntaryExit {
    epoch: U64,
    validator_index: U64,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default, SimpleSerialize, Clone)]
pub struct Deposit {
    proof: Vector<Bytes32, 33>,
    data: DepositData,
}

#[derive(serde::Deserialize, serde::Serialize, Default, Debug, SimpleSerialize, Clone)]
struct DepositData {
    pubkey: BLSPubKey,
    withdrawal_credentials: Bytes32,
    amount: U64,
    signature: SignatureBytes,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default, SimpleSerialize, Clone)]
pub struct ProposerSlashing {
    signed_header_1: SignedBeaconBlockHeader,
    signed_header_2: SignedBeaconBlockHeader,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default, SimpleSerialize, Clone)]
struct SignedBeaconBlockHeader {
    message: BeaconBlockHeader,
    signature: SignatureBytes,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default, SimpleSerialize, Clone)]
pub struct AttesterSlashing {
    attestation_1: IndexedAttestation,
    attestation_2: IndexedAttestation,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default, SimpleSerialize, Clone)]
pub struct Attestation {
    aggregation_bits: Bitlist<2048>,
    data: AttestationData,
    signature: SignatureBytes,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default, SimpleSerialize, Clone)]
struct AttestationData {
    slot: U64,
    index: U64,
    beacon_block_root: Bytes32,
    source: Checkpoint,
    target: Checkpoint,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default, SimpleSerialize, Clone)]
struct Checkpoint {
    epoch: U64,
    root: Bytes32,
}

#[derive(Default, Clone, Debug, SimpleSerialize, serde::Deserialize, serde::Serialize)]
pub struct SignedBlsToExecutionChange {
    message: BlsToExecutionChange,
    signature: SignatureBytes,
}

#[derive(Default, Clone, Debug, SimpleSerialize, serde::Deserialize, serde::Serialize)]
pub struct BlsToExecutionChange {
    validator_index: U64,
    from_bls_pubkey: BLSPubKey,
    to_execution_address: Address,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone, Default)]
pub struct Bootstrap {
    pub header: BeaconHeader,
    pub current_sync_committee: SyncCommittee,
    pub current_sync_committee_branch: Vec<Bytes32>,
}

#[derive(
    serde::Serialize, serde::Deserialize, SimpleSerialize, PartialEq, Debug, Clone, Default,
)]
pub struct SyncCommittee {
    // Size of 512. Would use an array but would need to
    // Manually implement serialize, deserialize for it.
    pub pubkeys: Vector<BLSPubKey, 512>,
    pub aggregate_pubkey: BLSPubKey,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct Update {
    pub attested_header: BeaconHeader,
    pub next_sync_committee: SyncCommittee,
    pub next_sync_committee_branch: Vec<Bytes32>,
    pub finalized_header: BeaconHeader,
    pub finality_branch: Vec<Bytes32>,
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: U64,
}

#[derive(
    serde::Serialize, serde::Deserialize, SimpleSerialize, PartialEq, Debug, Clone, Default,
)]
pub struct SyncAggregate {
    pub sync_committee_bits: Bitvector<512>,
    pub sync_committee_signature: SignatureBytes,
}

#[derive(SimpleSerialize, Default, Debug)]
pub struct SigningData {
    pub object_root: Bytes32,
    pub domain: Bytes32,
}
