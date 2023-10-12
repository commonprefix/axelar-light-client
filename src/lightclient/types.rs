use std::vec;

use primitives::{ByteList, ByteVector, U64};
use serde;
use ssz_rs::prelude::*;

pub type Bytes32 = ByteVector<32>;
pub type BLSPubKey = ByteVector<48>;
pub type SignatureBytes = ByteVector<96>;
pub type LogsBloom = ByteVector<256>;
pub type Address = ByteVector<20>;
pub type Transaction = ByteList<1073741824>;

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone, Default)]
pub struct LightClientState {
    pub finalized_header: BeaconBlockHeader,
    pub current_sync_committee: SyncCommittee,
    pub next_sync_committee: Option<SyncCommittee>,
    pub previous_max_active_participants: u64,
    pub current_max_active_participants: u64,
}

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
pub struct ExecutionPayload {
    pub parent_hash: Bytes32,
    pub fee_recipient: Address,
    pub state_root: Bytes32,
    pub receipts_root: Bytes32,
    pub logs_bloom: LogsBloom,
    pub prev_randao: Bytes32,
    pub block_number: U64,
    pub gas_limit: U64,
    pub gas_used: U64,
    pub timestamp: U64,
    pub extra_data: ByteList<32>,
    pub base_fee_per_gas: U256,
    pub block_hash: Bytes32,
    pub transactions: List<Transaction, 1048576>,
    pub withdrawals: List<Withdrawal, 16>,
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
pub struct Withdrawal {
    index: U64,
    validator_index: U64,
    address: Address,
    amount: U64,
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

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub genesis_time: u64,
    pub genesis_root: Vec<u8>,
    pub forks: Forks,
}

#[derive(SimpleSerialize, Default, Debug)]
pub struct ForkData {
    pub current_version: Vector<u8, 4>,
    pub genesis_validator_root: Bytes32,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Default, Clone)]
pub struct Fork {
    pub epoch: u64,
    pub fork_version: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Default, Clone)]
pub struct Forks {
    pub genesis: Fork,
    pub altair: Fork,
    pub bellatrix: Fork,
    pub capella: Fork,
}

#[derive(SimpleSerialize, Default, Debug)]
pub struct SigningData {
    pub object_root: Bytes32,
    pub domain: Bytes32,
}

/**
 *
 * Primitives used to wrap ssz-rs types to make them serde compatible.
 * - ByteVector: a fixed-length vector of bytes.
 * - U64: a 64-bit unsigned integer.
 */

pub(crate) mod primitives {
    use serde;
    use ssz_rs::prelude::*;
    use std::ops::Deref;

    /**
     * ByteVector: a fixed-length vector of bytes.
     */

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct ByteVector<const N: usize> {
        inner: ssz_rs::Vector<u8, N>,
    }

    impl<const N: usize> ByteVector<N> {
        pub fn as_slice(&self) -> &[u8] {
            self.inner.as_slice()
        }
    }

    impl<const N: usize> TryFrom<Vec<u8>> for ByteVector<N> {
        type Error = eyre::Report;

        fn try_from(value: Vec<u8>) -> std::result::Result<Self, Self::Error> {
            Ok(Self {
                inner: Vector::try_from(value).map_err(|(_, err)| err)?,
            })
        }
    }

    impl<const N: usize> TryFrom<&[u8]> for ByteVector<N> {
        type Error = eyre::Report;

        fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
            Ok(Self {
                inner: Vector::try_from(value.to_vec()).map_err(|(_, err)| err)?,
            })
        }
    }

    impl<const N: usize> Deref for ByteVector<N> {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            self.inner.as_slice()
        }
    }

    impl<const N: usize> ssz_rs::Merkleized for ByteVector<N> {
        fn hash_tree_root(&mut self) -> std::result::Result<Node, MerkleizationError> {
            self.inner.hash_tree_root()
        }
    }

    impl<const N: usize> ssz_rs::Sized for ByteVector<N> {
        fn size_hint() -> usize {
            0
        }

        fn is_variable_size() -> bool {
            false
        }
    }

    impl<const N: usize> ssz_rs::Serialize for ByteVector<N> {
        fn serialize(&self, buffer: &mut Vec<u8>) -> std::result::Result<usize, SerializeError> {
            self.inner.serialize(buffer)
        }
    }

    impl<const N: usize> ssz_rs::Deserialize for ByteVector<N> {
        fn deserialize(encoding: &[u8]) -> std::result::Result<Self, DeserializeError>
        where
            Self: std::marker::Sized,
        {
            Ok(Self {
                inner: Vector::deserialize(encoding)?,
            })
        }
    }

    impl<const N: usize> ssz_rs::SimpleSerialize for ByteVector<N> {}

    impl<const N: usize> serde::Serialize for ByteVector<N> {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let s = format!("0x{}", hex::encode(&self.inner));
            serializer.serialize_str(&s)
        }
    }

    impl<'de, const N: usize> serde::Deserialize<'de> for ByteVector<N> {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let bytes: String = serde::Deserialize::deserialize(deserializer)?;
            let bytes = hex::decode(bytes.strip_prefix("0x").unwrap()).unwrap();
            Ok(Self {
                inner: bytes.to_vec().try_into().unwrap(),
            })
        }
    }

    /**
     * U64: a 64-bit unsigned integer.
     */

    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
    pub struct U64 {
        inner: u64,
    }

    impl U64 {
        pub fn as_u64(&self) -> u64 {
            self.inner
        }
    }

    impl From<U64> for u64 {
        fn from(value: U64) -> Self {
            value.inner
        }
    }

    impl From<u64> for U64 {
        fn from(value: u64) -> Self {
            Self { inner: value }
        }
    }

    impl ssz_rs::Merkleized for U64 {
        fn hash_tree_root(&mut self) -> std::result::Result<Node, MerkleizationError> {
            self.inner.hash_tree_root()
        }
    }

    impl ssz_rs::Sized for U64 {
        fn size_hint() -> usize {
            0
        }

        fn is_variable_size() -> bool {
            false
        }
    }

    impl ssz_rs::Serialize for U64 {
        fn serialize(&self, buffer: &mut Vec<u8>) -> std::result::Result<usize, SerializeError> {
            self.inner.serialize(buffer)
        }
    }

    impl ssz_rs::Deserialize for U64 {
        fn deserialize(encoding: &[u8]) -> std::result::Result<Self, DeserializeError>
        where
            Self: std::marker::Sized,
        {
            Ok(Self {
                inner: u64::deserialize(encoding)?,
            })
        }
    }

    impl ssz_rs::SimpleSerialize for U64 {}

    impl serde::Serialize for U64 {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str(&self.inner.to_string())
        }
    }

    impl<'de> serde::Deserialize<'de> for U64 {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let val: String = serde::Deserialize::deserialize(deserializer)?;
            Ok(Self {
                inner: val.parse().unwrap(),
            })
        }
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct ByteList<const N: usize> {
        inner: List<u8, N>,
    }

    impl<const N: usize> ByteList<N> {
        pub fn as_slice(&self) -> &[u8] {
            self.inner.as_slice()
        }
    }

    impl<const N: usize> Deref for ByteList<N> {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            self.inner.as_slice()
        }
    }

    impl<const N: usize> TryFrom<Vec<u8>> for ByteList<N> {
        type Error = eyre::Report;

        fn try_from(value: Vec<u8>) -> std::result::Result<Self, Self::Error> {
            Ok(Self {
                inner: List::try_from(value).map_err(|(_, err)| err)?,
            })
        }
    }

    impl<const N: usize> TryFrom<&[u8]> for ByteList<N> {
        type Error = eyre::Report;

        fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
            Ok(Self {
                inner: List::try_from(value.to_vec()).map_err(|(_, err)| err)?,
            })
        }
    }

    impl<const N: usize> ssz_rs::Merkleized for ByteList<N> {
        fn hash_tree_root(&mut self) -> std::result::Result<Node, MerkleizationError> {
            self.inner.hash_tree_root()
        }
    }

    impl<const N: usize> ssz_rs::Sized for ByteList<N> {
        fn size_hint() -> usize {
            0
        }

        fn is_variable_size() -> bool {
            false
        }
    }

    impl<const N: usize> ssz_rs::Serialize for ByteList<N> {
        fn serialize(&self, buffer: &mut Vec<u8>) -> std::result::Result<usize, SerializeError> {
            self.inner.serialize(buffer)
        }
    }

    impl<const N: usize> ssz_rs::Deserialize for ByteList<N> {
        fn deserialize(encoding: &[u8]) -> std::result::Result<Self, DeserializeError>
        where
            Self: std::marker::Sized,
        {
            Ok(Self {
                inner: List::deserialize(encoding)?,
            })
        }
    }

    impl<const N: usize> ssz_rs::SimpleSerialize for ByteList<N> {}

    impl<'de, const N: usize> serde::Deserialize<'de> for ByteList<N> {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let bytes: String = serde::Deserialize::deserialize(deserializer)?;
            let bytes = hex::decode(bytes.strip_prefix("0x").unwrap()).unwrap();
            Ok(Self {
                inner: bytes.to_vec().try_into().unwrap(),
            })
        }
    }

    impl<const N: usize> serde::Serialize for ByteList<N> {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let s = format!("0x{}", hex::encode(&self.inner));
            serializer.serialize_str(&s)
        }
    }
}
