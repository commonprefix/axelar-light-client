use std::vec;

use primitives::{ByteVector, U64};
use serde;
use ssz_rs::prelude::*;

pub type Bytes32 = ByteVector<32>;
pub type BLSPubKey = ByteVector<48>;
pub type SignatureBytes = ByteVector<96>;

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct LightClientState {
    pub finalized_header: Header,
    pub current_sync_committee: SyncCommittee,
    pub next_sync_committee: Option<SyncCommittee>,
    pub optimistic_header: Header,
    pub previous_max_active_participants: u64,
    pub current_max_active_participants: u64,
}

#[derive(
    serde::Serialize, serde::Deserialize, SimpleSerialize, PartialEq, Debug, Clone, Default,
)]
pub struct Header {
    pub slot: U64,
    pub proposer_index: U64,
    pub parent_root: Bytes32,
    pub state_root: Bytes32,
    pub body_root: Bytes32,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct BeaconHeader {
    pub beacon: Header,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
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

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct SyncAggregate {
    pub sync_committee_bits: Bitvector<512>,
    pub sync_committee_signature: SignatureBytes,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub genesis_time: u64,
    pub genesis_root: Vec<u8>,
}

/**
 *
 * Primitives
 *
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
}
