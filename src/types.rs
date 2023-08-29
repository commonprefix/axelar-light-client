use std::ops::Deref;

use primitives::{ByteVector, U64};
use ssz_rs::prelude::*;

pub type Bytes32 = ByteVector<32>;
pub type BLSPubKey = ByteVector<48>;
pub type SignatureBytes = ByteVector<48>;

#[derive(serde::Deserialize, SimpleSerialize, PartialEq, Debug, Clone, Default)]
pub struct Header {
    pub slot: U64,
    pub proposer_index: U64,
    pub parent_root: Bytes32,
    pub state_root: Bytes32,
    pub body_root: Bytes32,
}

#[derive(serde::Deserialize, SimpleSerialize, PartialEq, Debug, Clone, Default)]
pub struct BeaconHeader {
    pub beacon: Header,
}

#[derive(serde::Deserialize, SimpleSerialize, PartialEq, Debug, Clone, Default)]
pub struct Bootstrap {
    pub header: BeaconHeader,
    pub current_sync_committee: SyncCommittee,
}

#[derive(serde::Deserialize, SimpleSerialize, PartialEq, Debug, Clone, Default)]
pub struct SyncCommittee {
    pub pubkeys: Vector<BLSPubKey, 512>,
    pub aggregate_pubkey: BLSPubKey,
}

mod primitives {
    use ssz_rs::prelude::*;
    use std::ops::Deref;

    /**
     * ByteVector: a fixed-length vector of bytes.
     */

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct ByteVector<const N: usize> {
        inner: Vector<u8, N>,
    }

    impl<const N: usize> ByteVector<N> {
        pub fn as_slice(&self) -> &[u8] {
            self.inner.as_slice()
        }
    }

    impl<const N: usize> Deref for ByteVector<N> {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
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
