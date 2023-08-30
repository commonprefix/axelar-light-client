use primitives::{ByteVector, U64};
use serde;

pub type Bytes32 = ByteVector<32>;
pub type BLSPubKey = ByteVector<48>;
pub type SignatureBytes = ByteVector<48>;

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct Header {
    pub slot: U64,
    pub proposer_index: U64,
    pub parent_root: Bytes32,
    pub state_root: Bytes32,
    pub body_root: Bytes32,
}

#[derive(serde::Deserialize, serde::Serialize, PartialEq, Debug, Clone)]
pub struct BeaconHeader {
    pub beacon: Header,
}

#[derive(serde::Deserialize, serde::Serialize, PartialEq, Debug, Clone)]
pub struct Bootstrap {
    pub genesis_time: U64,
    pub genesis_validator_root: Bytes32,
    pub slot: U64,
    pub committee: SyncCommittee,
}

#[derive(serde::Deserialize, serde::Serialize, PartialEq, Debug, Clone)]
pub struct SyncCommittee {
    // Size of 512. Would use an array but would need to
    // Manually implement serialize, deserialize for it.
    pub pubkeys: Vec<BLSPubKey>,
    pub aggregate_pubkey: BLSPubKey,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone, PartialEq)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub slot: u64,
    pub genesis_time: u64,
}

/**
 *
 * Primitives
 *
 */

pub(crate) mod primitives {

    /**
     * ByteVector: a fixed-length vector of bytes.
     */

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ByteVector<const N: usize> {
        inner: [u8; N],
    }

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
