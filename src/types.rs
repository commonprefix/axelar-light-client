use primitives::{ByteVector, U64};
use serde::{Deserialize, Serialize};
use ssz_rs::Bitvector;

pub type Bytes32 = ByteVector<32>;
pub type BLSPubKey = ByteVector<48>;
pub type SignatureBytes = ByteVector<96>;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Header {
    pub slot: U64,
    pub proposer_index: U64,
    pub parent_root: Bytes32,
    pub state_root: Bytes32,
    pub body_root: Bytes32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct BeaconHeader {
    pub beacon: Header,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Bootstrap {
    pub genesis_time: U64,
    pub genesis_validator_root: Bytes32,
    pub slot: U64,
    pub committee: SyncCommittee,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct SyncCommittee {
    // Size of 512. Would use an array but would need to
    // Manually implement serialize, deserialize for it.
    pub pubkeys: Vec<BLSPubKey>,
    pub aggregate_pubkey: BLSPubKey,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Update {
    pub attested_header: BeaconHeader,
    pub next_sync_committee: SyncCommittee,
    pub next_sync_committee_branch: Vec<Bytes32>,
    pub finalized_header: BeaconHeader,
    pub finality_branch: Vec<Bytes32>,
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: U64,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct SyncAggregate {
    pub sync_committee_bits: Bitvector<512>,
    pub sync_committee_signature: SignatureBytes,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
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
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /**
     * ByteVector: a fixed-length vector of bytes.
     */

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ByteVector<const N: usize> {
        inner: [u8; N],
    }

    impl<const N: usize> Serialize for ByteVector<N> {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let s = format!("0x{}", hex::encode(&self.inner));
            serializer.serialize_str(&s)
        }
    }

    impl<'de, const N: usize> Deserialize<'de> for ByteVector<N> {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes: String = Deserialize::deserialize(deserializer)?;
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

    impl Serialize for U64 {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&self.inner.to_string())
        }
    }

    impl<'de> Deserialize<'de> for U64 {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let val: String = Deserialize::deserialize(deserializer)?;
            Ok(Self {
                inner: val.parse().unwrap(),
            })
        }
    }
}
