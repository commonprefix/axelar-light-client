pub use axelar_wasm_std::hash::Hash;
pub use connection_router::state::{Address as AddressType, ChainName, CrossChainId, Message};
use milagro_bls::PublicKey;
use serde::de::Visitor;
use serde::{de::Error as SerdeError, ser, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use sync_committee_rs::{consensus_types::SyncCommittee, constants::SYNC_COMMITTEE_SIZE};

#[derive(serde::Serialize, serde::Deserialize, Default, PartialEq, Debug, Clone)]
pub struct SyncCommitteeWithKeys {
    #[serde(
        serialize_with = "pubkey_array_serializer",
        deserialize_with = "pubkey_array_deserializer"
    )]
    pub keys: Vec<PublicKey>,
    pub committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
}

#[derive(Serialize, Deserialize, Default, PartialEq, Debug, Clone)]
pub struct LightClientState {
    pub update_slot: u64,
    pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub next_sync_committee: Option<SyncCommittee<SYNC_COMMITTEE_SIZE>>,
}

#[derive(Default, PartialEq, Debug, Clone)]
pub struct LightClientStateWithKeys {
    pub update_slot: u64,
    pub current_sync_committee: SyncCommitteeWithKeys,
    pub next_sync_committee: Option<SyncCommitteeWithKeys>,
}

fn pubkey_array_deserializer<'de, D>(deserializer: D) -> Result<Vec<PublicKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_strings = Vec::<String>::deserialize(deserializer)?;
    hex_strings
        .into_iter()
        .map(|s| {
            hex::decode(&s).map_err(D::Error::custom).and_then(|bytes| {
                PublicKey::from_uncompressed_bytes(&bytes.as_slice())
                    .map_err(|e| D::Error::custom(format!("deserializer {:?}", e)))
            })
        })
        .collect()
}

pub struct PublicKeyWrapper(pub PublicKey);
impl Serialize for PublicKeyWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_string = hex::encode(self.0.as_uncompressed_bytes());
        serializer.serialize_str(&hex_string)
    }
}

impl<'de> Deserialize<'de> for PublicKeyWrapper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct WrapperVisitor;

        impl<'de> Visitor<'de> for WrapperVisitor {
            type Value = PublicKeyWrapper;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a hex string representing 96 bytes")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                let bytes = hex::decode(value).map_err(SerdeError::custom)?;
                if bytes.len() != 96 {
                    return Err(SerdeError::invalid_length(bytes.len(), &self));
                }

                let mut arr = [0u8; 96];
                arr.copy_from_slice(&bytes);
                Ok(PublicKeyWrapper(
                    PublicKey::from_uncompressed_bytes(bytes.as_slice())
                        .map_err(|e| E::custom(format!("wrapper {:?}", e)))?,
                ))
            }
        }

        deserializer.deserialize_str(WrapperVisitor)
    }
}

fn pubkey_array_serializer<S>(keys_vec: &Vec<PublicKey>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let result: Vec<String> = keys_vec
        .iter()
        .map(|key| hex::encode(key.as_uncompressed_bytes()))
        .collect();
    serializer.collect_seq(result)
}
