use core::fmt;

use crate::cosmwasm_schema::schemars;
use axelar_wasm_std::nonempty;
use connection_router::state::{CrossChainId, Message};
use cosmwasm_schema::schemars::JsonSchema;
use serde::{
    de::{self, Visitor},
    Deserializer, Serializer,
};
use ssz_rs::prelude::*;
use sync_committee_rs::constants::{Epoch, Version};

/// Trait used to create the keys of the map which contains the verification results
pub trait PrimaryKey {
    fn key(&self) -> String;
}

type Fork = (Epoch, Version);

/// Chain configuration that is used from the Light Client module for the verification of signatures
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub genesis_time: u64,
    pub genesis_root: Node,
    #[serde(
        serialize_with = "serialize_forks",
        deserialize_with = "deserialize_forks"
    )]
    pub forks: Vec<Fork>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub enum FinalizationVariant {
    Optimistic(),
    Finality(),
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct Config {
    pub chain_config: ChainConfig,
    pub gateway_address: String,
    pub finalization: FinalizationVariant,
}

/// Message describing an update of the operators set
#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Clone, JsonSchema)]
pub struct WorkerSetMessage {
    pub message_id: nonempty::String,
    pub new_operators_data: Vec<u8>,
}

/// Message variants that the Light Client can verify
#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Clone)]
pub enum ContentVariant {
    Message(Message),
    WorkerSet(WorkerSetMessage),
}

impl Default for ContentVariant {
    fn default() -> Self {
        let message = Message {
            cc_id: CrossChainId {
                chain: String::from("ethereum").try_into().unwrap(),
                id: String::from("foo:bar").try_into().unwrap(),
            },
            source_address: String::from("0x0000000000000000000000000000000000000000")
                .try_into()
                .unwrap(),
            destination_chain: String::from("fantom").try_into().unwrap(),
            destination_address: String::from("0x0000000000000000000000000000000000000")
                .try_into()
                .unwrap(),
            payload_hash: Default::default(),
        };

        ContentVariant::Message(message)
    }
}

impl PrimaryKey for WorkerSetMessage {
    fn key(&self) -> String {
        format!("workersetmessage:{}", *self.message_id)
    }
}

impl PrimaryKey for Message {
    fn key(&self) -> String {
        format!("message:{}", self.cc_id)
    }
}

pub type VerificationResult = Vec<(String, String)>;

fn serialize_forks<S>(forks: &[Fork], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let formatted_forks: Vec<(u64, String)> = forks
        .iter()
        .map(|&(epoch, version)| (epoch, format!("0x{}", hex::encode(version))))
        .collect();
    serializer.collect_seq(formatted_forks)
}

fn deserialize_forks<'de, D>(deserializer: D) -> Result<Vec<Fork>, D::Error>
where
    D: Deserializer<'de>,
{
    struct ForksVisitor;

    impl<'de> Visitor<'de> for ForksVisitor {
        type Value = Vec<(Epoch, Version)>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an array of (Epoch, Version) pairs")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut forks: Vec<Fork> = Vec::new();

            while let Some((epoch, hex_version)) = seq.next_element::<(u64, String)>()? {
                let version_bytes =
                    hex::decode(hex_version.trim_start_matches("0x")).map_err(de::Error::custom)?;
                let version = version_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| de::Error::custom("Version should be 4 bytes long"))?;
                forks.push((epoch, version));
            }

            Ok(forks)
        }
    }

    deserializer.deserialize_seq(ForksVisitor)
}
