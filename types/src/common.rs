use crate::cosmwasm_schema::schemars;
use axelar_wasm_std::nonempty;
use connection_router::state::{Message, CrossChainId};
use cosmwasm_schema::schemars::JsonSchema;
use ssz_rs::prelude::*;

/// Trait used to create the keys of the map which contains the verification results
pub trait PrimaryKey {
    fn key(&self) -> String;
}

/// Chain configuration that is used from the Light Client module for the verification of signatures
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub genesis_time: u64,
    pub genesis_root: Node,
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
            payload_hash: Default::default()
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