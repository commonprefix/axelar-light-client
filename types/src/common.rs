use axelar_wasm_std::nonempty;
use connection_router::Message;
use ssz_rs::prelude::*;

pub trait PrimaryKey {
    fn key(&self) -> String;
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub genesis_time: u64,
    pub genesis_root: Node,
    pub forks: Forks,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug)]
pub struct Fork {
    pub epoch: u64,
    pub fork_version: [u8; 4],
}

#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug)]
pub struct Forks {
    pub genesis: Fork,
    pub altair: Fork,
    pub bellatrix: Fork,
    pub capella: Fork,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct WorkerSetMessage {
    pub message_id: nonempty::String,
    pub new_operators_data: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub enum ContentVariant {
    Message(Message),
    WorkerSet(WorkerSetMessage),
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
