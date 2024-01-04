use axelar_wasm_std::nonempty;
use connection_router::state::Message;
use ssz_rs::prelude::*;

pub trait PrimaryKey {
    fn key(&self) -> String;
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub genesis_time: u64,
    pub genesis_root: Node,
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
