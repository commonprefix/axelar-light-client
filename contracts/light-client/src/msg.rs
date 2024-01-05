use cosmwasm_schema::cw_serde;
use types::connection_router::state::Message;
use types::proofs::{nonempty, BatchVerificationData, Operators};
use types::{
    common::ChainConfig,
    consensus::{Bootstrap, Update},
};

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct InstantiateMsg {
    pub bootstrap: Bootstrap,
    pub config: ChainConfig,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[allow(clippy::large_enum_variant)] // TODO: Properly fix this
pub enum ExecuteMsg {
    LightClientUpdate {
        update: Update,
    },
    BatchVerificationData {
        payload: BatchVerificationData,
    },
    VerifyMessages {
        messages: Vec<Message>,
    },
    VerifyWorkerSet {
        message_id: nonempty::String,
        new_operators: Operators,
    },
}

#[cw_serde]
pub enum QueryMsg {
    SyncCommittee {},
    LightClientState {},
    Config {},
    Version {},
    IsVerified { messages: Vec<Message> },
    IsWorkerSetVerified { new_operators: Operators },
}
