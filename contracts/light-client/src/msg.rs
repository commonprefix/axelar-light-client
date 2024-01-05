use cosmwasm_schema::cw_serde;
use types::common::Config;
use types::connection_router::state::Message;
use types::consensus::{Bootstrap, Update};
use types::proofs::{nonempty, BatchVerificationData, Operators};

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct InstantiateMsg {
    pub bootstrap: Bootstrap,
    pub config: Config,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[allow(clippy::large_enum_variant)] // TODO: Properly fix this
pub enum ExecuteMsg {
    LightClientUpdate {
        period: u64,
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
