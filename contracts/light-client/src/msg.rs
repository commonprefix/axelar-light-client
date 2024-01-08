use types::common::{Config, WorkerSetMessage};
use types::connection_router::state::Message;
use types::consensus::{Bootstrap, Update};
use types::cosmwasm_schema::*;
use types::proofs::BatchVerificationData;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct InstantiateMsg {
    pub bootstrap: Bootstrap,
    pub config: Config,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[allow(clippy::large_enum_variant)] // TODO: Properly fix this
pub enum ExecuteMsg {
    LightClientUpdate { update: Update },
    BatchVerificationData { payload: BatchVerificationData },
    VerifyMessages { messages: Vec<Message> },
}

#[cw_serde]
pub enum QueryMsg {
    SyncCommittee {},
    LightClientState {},
    Config {},
    Version {},
    IsVerified { messages: Vec<Message> },
    IsWorkerSetVerified { message: WorkerSetMessage },
}
