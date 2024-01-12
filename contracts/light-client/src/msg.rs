use cosmwasm_std::Response;
use cw_ownable::{cw_ownable_execute, cw_ownable_query};
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

#[cw_ownable_execute]
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[allow(clippy::large_enum_variant)] // TODO: Properly fix this
pub enum ExecuteMsg {
    LightClientUpdate { update: Update },
    BatchVerificationData { payload: BatchVerificationData },
    UpdateConfig(Config),
}

#[cw_ownable_query]
#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Response)]
    LightClientState {},
    #[returns(Response)]
    Config {},
    #[returns(Vec<(Message, bool)>)]
    IsVerified { messages: Vec<Message> },
    #[returns(bool)]
    IsWorkerSetVerified { message: WorkerSetMessage },
}
