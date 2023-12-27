use cosmwasm_schema::cw_serde;
use types::lightclient::Message;
use types::proofs::BatchVerificationData;
use types::{
    common::{ChainConfig, Forks},
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
    LightClientUpdate { period: u64, update: Update },
    UpdateForks { forks: Forks },
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
}
