use cosmwasm_schema::cw_serde;
use serde::{Deserialize, Serialize};

use crate::lightclient::types::{Bootstrap, ChainConfig, Forks, Update};

#[derive(Deserialize, Serialize, PartialEq, Debug, Clone)]
pub struct InstantiateMsg {
    pub bootstrap: Bootstrap,
    pub config: ChainConfig,
}

#[derive(Deserialize, Serialize, PartialEq, Debug, Clone)]
#[allow(clippy::large_enum_variant)] // TODO: Properly fix this
pub enum ExecuteMsg {
    LightClientUpdate { period: u64, update: Update },
    UpdateForks { forks: Forks },
}

#[cw_serde]
pub enum QueryMsg {
    Greet {},
    SyncCommittee { period: u64 },
    LightClientState {},
    Config {},
    Version {},
}
