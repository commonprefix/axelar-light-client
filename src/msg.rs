use cosmwasm_schema::cw_serde;
use serde::{Deserialize, Serialize};

use crate::lightclient::types::{Bootstrap, ChainConfig, Forks, Update};

#[derive(Deserialize, Serialize, PartialEq, Debug, Clone)]
pub struct InstantiateMsg {
    pub bootstrap: Bootstrap,
    pub config: ChainConfig,
    pub forks: Forks,
}

#[derive(Deserialize, Serialize, PartialEq, Debug, Clone)]
pub enum ExecuteMsg {
    Update { period: u64, update: Update },
}

#[cw_serde]
pub enum QueryMsg {
    Greet {},
    Bootstrap {},
    Update { period: u64 },
    LightClientState {},
    Forks {},
}
