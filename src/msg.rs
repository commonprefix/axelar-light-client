use cosmwasm_schema::cw_serde;
use serde::{Deserialize, Serialize};

use crate::types::{Bootstrap, ChainConfig, Update};

#[derive(Deserialize, Serialize, PartialEq, Debug, Clone)]
pub struct InstantiateMsg {
    pub bootstrap: Bootstrap,
    pub config: ChainConfig,
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
}
