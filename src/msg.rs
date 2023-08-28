use cosmwasm_schema::cw_serde;
use serde::{Deserialize, Serialize};

use crate::types::Bootstrap;

#[derive(Deserialize, Serialize, PartialEq, Debug, Clone)]
pub struct InstantiateMsg {
    pub bootstrap: Bootstrap,
}

#[cw_serde]
pub enum ExecuteMsg {}

#[cw_serde]
pub enum QueryMsg {
    Greet {},
    Bootstrap {},
}
