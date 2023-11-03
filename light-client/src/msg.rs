use connection_router::state::Message;
use cosmwasm_schema::cw_serde;
use serde::{Deserialize, Serialize};

use crate::lightclient::helpers::{from_hex_array, from_hex_string, to_hex_array, to_hex_string};
use types::{
    common::{ChainConfig, Forks},
    consensus::{Bootstrap, Update},
    lightclient::BlockVerificationData,
};

#[derive(Deserialize, Serialize, PartialEq, Debug, Clone)]
pub struct InstantiateMsg {
    pub bootstrap: Bootstrap,
    pub config: ChainConfig,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[allow(clippy::large_enum_variant)] // TODO: Properly fix this
pub enum ExecuteMsg {
    LightClientUpdate {
        period: u64,
        update: Update,
    },
    UpdateForks {
        forks: Forks,
    },
    VerifyBlock {
        verification_data: BlockVerificationData,
    },
    VerifyProof {
        #[serde(deserialize_with = "from_hex_array", serialize_with = "to_hex_array")]
        proof: Vec<Vec<u8>>,
        #[serde(deserialize_with = "from_hex_string", serialize_with = "to_hex_string")]
        key: Vec<u8>,
        #[serde(deserialize_with = "from_hex_string", serialize_with = "to_hex_string")]
        root: Vec<u8>, // TODO: set fixed size
    },
    VerifyTopicInclusion {
        #[serde(deserialize_with = "from_hex_string", serialize_with = "to_hex_string")]
        receipt: Vec<u8>,
        #[serde(deserialize_with = "from_hex_string", serialize_with = "to_hex_string")]
        topic: Vec<u8>,
    },
    VerifyMessages {
        messages: Vec<Message>,
    },
}

#[cw_serde]
pub enum QueryMsg {
    SyncCommittee { period: u64 },
    LightClientState {},
    Config {},
    Version {},
    PendingMessages {},
    IsVerified { messages: Vec<Message> },
}
