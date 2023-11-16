use cosmwasm_schema::cw_serde;

use types::{
    common::{ChainConfig, Forks},
    consensus::{Bootstrap, Update},
    lightclient::{BlockVerificationData, EventVerificationData},
};

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct InstantiateMsg {
    pub bootstrap: Bootstrap,
    pub config: ChainConfig,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
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
        // #[serde(deserialize_with = "from_hex_array", serialize_with = "to_hex_array")]
        proof: Vec<Vec<u8>>,
        // #[serde(deserialize_with = "from_hex_string", serialize_with = "to_hex_string")]
        key: Vec<u8>,
        // #[serde(deserialize_with = "from_hex_string", serialize_with = "to_hex_string")]
        root: Vec<u8>, // TODO: set fixed size
    },
    VerifyTopicInclusion {
        // #[serde(deserialize_with = "from_hex_string", serialize_with = "to_hex_string")]
        receipt: Vec<u8>,
        // #[serde(deserialize_with = "from_hex_string", serialize_with = "to_hex_string")]
        topic: Vec<u8>,
    },
    EventVerificationData {
        payload: EventVerificationData,
    },
}

#[cw_serde]
pub enum QueryMsg {
    Greet {},
    SyncCommittee { period: u64 },
    LightClientState {},
    Config {},
    Version {},
}
