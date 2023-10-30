use helpers::{from_hex_array, from_hex_string, to_hex_array, to_hex_string};
use serde::{Deserialize, Serialize};

use crate::helpers;

#[derive(Deserialize, Serialize, PartialEq, Debug, Clone)]
pub enum ExecuteMsg {
    VerifyProof {
        #[serde(deserialize_with = "from_hex_array", serialize_with = "to_hex_array")]
        proof: Vec<Vec<u8>>,
        #[serde(deserialize_with = "from_hex_string", serialize_with = "to_hex_string")]
        key: Vec<u8>,
        #[serde(deserialize_with = "from_hex_string", serialize_with = "to_hex_string")]
        root: Vec<u8>, // TODO: set fixed size
    },
    Test {},
}
