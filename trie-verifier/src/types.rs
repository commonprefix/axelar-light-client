use helpers::{from_hex_array, from_hex_string, to_hex_array, to_hex_string};
use serde::{Deserialize, Serialize};

use crate::helpers;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Default)]
pub struct VerificationRequest {
    #[serde(deserialize_with = "from_hex_array", serialize_with = "to_hex_array")]
    pub proof: Vec<Vec<u8>>,
    #[serde(deserialize_with = "from_hex_string", serialize_with = "to_hex_string")]
    pub key: Vec<u8>,
    #[serde(deserialize_with = "from_hex_string", serialize_with = "to_hex_string")]
    pub root: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct VerificationResponse {
    pub valid: bool,
}
