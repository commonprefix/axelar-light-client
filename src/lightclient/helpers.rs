use std::fmt;

use eyre::Result;
use ssz_rs::prelude::*;

use crate::lightclient::types::Bytes32;

pub fn is_proof_valid<L: Merkleized>(
    root: &Bytes32,
    leaf_object: &mut L,
    branch: &[Bytes32],
    depth: usize,
    index: usize,
) -> bool {
    let res: Result<bool> = (move || {
        let leaf_hash = leaf_object.hash_tree_root()?;
        let state_root = bytes32_to_node(root)?;
        let branch = branch_to_nodes(branch.to_vec())?;

        let is_valid = is_valid_merkle_branch(&leaf_hash, branch.iter(), depth, index, &state_root);
        Ok(is_valid)
    })();

    if let Ok(is_valid) = res {
        is_valid
    } else {
        false
    }
}

pub fn branch_to_nodes(branch: Vec<Bytes32>) -> Result<Vec<Node>> {
    branch
        .iter()
        .map(bytes32_to_node)
        .collect::<Result<Vec<Node>>>()
}

pub fn bytes32_to_node(bytes: &Bytes32) -> Result<Node> {
    Ok(Node::try_from(bytes.as_slice())?)
}

pub fn hex_str_to_bytes(s: &str) -> Result<Vec<u8>> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    Ok(hex::decode(stripped)?)
}

pub fn calc_sync_period(slot: u64) -> u64 {
    let epoch = slot / 32; // 32 slots per epoch
    epoch / 256 // 256 epochs per sync committee
}

pub fn from_hex_string<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct HexVisitor;

    impl<'de> serde::de::Visitor<'de> for HexVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string representing hex bytes")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            hex::decode(value.trim_start_matches("0x"))
                .map_err(|err| E::custom(format!("failed to decode hex: {}", err)))
        }
    }

    deserializer.deserialize_str(HexVisitor)
}

pub fn from_hex_array<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct HexArrayVisitor;

    impl<'de> serde::de::Visitor<'de> for HexArrayVisitor {
        type Value = Vec<Vec<u8>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an array of strings representing hex bytes")
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
        where
            S: serde::de::SeqAccess<'de>,
        {
            let mut vec = Vec::new();
            while let Some(hex_str) = seq.next_element::<String>()? {
                // Adjusted to expect owned String values
                let bytes = hex::decode(hex_str.trim_start_matches("0x")).map_err(|err| {
                    serde::de::Error::custom(format!("failed to decode hex: {}", err))
                })?;
                vec.push(bytes);
            }
            Ok(vec)
        }
    }

    deserializer.deserialize_seq(HexArrayVisitor)
}

pub fn to_hex_array<S>(bytes_array: &Vec<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;

    let mut seq = serializer.serialize_seq(Some(bytes_array.len()))?;

    for bytes in bytes_array {
        let hex_str = hex::encode(bytes);
        seq.serialize_element(&hex_str)?;
    }

    // End the sequence and return the result.
    seq.end()
}

pub fn to_hex_string<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let hex_str = hex::encode(bytes);
    serializer.serialize_str(&hex_str)
}

#[cfg(test)]
pub mod test_helpers {
    use std::fs::File;

    use crate::lightclient::types::{
        Bootstrap, ChainConfig, Fork, Forks, ReceiptVerificationRequest, Update,
    };

    use super::hex_str_to_bytes;

    pub fn get_bootstrap() -> Bootstrap {
        let file = File::open("testdata/bootstrap.json").unwrap();
        let bootstrap: Bootstrap = serde_json::from_reader(file).unwrap();

        return bootstrap;
    }

    // Currently have in testdata: 767, 862, 863
    pub fn get_update(period: u64) -> Update {
        let path = format!("testdata/{}.json", period);
        let file = File::open(path).unwrap();
        let update: Update = serde_json::from_reader(file).unwrap();

        return update;
    }

    pub fn get_receipt_verification_request() -> ReceiptVerificationRequest {
        let path = format!("testdata/receipt_proof.json");
        let file = File::open(path).unwrap();
        let request: ReceiptVerificationRequest = serde_json::from_reader(file).unwrap();

        return request;
    }

    pub fn get_config() -> ChainConfig {
        return ChainConfig {
            chain_id: 1,
            genesis_time: 1606824023,
            genesis_root: hex_str_to_bytes(
                "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
            )
            .unwrap(),
            forks: get_forks(),
        };
    }

    pub fn get_forks() -> Forks {
        return Forks {
            genesis: Fork {
                epoch: 0,
                fork_version: hex_str_to_bytes("0x00000000").unwrap(),
            },
            altair: Fork {
                epoch: 74240,
                fork_version: hex_str_to_bytes("0x01000000").unwrap(),
            },
            bellatrix: Fork {
                epoch: 144896,
                fork_version: hex_str_to_bytes("0x02000000").unwrap(),
            },
            capella: Fork {
                epoch: 194048,
                fork_version: hex_str_to_bytes("0x03000000").unwrap(),
            },
        };
    }
}
