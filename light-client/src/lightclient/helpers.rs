use std::{fmt, sync::Arc};

use cita_trie::{MemoryDB, PatriciaTrie, Trie};
use eyre::Result;

use hasher::HasherKeccak;
use ssz_rs::{is_valid_merkle_branch, verify_merkle_proof, GeneralizedIndex, Merkleized, Node};
use sync_committee_rs::{
    constants::{
        Bytes32, Root, BLOCK_ROOTS_INDEX, BLOCK_ROOTS_INDEX_LOG2, EXECUTION_PAYLOAD_INDEX,
        EXECUTION_PAYLOAD_INDEX_LOG2,
    },
    types::BlockRootsProof,
};

pub fn is_proof_valid<L: Merkleized>(
    state_root: &Node,
    leaf_object: &mut L,
    branch: &[Bytes32],
    depth: usize,
    index: usize,
) -> bool {
    let res: Result<bool> = (move || {
        let leaf_hash = leaf_object.hash_tree_root()?;
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

pub fn verify_block_roots_proof(
    proof: &BlockRootsProof,
    block: &Node,
    block_roots_root: &Root,
) -> bool {
    verify_merkle_proof(
        block,
        &proof.block_header_branch[..],
        &GeneralizedIndex(proof.block_header_index as usize),
        block_roots_root,
    )
}

pub fn verify_block_roots_branch(
    block_roots_branch: &Vec<Node>,
    block_roots_root: &Node,
    state_root: &Root,
) -> bool {
    is_valid_merkle_branch(
        block_roots_root,
        block_roots_branch.iter(),
        BLOCK_ROOTS_INDEX_LOG2 as usize,
        BLOCK_ROOTS_INDEX as usize,
        state_root,
    )
}

pub fn verify_execution_payload_branch(
    execution_payload_branch: &Vec<Node>,
    execution_payload_root: &Root,
    state_root: &Root,
) -> bool {
    is_valid_merkle_branch(
        execution_payload_root,
        execution_payload_branch.iter(),
        EXECUTION_PAYLOAD_INDEX_LOG2 as usize,
        EXECUTION_PAYLOAD_INDEX as usize,
        state_root,
    )
}

pub fn verify_trie_proof(root: Root, key: u64, proof: Vec<Node>) -> Option<Vec<u8>> {
    let memdb = Arc::new(MemoryDB::new(true));
    let hasher = Arc::new(HasherKeccak::new());
    let proof_bytes = proof
        .into_iter()
        .map(|node| node.as_bytes().to_vec())
        .collect::<Vec<Vec<u8>>>();

    let trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));
    trie.verify_proof(root.as_bytes(), key.to_ne_bytes().as_ref(), proof_bytes)
        .unwrap()
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

    use ssz_rs::Node;
    use types::{
        common::{ChainConfig, Fork, Forks},
        consensus::{Bootstrap, Update},
        lightclient::{EventVerificationData, TopicInclusionRequest},
    };

    use super::hex_str_to_bytes;

    pub fn get_bootstrap() -> Bootstrap {
        let file = File::open("testdata/bootstrap.json").unwrap();
        let bootstrap: Bootstrap = serde_json::from_reader(file).unwrap();

        bootstrap
    }

    // Currently have in testdata: 767, 862, 863
    pub fn get_update(period: u64) -> Update {
        let path = format!("testdata/{}.json", period);
        let file = File::open(path).unwrap();
        let update: Update = serde_json::from_reader(file).unwrap();

        update
    }

    pub fn get_event_verification_data() -> EventVerificationData {
        let path = format!("testdata/event_verification_data.json");
        let file = File::open(path).unwrap();
        serde_json::from_reader(file).unwrap()
    }

    pub fn get_topic_inclusion_query() -> TopicInclusionRequest {
        let path = format!("testdata/topic_inclusion.json");
        let file = File::open(path).unwrap();
        let request: TopicInclusionRequest = serde_json::from_reader(file).unwrap();

        return request;
    }

    pub fn get_config() -> ChainConfig {
        let genesis_root_bytes: [u8; 32] =
            hex_str_to_bytes("0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
                .unwrap()
                .try_into()
                .unwrap();

        ChainConfig {
            chain_id: 1,
            genesis_time: 1606824023,
            genesis_root: Node::from_bytes(genesis_root_bytes),
            forks: get_forks(),
        }
    }

    pub fn get_forks() -> Forks {
        Forks {
            genesis: Fork {
                epoch: 0,
                fork_version: hex_str_to_bytes("0x00000000").unwrap().try_into().unwrap(),
            },
            altair: Fork {
                epoch: 74240,
                fork_version: hex_str_to_bytes("0x01000000").unwrap().try_into().unwrap(),
            },
            bellatrix: Fork {
                epoch: 144896,
                fork_version: hex_str_to_bytes("0x02000000").unwrap().try_into().unwrap(),
            },
            capella: Fork {
                epoch: 194048,
                fork_version: hex_str_to_bytes("0x03000000").unwrap().try_into().unwrap(),
            },
        }
    }
}
