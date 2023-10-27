use eyre::Result;
use ssz_rs::prelude::*;

use crate::lightclient::types::{BeaconBlockHeader, Bytes32};

pub fn is_proof_valid<L: Merkleized>(
    attested_header: &BeaconBlockHeader,
    leaf_object: &mut L,
    branch: &[Bytes32],
    depth: usize,
    index: usize,
) -> bool {
    let res: Result<bool> = (move || {
        let leaf_hash = leaf_object.hash_tree_root()?;
        let state_root = bytes32_to_node(&attested_header.state_root)?;
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

#[cfg(test)]
pub mod test_helpers {
    use std::fs::File;

    use crate::lightclient::types::{Bootstrap, ChainConfig, Fork, Forks, Update};

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

    pub fn get_config() -> ChainConfig {
        ChainConfig {
            chain_id: 1,
            genesis_time: 1606824023,
            genesis_root: hex_str_to_bytes(
                "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
            )
            .unwrap(),
            forks: get_forks(),
        }
    }

    pub fn get_forks() -> Forks {
        Forks {
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
        }
    }
}
