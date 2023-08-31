use eyre::Result;
use ssz_rs::prelude::*;

use crate::types::{Bytes32, ChainConfig, Header};

pub fn calc_sync_period(slot: u64) -> u64 {
    let epoch = slot / 32; // 32 slots per epoch
    epoch / 256 // 256 epochs per sync committee
}

// pub fn is_aggregate_valid(sig_bytes: &SignatureBytes, msg: &[u8], pks: &[&PublicKey]) -> bool {
//     let sig_res = AggregateSignature::from_bytes(sig_bytes);
//     match sig_res {
//         Ok(sig) => sig.fast_aggregate_verify(msg, pks),
//         Err(_) => false,
//     }
// }

pub fn is_proof_valid<L: Merkleized>(
    attested_header: &Header,
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

fn slot_timestamp(config: ChainConfig, slot: u64) -> u64 {
    slot * 12 + config.genesis_time
}

pub fn hex_str_to_bytes(s: &str) -> Result<Vec<u8>> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    Ok(hex::decode(stripped)?)
}
