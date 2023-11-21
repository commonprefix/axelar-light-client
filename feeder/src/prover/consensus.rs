use consensus_types::{
    consensus::{BeaconBlockAlias, BeaconStateType, BlockRootsType},
    proofs::{AncestryProof, BlockRootsProof},
};
use eyre::Result;
use ssz_rs::{get_generalized_index, Node, SszVariableOrIndex};
use sync_committee_rs::constants::{BLOCK_ROOTS_INDEX, SLOTS_PER_HISTORICAL_ROOT};
/**
 * Generates a merkle proof from the transactions to the execution payload of
 * the beacon block body.
*/
pub fn generate_transactions_branch(beacon_block: &mut BeaconBlockAlias) -> Result<Vec<Node>> {
    let path = vec![SszVariableOrIndex::Name("transactions")];
    // println!("{:#?}", beacon_block.body.execution_payload);
    let g_index = get_generalized_index(&beacon_block.body.execution_payload, &path);
    let proof = ssz_rs::generate_proof(&mut beacon_block.body.execution_payload, &[g_index])?;

    Ok(proof)
}

/**
 * Generates a merkle proof from the receipts_root to the execution payload of
 * the beacon block body.
*/
pub fn generate_receipts_branch(beacon_block: &mut BeaconBlockAlias) -> Result<Vec<Node>> {
    let path = vec![SszVariableOrIndex::Name("receipts_root")];
    let g_index = get_generalized_index(&beacon_block.body.execution_payload, &path);
    let proof = ssz_rs::generate_proof(&mut beacon_block.body.execution_payload, &[g_index])?;

    Ok(proof)
}

/**
 * Generates a merkle proof from the execution payload to the beacon block body.
*/
pub fn generate_exec_payload_branch(beacon_block: &mut BeaconBlockAlias) -> Result<Vec<Node>> {
    let path = vec![SszVariableOrIndex::Name("execution_payload")];
    let g_index = get_generalized_index(&beacon_block.body, &path);
    let proof = ssz_rs::generate_proof(&mut beacon_block.body, &[g_index])?;

    Ok(proof)
}

/**
 * Generates an ancestry proof from the recent block state to the target block
 * using either the block_roots or the historical_roots beacon state property.
*/
pub fn prove_ancestry(
    recent_block_state: &mut BeaconStateType,
    target_block_slot: u64,
) -> Result<AncestryProof> {
    let is_in_block_roots_range = target_block_slot < recent_block_state.slot
        && recent_block_state.slot <= target_block_slot + SLOTS_PER_HISTORICAL_ROOT as u64;

    let proof = if is_in_block_roots_range {
        prove_ancestry_with_block_roots(recent_block_state, target_block_slot)?
    } else {
        prove_ancestry_with_historical_roots(recent_block_state, target_block_slot)?
    };

    Ok(proof)
}

/**
 * Generates a proof from the block_roots_root to the beacon state root.
*/
pub fn generate_block_roots_branch(beacon_state: &mut BeaconStateType) -> Result<Vec<Node>> {
    let path = &[BLOCK_ROOTS_INDEX as usize];
    let proof = ssz_rs::generate_proof(beacon_state, path)?;

    Ok(proof)
}

/**
 * Generates a proof from the interested block to the block_roots_root.
*/
pub fn generate_block_root_proof(
    block_roots: &mut BlockRootsType,
    g_index: usize,
) -> Result<Vec<Node>> {
    let proof = ssz_rs::generate_proof(block_roots, &[g_index])?;

    Ok(proof)
}

/**
 * Generates an ancestry proof from the recent block state to the target block
 * using the block_roots beacon state property. The target block must in
 * the range [recent_block_slot - SLOTS_PER_HISTORICAL_ROOT, recent_block_slot].
 */
pub fn prove_ancestry_with_block_roots(
    recent_block_state: &mut BeaconStateType,
    target_block_slot: u64,
) -> Result<AncestryProof> {
    let block_index = get_generalized_index(
        &recent_block_state.block_roots,
        &[SszVariableOrIndex::Index(
            target_block_slot as usize % SLOTS_PER_HISTORICAL_ROOT,
        )],
    );

    let block_roots_proof = BlockRootsProof {
        block_header_index: block_index as u64,
        block_header_branch: generate_block_root_proof(
            &mut recent_block_state.block_roots,
            block_index,
        )?,
    };

    let block_roots_branch = generate_block_roots_branch(recent_block_state)?;

    let ancestry_proof = AncestryProof::BlockRoots {
        block_roots_proof,
        block_roots_branch,
    };

    Ok(ancestry_proof)
}

/**
 * Generates an ancestry proof from the recent block state to the target block
 * using the historical_roots beacon state property. The target block should be
 * in a slot less than recent_block_slot - SLOTS_PER_HISTORICAL_ROOT.
 */
pub fn prove_ancestry_with_historical_roots(
    _recent_block_state: &BeaconStateType,
    _target_block_slot: u64,
) -> Result<AncestryProof> {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use crate::prover::consensus::{
        generate_exec_payload_branch, generate_receipts_branch, generate_transactions_branch,
    };
    use consensus_types::consensus::BeaconBlockAlias;
    use ssz_rs::{GeneralizedIndex, Merkleized};
    use std::fs::File;

    pub fn get_beacon_block() -> BeaconBlockAlias {
        let file = File::open("./src/prover/testdata/beacon_block.json").unwrap();
        serde_json::from_reader(file).unwrap()
    }

    // Execution payload to beacon block body
    const EXECUTION_PAYLOAD_G_INDEX: usize = 25;

    // Generalized indices to execution payload
    const RECEIPTS_ROOT_G_INDEX: usize = 19;
    const TRANSACTIONS_G_INDEX: usize = 29;

    #[test]
    fn test_execution_payload_branch() {
        let mut beacon_block = get_beacon_block();
        let proof = generate_exec_payload_branch(&mut beacon_block).unwrap();

        let is_proof_valid = ssz_rs::verify_merkle_proof(
            &beacon_block
                .body
                .execution_payload
                .hash_tree_root()
                .unwrap(),
            proof.as_slice(),
            &GeneralizedIndex(EXECUTION_PAYLOAD_G_INDEX),
            &beacon_block.body.hash_tree_root().unwrap(),
        );

        assert!(is_proof_valid);
    }

    #[test]
    fn test_receipts_branch() {
        let mut beacon_block = get_beacon_block();
        let proof = generate_receipts_branch(&mut beacon_block).unwrap();

        let is_proof_valid = ssz_rs::verify_merkle_proof(
            &beacon_block
                .body
                .execution_payload
                .receipts_root
                .hash_tree_root()
                .unwrap(),
            proof.as_slice(),
            &GeneralizedIndex(RECEIPTS_ROOT_G_INDEX),
            &beacon_block
                .body
                .execution_payload
                .hash_tree_root()
                .unwrap(),
        );

        assert!(is_proof_valid);
    }

    #[test]
    fn test_transactions_branch() {
        let mut beacon_block = get_beacon_block();
        let proof = generate_transactions_branch(&mut beacon_block).unwrap();

        let is_proof_valid = ssz_rs::verify_merkle_proof(
            &beacon_block
                .body
                .execution_payload
                .transactions
                .hash_tree_root()
                .unwrap(),
            proof.as_slice(),
            &GeneralizedIndex(TRANSACTIONS_G_INDEX),
            &beacon_block
                .body
                .execution_payload
                .hash_tree_root()
                .unwrap(),
        );

        assert!(is_proof_valid);
    }
}
