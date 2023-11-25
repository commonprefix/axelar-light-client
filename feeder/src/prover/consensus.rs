use crate::error::RpcError;
use crate::eth::{constants::STATE_PROVER_RPC, utils::get};
use crate::prover::types::ProofResponse;
use consensus_types::{consensus::BeaconStateType, proofs::AncestryProof};
use eyre::Result;
use ssz_rs::{get_generalized_index, SszVariableOrIndex};
use sync_committee_rs::constants::SLOTS_PER_HISTORICAL_ROOT;

/**
 * Generates a merkle proof from the transaction to the beacon block root.
*/
pub async fn generate_transaction_branch(
    block_id: &String,
    tx_index: u64,
) -> Result<ProofResponse> {
    let path = vec![
        SszVariableOrIndex::Name("body"),
        SszVariableOrIndex::Name("execution_payload"),
        SszVariableOrIndex::Name("transactions"),
        SszVariableOrIndex::Index(tx_index as usize),
    ];

    let proof = get_block_proof(block_id, path).await?;
    Ok(proof)
}

/**
 * Generates a merkle proof from the receipts_root to the beacon block root.
*/
pub async fn generate_receipts_root_branch(block_id: &String) -> Result<ProofResponse> {
    let path = vec![
        SszVariableOrIndex::Name("body"),
        SszVariableOrIndex::Name("execution_payload"),
        SszVariableOrIndex::Name("receipts_root"),
    ];

    let proof = get_block_proof(block_id, path).await?;
    Ok(proof)
}

/**
 * Generates an ancestry proof from the recent block state to the target block
 * using either the block_roots or the historical_roots beacon state property.
*/
pub async fn prove_ancestry(
    target_block_slot: u64,
    recent_block_slot: u64,
    recent_block_state_id: String,
) -> Result<AncestryProof> {
    let is_in_block_roots_range = target_block_slot < recent_block_slot
        && recent_block_slot <= target_block_slot + SLOTS_PER_HISTORICAL_ROOT as u64;

    let proof = if is_in_block_roots_range {
        prove_ancestry_with_block_roots(target_block_slot, recent_block_state_id).await?
    } else {
        unimplemented!()
    };

    Ok(proof)
}

/**
 * Generates an ancestry proof from the recent block state to the target block
 * using the block_roots beacon state property using the lodestar prover. The
 * target block must in the range
 * [recent_block_slot - SLOTS_PER_HISTORICAL_ROOT, recent_block_slot].
 */
pub async fn prove_ancestry_with_block_roots(
    target_block_slot: u64,
    recent_block_state_id: String,
) -> Result<AncestryProof> {
    let index = target_block_slot as usize % SLOTS_PER_HISTORICAL_ROOT;
    let g_index_from_state_root = get_generalized_index(
        &BeaconStateType::default(),
        &[
            SszVariableOrIndex::Name("block_roots"),
            SszVariableOrIndex::Index(index),
        ],
    ) as u64;

    let res = get_state_proof(recent_block_state_id, g_index_from_state_root).await?;

    let ancestry_proof = AncestryProof::BlockRoots {
        block_roots_index: g_index_from_state_root as u64,
        block_root_proof: res.witnesses,
    };

    Ok(ancestry_proof)
}

/**
 * Generates an ancestry proof from the recent block state to the target block
 * using the historical_roots beacon state property. The target block should be
 * in a slot less than recent_block_slot - SLOTS_PER_HISTORICAL_ROOT.
 */
pub fn _prove_ancestry_with_historical_roots(
    _recent_block_state: &BeaconStateType,
    _target_block_slot: u64,
) -> Result<AncestryProof> {
    unimplemented!()
}

async fn get_state_proof(state_id: String, gindex: u64) -> Result<ProofResponse> {
    let req = format!(
        "{}/state_proof/?state_id={}&gindex={}",
        STATE_PROVER_RPC, state_id, gindex
    );

    let res: ProofResponse = get(&req)
        .await
        .map_err(|e| RpcError::new("get_state_proof", e))?;

    Ok(res)
}

async fn get_block_proof(
    block_id: &String,
    path: Vec<SszVariableOrIndex>,
) -> Result<ProofResponse> {
    fn parse_path(path: Vec<SszVariableOrIndex>) -> String {
        let mut path_str = String::new();
        for p in path {
            match p {
                SszVariableOrIndex::Name(name) => path_str.push_str(&format!(",{}", name)),
                SszVariableOrIndex::Index(index) => path_str.push_str(&format!(",{}", index)),
            }
        }
        path_str[1..].to_string() // remove first comma
    }

    let path = parse_path(path);
    let req = format!(
        "{}/block_proof/?block_id={}&path={}",
        STATE_PROVER_RPC, block_id, path
    );
    println!("{}", req);

    let res: ProofResponse = get(&req)
        .await
        .map_err(|e| RpcError::new("get_block_proof", e))?;

    Ok(res)
}

#[cfg(test)]
mod tests {
    use crate::eth::consensus::ConsensusRPC;
    use crate::eth::constants::CONSENSUS_RPC;
    use crate::prover::consensus::{
        generate_receipts_root_branch, generate_transaction_branch, prove_ancestry_with_block_roots,
    };
    use consensus_types::consensus::BeaconBlockAlias;
    use consensus_types::proofs::AncestryProof;
    use ssz_rs::{GeneralizedIndex, Merkleized};
    use std::fs::File;
    use tokio::test as tokio_test;

    pub fn get_beacon_block() -> BeaconBlockAlias {
        let file = File::open("./src/prover/testdata/beacon_block.json").unwrap();
        serde_json::from_reader(file).unwrap()
    }

    /**
     * TESTS BELOW REQUIRE NETWORK REQUESTS
     */
    #[tokio_test]
    async fn test_transactions_branch() {
        let mut block = get_beacon_block();
        let block_root = block.hash_tree_root().unwrap();

        let tx_index = 15;
        let transaction = &mut block.body.execution_payload.transactions[tx_index];
        let node = transaction.hash_tree_root().unwrap();

        let proof = generate_transaction_branch(&block_root.to_string(), tx_index as u64)
            .await
            .unwrap();

        let is_proof_valid = ssz_rs::verify_merkle_proof(
            &node,
            proof.witnesses.as_slice(),
            &GeneralizedIndex(proof.gindex as usize),
            &block_root,
        );

        assert!(is_proof_valid)
    }

    #[tokio_test]
    async fn test_receipts_root_branch() {
        let mut block = get_beacon_block();
        let block_root = block.hash_tree_root().unwrap();

        let proof = generate_receipts_root_branch(&block_root.to_string())
            .await
            .unwrap();

        let is_proof_valid = ssz_rs::verify_merkle_proof(
            &block
                .body
                .execution_payload
                .receipts_root
                .hash_tree_root()
                .unwrap(),
            proof.witnesses.as_slice(),
            &GeneralizedIndex(proof.gindex as usize),
            &block_root,
        );

        assert!(is_proof_valid)
    }

    #[tokio_test]
    async fn test_block_roots_proof() {
        let consensus = ConsensusRPC::new(CONSENSUS_RPC);
        let latest_block = consensus.get_latest_beacon_block_header().await.unwrap();
        let mut old_block = consensus
            .get_beacon_block_header(latest_block.slot - 1000)
            .await
            .unwrap();

        let proof =
            prove_ancestry_with_block_roots(old_block.slot, latest_block.state_root.to_string())
                .await
                .unwrap();

        match proof {
            AncestryProof::BlockRoots {
                block_roots_index,
                block_root_proof,
            } => {
                let is_valid_proof = ssz_rs::verify_merkle_proof(
                    &old_block.hash_tree_root().unwrap(),
                    block_root_proof.as_slice(),
                    &GeneralizedIndex(block_roots_index as usize),
                    &latest_block.state_root,
                );
                assert!(is_valid_proof)
            }
            _ => panic!("Expected block roots proof"),
        }
    }
}
