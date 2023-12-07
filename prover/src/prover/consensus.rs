use crate::prover::{
    state_prover::StateProverAPI,
    types::{GindexOrPath, ProofResponse},
};
use consensus_types::{consensus::BeaconStateType, proofs::AncestryProof};
use eth::consensus::CustomConsensusApi;
use eyre::{anyhow, Result};
use ssz_rs::{get_generalized_index, Node, SszVariableOrIndex, Vector};
use sync_committee_rs::constants::{
    CAPELLA_FORK_EPOCH, SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT,
};

const CAPELLA_FORK_SLOT: u64 = CAPELLA_FORK_EPOCH * SLOTS_PER_EPOCH;

/**
 * Generates a merkle proof from the transaction to the beacon block root.
*/
pub async fn generate_transaction_proof(
    state_prover: &dyn StateProverAPI,
    block_id: &String,
    tx_index: u64,
) -> Result<ProofResponse> {
    let path = vec![
        SszVariableOrIndex::Name("body"),
        SszVariableOrIndex::Name("execution_payload"),
        SszVariableOrIndex::Name("transactions"),
        SszVariableOrIndex::Index(tx_index as usize),
    ];

    let proof = state_prover
        .get_block_proof(block_id, GindexOrPath::Path(path))
        .await?;
    Ok(proof)
}

/**
 * Generates a merkle proof from the receipts_root to the beacon block root.
*/
pub async fn generate_receipts_root_proof(
    state_prover: &dyn StateProverAPI,
    block_id: &String,
) -> Result<ProofResponse> {
    let path = vec![
        SszVariableOrIndex::Name("body"),
        SszVariableOrIndex::Name("execution_payload"),
        SszVariableOrIndex::Name("receipts_root"),
    ];

    let proof = state_prover
        .get_block_proof(block_id, GindexOrPath::Path(path))
        .await?;
    Ok(proof)
}

/**
 * Generates an ancestry proof from the recent block state to the target block
 * using either the block_roots or the historical_roots beacon state property.
*/
pub async fn prove_ancestry(
    consensus: &dyn CustomConsensusApi,
    state_prover: &dyn StateProverAPI,
    target_block_slot: usize,
    recent_block_slot: usize,
    recent_block_state_id: &String,
) -> Result<AncestryProof> {
    let is_in_block_roots_range = target_block_slot < recent_block_slot
        && recent_block_slot <= target_block_slot + SLOTS_PER_HISTORICAL_ROOT;

    let proof = if is_in_block_roots_range {
        prove_ancestry_with_block_roots(state_prover, &target_block_slot, recent_block_state_id)
            .await?
    } else {
        prove_ancestry_with_historical_summaries(
            consensus,
            state_prover,
            &(target_block_slot as u64),
            recent_block_state_id,
        )
        .await?
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
    state_prover: &dyn StateProverAPI,
    target_block_slot: &usize,
    recent_block_state_id: &String,
) -> Result<AncestryProof> {
    let index = target_block_slot % SLOTS_PER_HISTORICAL_ROOT;
    let g_index_from_state_root = get_generalized_index(
        &BeaconStateType::default(),
        &[
            SszVariableOrIndex::Name("block_roots"),
            SszVariableOrIndex::Index(index),
        ],
    );

    let res = state_prover
        .get_state_proof(
            recent_block_state_id,
            &GindexOrPath::Gindex(g_index_from_state_root),
        )
        .await?;

    let ancestry_proof = AncestryProof::BlockRoots {
        block_roots_index: g_index_from_state_root as u64,
        block_root_proof: res.witnesses,
    };

    Ok(ancestry_proof)
}

async fn prove_historical_summaries_proof(
    state_prover: &dyn StateProverAPI,
    target_block_slot: &u64,
    recent_block_state_id: &String,
) -> Result<ProofResponse> {
    let historical_summaries_index =
        (target_block_slot - CAPELLA_FORK_SLOT) / SLOTS_PER_HISTORICAL_ROOT as u64;

    let path = vec![
        SszVariableOrIndex::Name("historical_summaries"),
        SszVariableOrIndex::Index(historical_summaries_index as usize),
        SszVariableOrIndex::Name("block_summary_root"),
    ];

    let res = state_prover
        .get_state_proof(recent_block_state_id, &GindexOrPath::Path(path))
        .await?;

    Ok(res)
}

async fn prove_block_root_to_block_summary_root(
    consensus: &dyn CustomConsensusApi,
    target_block_slot: &u64,
) -> Result<Vec<Node>> {
    let block_root_index = *target_block_slot as usize % SLOTS_PER_HISTORICAL_ROOT;
    let start_slot = target_block_slot - block_root_index as u64;

    let mut block_roots = consensus.get_block_roots_tree(start_slot).await?;

    let gindex = get_generalized_index(
        &Vector::<Node, SLOTS_PER_HISTORICAL_ROOT>::default(),
        &[SszVariableOrIndex::Index(block_root_index)],
    );
    let proof = ssz_rs::generate_proof(&mut block_roots, &[gindex])?;

    Ok(proof)
}

/**
 * Generates an ancestry proof from the recent block state to the target block
 * using the historical_roots beacon state property. The target block should be
 * in a slot less than recent_block_slot - SLOTS_PER_HISTORICAL_ROOT.
 */
pub async fn prove_ancestry_with_historical_summaries(
    consensus: &dyn CustomConsensusApi,
    state_prover: &dyn StateProverAPI,
    target_block_slot: &u64,
    recent_block_state_id: &String,
) -> Result<AncestryProof> {
    if *target_block_slot < CAPELLA_FORK_SLOT {
        return Err(anyhow!(
            "Target block epoch is less than CAPELLA_FORK_EPOCH"
        ));
    }
    let historical_summaries_proof =
        prove_historical_summaries_proof(state_prover, target_block_slot, recent_block_state_id)
            .await?;

    let block_root_to_block_summary_root =
        prove_block_root_to_block_summary_root(consensus, target_block_slot).await?;

    let res = AncestryProof::HistoricalRoots {
        block_root_proof: block_root_to_block_summary_root,
        block_summary_root_proof: historical_summaries_proof.witnesses,
        block_summary_root: historical_summaries_proof.leaf,
        block_summary_root_gindex: historical_summaries_proof.gindex,
    };

    Ok(res)
}

#[cfg(test)]
mod tests {
    use crate::prover::consensus::{
        generate_receipts_root_proof, generate_transaction_proof, prove_ancestry_with_block_roots,
        prove_ancestry_with_historical_summaries,
    };
    use crate::prover::mocks::mock_consensus_rpc::MockConsensusRPC;
    use crate::prover::mocks::mock_state_prover::MockStateProver;
    use consensus_types::proofs::AncestryProof;
    use eth::consensus::EthBeaconAPI;
    use ssz_rs::{
        get_generalized_index, GeneralizedIndex, Merkleized, Node, SszVariableOrIndex, Vector,
    };
    use sync_committee_rs::constants::SLOTS_PER_HISTORICAL_ROOT;
    use tokio::test as tokio_test;

    /**
     * TESTS BELOW REQUIRE NETWORK REQUESTS
     */
    #[tokio_test]
    async fn test_transactions_proof() {
        let consensus = &MockConsensusRPC::new();
        let state_prover = MockStateProver::new();
        let mut block = consensus.get_beacon_block(7807119).await.unwrap();
        let block_root = block.hash_tree_root().unwrap();

        let tx_index = 15;
        let transaction = &mut block.body.execution_payload.transactions[tx_index];
        let node = transaction.hash_tree_root().unwrap();

        let proof =
            generate_transaction_proof(&state_prover, &block_root.to_string(), tx_index as u64)
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
    async fn test_receipts_root_proof() {
        let consensus = &MockConsensusRPC::new();
        let state_prover = MockStateProver::new();
        let mut block = consensus.get_beacon_block(7807119).await.unwrap();
        let block_root = block.hash_tree_root().unwrap();

        let proof = generate_receipts_root_proof(&state_prover, &block_root.to_string())
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
        let consensus = &MockConsensusRPC::new();
        let latest_block = consensus.get_beacon_block_header(7878867).await.unwrap();
        let state_prover = MockStateProver::new();
        let mut old_block = consensus
            .get_beacon_block_header(7878867 - 1000)
            .await
            .unwrap();

        let proof = prove_ancestry_with_block_roots(
            &state_prover,
            &(old_block.slot as usize),
            &latest_block.state_root.to_string(),
        )
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

    #[tokio_test]
    async fn test_historical_proof() {
        let consensus = MockConsensusRPC::new();
        let state_prover = MockStateProver::new();

        let latest_block = consensus.get_beacon_block_header(7879376).await.unwrap();
        let mut old_block = consensus
            .get_beacon_block_header(7870916 - 8196)
            .await
            .unwrap();

        let proof = prove_ancestry_with_historical_summaries(
            &consensus,
            &state_prover,
            &(old_block.slot),
            &latest_block.state_root.to_string(),
        )
        .await
        .unwrap();

        match proof {
            AncestryProof::HistoricalRoots {
                block_summary_root_proof,
                block_root_proof,
                block_summary_root_gindex,
                block_summary_root,
            } => {
                // Proof from state root to the specific block_summary_root of the historical_summaries
                let is_valid_proof = ssz_rs::verify_merkle_proof(
                    &block_summary_root,
                    &block_summary_root_proof,
                    &GeneralizedIndex(block_summary_root_gindex as usize),
                    &latest_block.state_root,
                );
                assert!(is_valid_proof);

                // Proof from block_summary_root to the target block

                let block_root_index = old_block.slot as usize % SLOTS_PER_HISTORICAL_ROOT;
                let gindex = get_generalized_index(
                    &Vector::<Node, SLOTS_PER_HISTORICAL_ROOT>::default(),
                    &[SszVariableOrIndex::Index(block_root_index)],
                );

                let is_valid_proof = ssz_rs::verify_merkle_proof(
                    &old_block.hash_tree_root().unwrap(),
                    &block_root_proof,
                    &GeneralizedIndex(gindex),
                    &block_summary_root,
                );
                assert!(is_valid_proof)
            }
            _ => panic!("Expected block roots proof"),
        }
    }
}
