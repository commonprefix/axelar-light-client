use std::sync::Arc;

use crate::prover::{
    state_prover::StateProverAPI,
    types::{GindexOrPath, ProofResponse},
};
use async_trait::async_trait;
use consensus_types::{consensus::BeaconStateType, proofs::AncestryProof};
use eth::consensus::EthBeaconAPI;
use eyre::{anyhow, Result};
use mockall::automock;
use ssz_rs::{get_generalized_index, Node, SszVariableOrIndex, Vector};
use sync_committee_rs::constants::{
    CAPELLA_FORK_EPOCH, SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT,
};

const CAPELLA_FORK_SLOT: u64 = CAPELLA_FORK_EPOCH * SLOTS_PER_EPOCH;

#[async_trait]
pub trait ConsensusProverAPI {
    async fn generate_transaction_proof(
        &self,
        block_id: &str,
        tx_index: u64,
    ) -> Result<ProofResponse>;
    async fn generate_receipts_root_proof(&self, block_id: &str) -> Result<ProofResponse>;
    async fn prove_ancestry_with_block_roots(
        &self,
        target_block_slot: &u64,
        recent_block_state_id: &str,
    ) -> Result<AncestryProof>;
    async fn prove_historical_summaries_proof(
        &self,
        target_block_slot: &u64,
        recent_block_state_id: &str,
    ) -> Result<ProofResponse>;
    async fn prove_block_root_to_block_summary_root(
        &self,
        target_block_slot: &u64,
    ) -> Result<Vec<Node>>;
    async fn prove_ancestry_with_historical_summaries(
        &self,
        target_block_slot: &u64,
        recent_block_state_id: &str,
    ) -> Result<AncestryProof>;
}

#[derive(Clone)]
pub struct ConsensusProver<CR: EthBeaconAPI, SP: StateProverAPI> {
    consensus_rpc: Arc<CR>,
    state_prover: SP,
}

/**
 * Generates a merkle proof from the transaction to the beacon block root.
*/
impl<CR: EthBeaconAPI, SP: StateProverAPI> ConsensusProver<CR, SP> {
    pub fn new(consensus_rpc: Arc<CR>, state_prover: SP) -> Self {
        ConsensusProver {
            consensus_rpc,
            state_prover,
        }
    }
}

#[automock]
#[async_trait]
impl<CR: EthBeaconAPI, SP: StateProverAPI> ConsensusProverAPI for ConsensusProver<CR, SP> {
    async fn generate_transaction_proof(
        &self,
        block_id: &str,
        tx_index: u64,
    ) -> Result<ProofResponse> {
        let path = vec![
            SszVariableOrIndex::Name("body"),
            SszVariableOrIndex::Name("execution_payload"),
            SszVariableOrIndex::Name("transactions"),
            SszVariableOrIndex::Index(tx_index as usize),
        ];

        let proof = self
            .state_prover
            .get_block_proof(block_id, GindexOrPath::Path(path))
            .await?;
        Ok(proof)
    }

    /**
     * Generates a merkle proof from the receipts_root to the beacon block root.
     */
    async fn generate_receipts_root_proof(&self, block_id: &str) -> Result<ProofResponse> {
        let path = vec![
            SszVariableOrIndex::Name("body"),
            SszVariableOrIndex::Name("execution_payload"),
            SszVariableOrIndex::Name("receipts_root"),
        ];

        let proof = self
            .state_prover
            .get_block_proof(block_id, GindexOrPath::Path(path))
            .await?;
        Ok(proof)
    }

    /**
     * Generates an ancestry proof from the recent block state to the target block
     * using the block_roots beacon state property using the lodestar prover. The
     * target block must in the range
     * [recent_block_slot - SLOTS_PER_HISTORICAL_ROOT, recent_block_slot].
     */
    async fn prove_ancestry_with_block_roots(
        &self,
        target_block_slot: &u64,
        recent_block_state_id: &str,
    ) -> Result<AncestryProof> {
        let index = target_block_slot % SLOTS_PER_HISTORICAL_ROOT as u64;
        let g_index_from_state_root = get_generalized_index(
            &BeaconStateType::default(),
            &[
                SszVariableOrIndex::Name("block_roots"),
                SszVariableOrIndex::Index(index as usize),
            ],
        );

        let res = self
            .state_prover
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
        &self,
        target_block_slot: &u64,
        recent_block_state_id: &str,
    ) -> Result<ProofResponse> {
        let historical_summaries_index =
            (target_block_slot - CAPELLA_FORK_SLOT) / SLOTS_PER_HISTORICAL_ROOT as u64;

        let path = vec![
            SszVariableOrIndex::Name("historical_summaries"),
            SszVariableOrIndex::Index(historical_summaries_index as usize),
            SszVariableOrIndex::Name("block_summary_root"),
        ];

        let res = self
            .state_prover
            .get_state_proof(recent_block_state_id, &GindexOrPath::Path(path))
            .await?;

        Ok(res)
    }

    async fn prove_block_root_to_block_summary_root(
        &self,
        target_block_slot: &u64,
    ) -> Result<Vec<Node>> {
        let block_root_index = *target_block_slot as usize % SLOTS_PER_HISTORICAL_ROOT;
        let start_slot = target_block_slot - block_root_index as u64;

        let mut block_roots = self.consensus_rpc.get_block_roots_tree(start_slot).await?;

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
    async fn prove_ancestry_with_historical_summaries(
        &self,
        target_block_slot: &u64,
        recent_block_state_id: &str,
    ) -> Result<AncestryProof> {
        if *target_block_slot < CAPELLA_FORK_SLOT {
            return Err(anyhow!(
                "Target block epoch is less than CAPELLA_FORK_EPOCH"
            ));
        }
        let historical_summaries_proof = self
            .prove_historical_summaries_proof(target_block_slot, recent_block_state_id)
            .await?;

        let block_root_to_block_summary_root = self
            .prove_block_root_to_block_summary_root(target_block_slot)
            .await?;

        let res = AncestryProof::HistoricalRoots {
            block_root_proof: block_root_to_block_summary_root,
            block_summary_root_proof: historical_summaries_proof.witnesses,
            block_summary_root: historical_summaries_proof.leaf,
            block_summary_root_gindex: historical_summaries_proof.gindex,
        };

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{ConsensusProver, ConsensusProverAPI};
    use crate::prover::mocks::mock_consensus_rpc::MockConsensusRPC;
    use crate::prover::mocks::mock_state_prover::MockStateProver;
    use consensus_types::consensus::BeaconBlockAlias;
    use consensus_types::proofs::AncestryProof;
    use eth::consensus::EthBeaconAPI;
    use ssz_rs::{
        get_generalized_index, GeneralizedIndex, Merkleized, Node, SszVariableOrIndex, Vector,
    };
    use sync_committee_rs::constants::SLOTS_PER_HISTORICAL_ROOT;
    use tokio::test as tokio_test;

    async fn setup_block_and_provers(
        consensus_block_number: u64,
    ) -> (
        Arc<MockConsensusRPC>,
        MockStateProver,
        BeaconBlockAlias,
        Node,
    ) {
        let consensus = MockConsensusRPC::new();
        let state_prover = MockStateProver::new();
        let mut block = consensus
            .get_beacon_block(consensus_block_number)
            .await
            .unwrap();
        let block_root = block.hash_tree_root().unwrap();

        (Arc::new(consensus), state_prover, block, block_root)
    }

    #[tokio_test]
    async fn test_transactions_proof_valid() {
        let (consensus, state_prover, mut block, block_root) =
            setup_block_and_provers(7807119).await;
        let consensus_prover = ConsensusProver::new(consensus, state_prover);
        let tx_index = 15;

        let transaction = &mut block.body.execution_payload.transactions[tx_index];
        let node = transaction.hash_tree_root().unwrap();

        let proof = consensus_prover
            .generate_transaction_proof(&block_root.to_string(), tx_index as u64)
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
    async fn test_transactions_proof_invalid_transaction() {
        let (consensus, state_prover, mut block, block_root) =
            setup_block_and_provers(7807119).await;
        let consensus_prover = ConsensusProver::new(consensus, state_prover);

        let tx_index = 15;

        let transaction = &mut block.body.execution_payload.transactions[tx_index];
        transaction[0] = 0;

        let node = transaction.hash_tree_root().unwrap();

        let proof = consensus_prover
            .generate_transaction_proof(&block_root.to_string(), tx_index as u64)
            .await
            .unwrap();

        let mut invalid_block_root = block_root;
        invalid_block_root.0[31] = 0;

        let is_proof_valid = ssz_rs::verify_merkle_proof(
            &node,
            &proof.witnesses,
            &GeneralizedIndex(proof.gindex as usize),
            &invalid_block_root,
        );

        assert!(!is_proof_valid)
    }

    #[tokio_test]
    async fn test_transactions_proof_wrong_transaction() {
        let (consensus, state_prover, mut block, block_root) =
            setup_block_and_provers(7807119).await;
        let consensus_prover = ConsensusProver::new(consensus, state_prover);
        let tx_index = 15;

        // Different transaction
        let transaction = &mut block.body.execution_payload.transactions[16];
        let node = transaction.hash_tree_root().unwrap();

        let proof = consensus_prover
            .generate_transaction_proof(&block_root.to_string(), tx_index as u64)
            .await
            .unwrap();

        let is_proof_valid = ssz_rs::verify_merkle_proof(
            &node,
            &proof.witnesses,
            &GeneralizedIndex(proof.gindex as usize),
            &block_root,
        );

        assert!(!is_proof_valid)
    }

    #[tokio_test]
    async fn test_transactions_proof_invalid_block_root() {
        let (consensus, state_prover, mut block, block_root) =
            setup_block_and_provers(7807119).await;
        let consensus_prover = ConsensusProver::new(consensus, state_prover);

        let tx_index = 15;
        let transaction = &mut block.body.execution_payload.transactions[tx_index];
        let node = transaction.hash_tree_root().unwrap();

        let proof = consensus_prover
            .generate_transaction_proof(&block_root.to_string(), tx_index as u64)
            .await
            .unwrap();

        let mut invalid_block_root = block_root;
        invalid_block_root.0[31] = 0;

        let is_proof_valid = ssz_rs::verify_merkle_proof(
            &node,
            &proof.witnesses,
            &GeneralizedIndex(proof.gindex as usize),
            &invalid_block_root,
        );

        assert!(!is_proof_valid)
    }

    #[tokio_test]
    async fn test_transactions_proof_invalid_proof() {
        let (consensus, state_prover, mut block, block_root) =
            setup_block_and_provers(7807119).await;
        let consensus_prover = ConsensusProver::new(consensus, state_prover);
        let tx_index = 15;
        let transaction = &mut block.body.execution_payload.transactions[tx_index];
        let node = transaction.hash_tree_root().unwrap();

        let proof = consensus_prover
            .generate_transaction_proof(&block_root.to_string(), tx_index as u64)
            .await
            .unwrap();

        let mut invalid_proof = proof.witnesses.clone();
        invalid_proof[0] = Node::default();

        let is_proof_valid = ssz_rs::verify_merkle_proof(
            &node,
            &invalid_proof,
            &GeneralizedIndex(proof.gindex as usize),
            &block_root,
        );

        assert!(!is_proof_valid)
    }

    #[tokio_test]
    async fn test_receipts_root_proof_valid() {
        let (consensus, state_prover, mut block, block_root) =
            setup_block_and_provers(7807119).await;
        let consensus_prover = ConsensusProver::new(consensus, state_prover);

        let proof = consensus_prover
            .generate_receipts_root_proof(&block_root.to_string())
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
    async fn test_receipts_root_proof_invalid_proof() {
        let (consensus, state_prover, mut block, block_root) =
            setup_block_and_provers(7807119).await;
        let consensus_prover = ConsensusProver::new(consensus, state_prover);

        let proof = consensus_prover
            .generate_receipts_root_proof(&block_root.to_string())
            .await
            .unwrap();

        let mut invalid_proof = proof.witnesses.clone();
        invalid_proof[0] = Node::default();

        let is_proof_valid = ssz_rs::verify_merkle_proof(
            &block
                .body
                .execution_payload
                .receipts_root
                .hash_tree_root()
                .unwrap(),
            &invalid_proof,
            &GeneralizedIndex(proof.gindex as usize),
            &block_root,
        );

        assert!(!is_proof_valid)
    }

    #[tokio_test]
    async fn test_receipts_root_proof_invalid_receipts_root() {
        let (consensus, state_prover, _, block_root) = setup_block_and_provers(7807119).await;
        let consensus_prover = ConsensusProver::new(consensus, state_prover);

        let proof = consensus_prover
            .generate_receipts_root_proof(&block_root.to_string())
            .await
            .unwrap();

        let is_proof_valid = ssz_rs::verify_merkle_proof(
            &Node::default(),
            &proof.witnesses,
            &GeneralizedIndex(proof.gindex as usize),
            &block_root,
        );

        assert!(!is_proof_valid)
    }

    #[tokio_test]
    async fn test_prove_ancestry_with_block_roots() {
        let (consensus, state_prover, _, _) = setup_block_and_provers(7807119).await;
        let latest_block_7878867 = consensus.get_beacon_block_header(7878867).await.unwrap();
        let latest_block_7879376 = consensus.get_beacon_block_header(7879376).await.unwrap();
        let consensus_prover = ConsensusProver::new(consensus, state_prover);

        let old_block_slot = 7878867 - 1000;
        let proof = consensus_prover
            .prove_ancestry_with_block_roots(
                &old_block_slot,
                &latest_block_7878867.state_root.to_string(),
            )
            .await
            .unwrap();

        if let AncestryProof::HistoricalRoots {
            block_root_proof: _,
            block_summary_root: _,
            block_summary_root_proof: _,
            block_summary_root_gindex: _,
        } = proof
        {
            panic!("Expected block roots proof")
        }

        let old_block_slot = 7870916 - 8196;
        let proof = consensus_prover
            .prove_ancestry_with_historical_summaries(
                &old_block_slot,
                &latest_block_7879376.state_root.to_string(),
            )
            .await
            .unwrap();

        if let AncestryProof::BlockRoots {
            block_roots_index: _,
            block_root_proof: _,
        } = proof
        {
            panic!("Expected historical summaries proof")
        }
    }

    #[tokio_test]
    async fn test_block_roots_proof_valid() {
        let (consensus, state_prover, _, _) = setup_block_and_provers(7807119).await;
        let latest_block = consensus.get_beacon_block_header(7878867).await.unwrap();
        let mut old_block = consensus
            .get_beacon_block_header(7878867 - 1000)
            .await
            .unwrap();

        let consensus_prover = ConsensusProver::new(consensus, state_prover);

        let proof = consensus_prover
            .prove_ancestry_with_block_roots(
                &old_block.slot,
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
    async fn test_block_roots_proof_invalid_proof() {
        let (consensus, state_prover, _, _) = setup_block_and_provers(7807119).await;
        let latest_block = consensus.get_beacon_block_header(7878867).await.unwrap();
        let mut old_block = consensus
            .get_beacon_block_header(7878867 - 1000)
            .await
            .unwrap();

        let consensus_prover = ConsensusProver::new(consensus, state_prover);

        let proof = consensus_prover
            .prove_ancestry_with_block_roots(
                &old_block.slot,
                &latest_block.state_root.to_string(),
            )
            .await
            .unwrap();

        match proof {
            AncestryProof::BlockRoots {
                block_roots_index,
                mut block_root_proof,
            } => {
                // Make proof invalid
                block_root_proof[0] = Node::default();

                let is_valid_proof = ssz_rs::verify_merkle_proof(
                    &old_block.hash_tree_root().unwrap(),
                    block_root_proof.as_slice(),
                    &GeneralizedIndex(block_roots_index as usize),
                    &latest_block.state_root,
                );
                assert!(!is_valid_proof)
            }
            _ => panic!("Expected block roots proof"),
        }
    }

    #[tokio_test]
    async fn test_historical_proof_valid() {
        let (consensus, state_prover, _, _) = setup_block_and_provers(7807119).await;
        let latest_block = consensus.get_beacon_block_header(7879376).await.unwrap();
        let mut old_block = consensus
            .get_beacon_block_header(7870916 - 8196)
            .await
            .unwrap();

        let consensus_prover = ConsensusProver::new(consensus, state_prover);

        let proof = consensus_prover
            .prove_ancestry_with_historical_summaries(
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

    #[tokio_test]
    async fn test_historical_proof_invalid_proofs() {
        let (consensus, state_prover, _, _) = setup_block_and_provers(7807119).await;
        let latest_block = consensus.get_beacon_block_header(7879376).await.unwrap();
        let mut old_block = consensus
            .get_beacon_block_header(7870916 - 8196)
            .await
            .unwrap();

        let consensus_prover = ConsensusProver::new(consensus, state_prover);

        let proof = consensus_prover
            .prove_ancestry_with_historical_summaries(
                &(old_block.slot),
                &latest_block.state_root.to_string(),
            )
            .await
            .unwrap();

        match proof {
            AncestryProof::HistoricalRoots {
                mut block_summary_root_proof,
                mut block_root_proof,
                block_summary_root_gindex,
                block_summary_root,
            } => {
                // Make proofs invalid
                block_summary_root_proof[0] = Node::default();
                block_root_proof[0] = Node::default();

                // Proof from state root to the specific block_summary_root of the historical_summaries
                let is_valid_proof = ssz_rs::verify_merkle_proof(
                    &block_summary_root,
                    &block_summary_root_proof,
                    &GeneralizedIndex(block_summary_root_gindex as usize),
                    &latest_block.state_root,
                );
                assert!(!is_valid_proof);

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
                assert!(!is_valid_proof)
            }
            _ => panic!("Expected block roots proof"),
        }
    }
}
