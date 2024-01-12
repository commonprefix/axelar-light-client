use std::{sync::Arc, default};

use super::utils;
use crate::prover::{
    errors::ProverError,
    state_prover::StateProverAPI,
    types::{GindexOrPath, ProofResponse},
};
use async_trait::async_trait;
use cita_trie::Trie;
use consensus_types::ssz_rs::{
    generate_proof, get_generalized_index, Node, SszVariableOrIndex, Vector,
};
use consensus_types::sync_committee_rs::constants::{
    CAPELLA_FORK_EPOCH, SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT,
};
use consensus_types::{consensus::BeaconStateType, proofs::AncestryProof};
use eth::consensus::EthBeaconAPI;
use ethers::{types::TransactionReceipt, utils::rlp::encode};
use log::debug;
use mockall::automock;

const CAPELLA_FORK_SLOT: u64 = CAPELLA_FORK_EPOCH * SLOTS_PER_EPOCH;

#[async_trait]
pub trait ProofGeneratorAPI {
    /// Generates a merkle proof from a specific transaction to the beacon block root.
    async fn generate_transaction_proof(
        &self,
        block_id: &str,
        tx_index: u64,
    ) -> Result<ProofResponse, ProverError>;
    /// Generates a merkle proof from the receipts_root to the beacon block root.
    async fn generate_receipts_root_proof(
        &self,
        block_id: &str,
    ) -> Result<ProofResponse, ProverError>;
    /// Generates an ancestry proof from the target block to the beacon
    /// state root using the block roots state property. This proof is easy
    /// to be generated but it can only prove blocks up to a period old (~27
    /// hours)
    async fn prove_ancestry_with_block_roots(
        &self,
        target_block_slot: &u64,
        recent_block_state_id: &str,
    ) -> Result<AncestryProof, ProverError>;
    /// Generates an ancestry proof from the target block to the beacon state root
    /// using the historical roots state property. This proof needs the
    /// block_roots tree to be reconstructed (i.e. fetching all 8196 block roots
    /// of a period and then generating the proofs).
    async fn prove_historical_summaries_proof(
        &self,
        target_block_slot: &u64,
        recent_block_state_id: &str,
    ) -> Result<ProofResponse, ProverError>;
    /// Generates a proof from the block root to the block summary root state property.
    async fn prove_block_root_to_block_summary_root(
        &self,
        target_block_slot: &u64,
    ) -> Result<Vec<Node>, ProverError>;
    /// Generates an ancestry proof from the recent block state to the target block
    /// using the historical_roots beacon state property. The target block should be
    /// in a slot less than recent_block_slot - SLOTS_PER_HISTORICAL_ROOT.
    async fn prove_ancestry_with_historical_summaries(
        &self,
        target_block_slot: &u64,
        recent_block_state_id: &str,
    ) -> Result<AncestryProof, ProverError>;
    /// Generates an Merkle Patricia tree proof from a receipt to the receipts_root.
    fn generate_receipt_proof(
        &self,
        receipts: &[TransactionReceipt],
        index: u64,
    ) -> Result<Vec<Vec<u8>>, ProverError>;
}

/// Main proving mechanism for generating proofs from both the execution and the
/// consensus block to the beacon state or block root.
#[derive(Clone)]
pub struct ProofGenerator<CR: EthBeaconAPI, SP: StateProverAPI> {
    consensus_rpc: Arc<CR>,
    state_prover: SP,
}

impl<CR: EthBeaconAPI, SP: StateProverAPI> ProofGenerator<CR, SP> {
    pub fn new(consensus_rpc: Arc<CR>, state_prover: SP) -> Self {
        ProofGenerator {
            consensus_rpc,
            state_prover,
        }
    }
}

#[automock]
#[async_trait]
impl<CR: EthBeaconAPI, SP: StateProverAPI> ProofGeneratorAPI for ProofGenerator<CR, SP> {
    /// This implementation generates a merkle proof from a specific transaction
    /// to the beacon block root by calling the state prover (a wrapper around
    /// the proofs endpoint of lodestar).
    async fn generate_transaction_proof(
        &self,
        block_id: &str,
        tx_index: u64,
    ) -> Result<ProofResponse, ProverError> {
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

        debug!(
            "Got transaction proof from state prover {} {}",
            block_id, tx_index
        );
        Ok(proof)
    }

    /// This implementation generates a merkle proof from the receipts_root to
    /// the beacon block root by calling the state prover's /block_proof endpoint.
    async fn generate_receipts_root_proof(
        &self,
        block_id: &str,
    ) -> Result<ProofResponse, ProverError> {
        let path = vec![
            SszVariableOrIndex::Name("body"),
            SszVariableOrIndex::Name("execution_payload"),
            SszVariableOrIndex::Name("receipts_root"),
        ];

        let proof = self
            .state_prover
            .get_block_proof(block_id, GindexOrPath::Path(path))
            .await?;

        debug!("Got receipts_root proof from state prover {}", block_id);
        Ok(proof)
    }

    /// This implementation generates an ancestry proof from the target block to a recent block.
    /// The target block cannot be older than SLOTS_PER_HISTORICAL_ROOT (8192 blocks, ~27 hours).
    async fn prove_ancestry_with_block_roots(
        &self,
        target_block_slot: &u64,
        recent_block_state_id: &str,
    ) -> Result<AncestryProof, ProverError> {
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

        debug!(
            "Got ancestry proof with block roots from {} to {}",
            target_block_slot, recent_block_state_id
        );
        Ok(ancestry_proof)
    }

    /// This implementation uses the state prover to fetch a proof from the
    /// state root to the specific historical summary of the period we're
    /// interested in.
    async fn prove_historical_summaries_proof(
        &self,
        target_block_slot: &u64,
        recent_block_state_id: &str,
    ) -> Result<ProofResponse, ProverError> {
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

        debug!(
            "Got historical summaries proof from {} to {}",
            target_block_slot, recent_block_state_id
        );

        Ok(res)
    }

    async fn prove_block_root_to_block_summary_root(
        &self,
        target_block_slot: &u64,
    ) -> Result<Vec<Node>, ProverError> {
        let block_root_index = *target_block_slot as usize % SLOTS_PER_HISTORICAL_ROOT;
        let start_slot = target_block_slot - block_root_index as u64;

        let mut block_roots = self.consensus_rpc.get_block_roots_tree(start_slot).await?;

        let gindex = get_generalized_index(
            &Vector::<Node, SLOTS_PER_HISTORICAL_ROOT>::default(),
            &[SszVariableOrIndex::Index(block_root_index)],
        );
        let proof = generate_proof(&mut block_roots, &[gindex])?;

        debug!(
            "Got block root to block summary root proof from {}",
            target_block_slot
        );
        Ok(proof)
    }

    async fn prove_ancestry_with_historical_summaries(
        &self,
        target_block_slot: &u64,
        recent_block_state_id: &str,
    ) -> Result<AncestryProof, ProverError> {
        if *target_block_slot < CAPELLA_FORK_SLOT {
            return Err(ProverError::InvalidDataError(
                "Target block epoch is less than CAPELLA_FORK_EPOCH".to_string(),
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

        debug!(
            "Got ancestry proof with historical summaries from {} to {}",
            target_block_slot, recent_block_state_id
        );
        Ok(res)
    }

    fn generate_receipt_proof(
        &self,
        receipts: &[TransactionReceipt],
        index: u64,
    ) -> Result<Vec<Vec<u8>>, ProverError> {
        let mut trie = utils::generate_trie(receipts.to_owned(), utils::encode_receipt);
        let _trie_root = trie.root().unwrap();

        let receipt_index = encode(&index);
        let proof = trie.get_proof(receipt_index.to_vec().as_slice())?;

        debug!("Got receipt proof for {}", index);
        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::sync::Arc;

    use super::{ProofGenerator, ProofGeneratorAPI};
    use crate::prover::state_prover::MockStateProver;
    use crate::prover::test_helpers::test_utils::*;
    use crate::prover::types::GindexOrPath;
    use crate::prover::types::ProofResponse;
    use crate::prover::utils::parse_path;
    use consensus_types::consensus::BeaconBlockAlias;
    use consensus_types::proofs::AncestryProof;
    use consensus_types::ssz_rs::{
        get_generalized_index, verify_merkle_proof, GeneralizedIndex, Merkleized, Node,
        SszVariableOrIndex, Vector,
    };
    use consensus_types::sync_committee_rs::constants::Root;
    use consensus_types::sync_committee_rs::{
        consensus_types::BeaconBlockHeader, constants::SLOTS_PER_HISTORICAL_ROOT,
    };
    use eth::consensus::EthBeaconAPI;
    use eth::consensus::MockConsensusRPC;
    use tokio::test as tokio_test;

    async fn setup_block_and_provers(
        consensus_block_number: u64,
    ) -> (
        Arc<MockConsensusRPC>,
        MockStateProver,
        BeaconBlockAlias,
        Node,
    ) {
        let mut consensus = MockConsensusRPC::new();

        consensus
            .expect_get_beacon_block_header()
            .returning(|slot| {
                let filename = format!("./src/prover/testdata/beacon_block_headers/{}.json", slot);
                let file = File::open(filename).unwrap();
                let res: BeaconBlockHeader = serde_json::from_reader(file).unwrap();
                Ok(res)
            });

        consensus.expect_get_beacon_block().returning(|slot| {
            let filename = format!("./src/prover/testdata/beacon_blocks/{}.json", slot);
            let file = File::open(filename).unwrap();
            let res: BeaconBlockAlias = serde_json::from_reader(file).unwrap();
            Ok(res)
        });

        consensus.expect_get_block_roots_tree().returning(|_| {
            let file = File::open("./src/prover/testdata/block_roots.json").unwrap();
            let tree: Vector<_, SLOTS_PER_HISTORICAL_ROOT> = serde_json::from_reader(file).unwrap();
            Ok(tree)
        });

        let mut state_prover = MockStateProver::new();

        state_prover
            .expect_get_state_proof()
            .returning(|state_id, gindex_or_path| {
                let filename = match gindex_or_path {
                    GindexOrPath::Gindex(gindex) => {
                        format!("state_proof_{}_g{}.json", state_id, gindex)
                    }
                    GindexOrPath::Path(path) => {
                        let path = parse_path(path);
                        format!("state_proof_{}_{}.json", state_id, path)
                    }
                };

                let filename = format!("./src/prover/testdata/state_prover/{}", filename);
                let file = File::open(filename).unwrap();

                let res: ProofResponse = serde_json::from_reader(file).unwrap();

                Ok(res)
            });

        state_prover
            .expect_get_block_proof()
            .returning(|block_id, gindex_or_path| {
                let filename = match gindex_or_path {
                    GindexOrPath::Gindex(gindex) => {
                        format!("block_proof_{}_g{}.json", block_id, gindex)
                    }
                    GindexOrPath::Path(path) => {
                        let path = parse_path(&path);
                        format!("block_proof_{}_{}.json", block_id, path)
                    }
                };

                let filename = format!("./src/prover/testdata/state_prover/{}", filename);
                let file = File::open(filename).unwrap();

                let res: ProofResponse = serde_json::from_reader(file).unwrap();

                Ok(res)
            });

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
        let proof_generator = ProofGenerator::new(consensus, state_prover);
        let tx_index = 15;

        let transaction = &mut block.body.execution_payload.transactions[tx_index];
        let node = transaction.hash_tree_root().unwrap();

        let proof = proof_generator
            .generate_transaction_proof(&block_root.to_string(), tx_index as u64)
            .await
            .unwrap();

        let is_proof_valid = verify_merkle_proof(
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
        let proof_generator = ProofGenerator::new(consensus, state_prover);

        let tx_index = 15;

        let transaction = &mut block.body.execution_payload.transactions[tx_index];
        transaction[0] = 0;

        let node = transaction.hash_tree_root().unwrap();

        let proof = proof_generator
            .generate_transaction_proof(&block_root.to_string(), tx_index as u64)
            .await
            .unwrap();

        let mut invalid_block_root = block_root;
        invalid_block_root.0[31] = 0;

        let is_proof_valid = verify_merkle_proof(
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
        let proof_generator = ProofGenerator::new(consensus, state_prover);
        let tx_index = 15;

        // Different transaction
        let transaction = &mut block.body.execution_payload.transactions[16];
        let node = transaction.hash_tree_root().unwrap();

        let proof = proof_generator
            .generate_transaction_proof(&block_root.to_string(), tx_index as u64)
            .await
            .unwrap();

        let is_proof_valid = verify_merkle_proof(
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
        let proof_generator = ProofGenerator::new(consensus, state_prover);

        let tx_index = 15;
        let transaction = &mut block.body.execution_payload.transactions[tx_index];
        let node = transaction.hash_tree_root().unwrap();

        let proof = proof_generator
            .generate_transaction_proof(&block_root.to_string(), tx_index as u64)
            .await
            .unwrap();

        let mut invalid_block_root = block_root;
        invalid_block_root.0[31] = 0;

        let is_proof_valid = verify_merkle_proof(
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
        let proof_generator = ProofGenerator::new(consensus, state_prover);
        let tx_index = 15;
        let transaction = &mut block.body.execution_payload.transactions[tx_index];
        let node = transaction.hash_tree_root().unwrap();

        let proof = proof_generator
            .generate_transaction_proof(&block_root.to_string(), tx_index as u64)
            .await
            .unwrap();

        let mut invalid_proof = proof.witnesses.clone();
        invalid_proof[0] = Node::default();

        let is_proof_valid = verify_merkle_proof(
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
        let proof_generator = ProofGenerator::new(consensus, state_prover);

        let proof = proof_generator
            .generate_receipts_root_proof(&block_root.to_string())
            .await
            .unwrap();

        let is_proof_valid = verify_merkle_proof(
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
        let proof_generator = ProofGenerator::new(consensus, state_prover);

        let proof = proof_generator
            .generate_receipts_root_proof(&block_root.to_string())
            .await
            .unwrap();

        let mut invalid_proof = proof.witnesses.clone();
        invalid_proof[0] = Node::default();

        let is_proof_valid = verify_merkle_proof(
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
        let proof_generator = ProofGenerator::new(consensus, state_prover);

        let proof = proof_generator
            .generate_receipts_root_proof(&block_root.to_string())
            .await
            .unwrap();

        let is_proof_valid = verify_merkle_proof(
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
        let proof_generator = ProofGenerator::new(consensus, state_prover);

        let old_block_slot = 7878867 - 1000;
        let proof = proof_generator
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
        let proof = proof_generator
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

        let proof_generator = ProofGenerator::new(consensus, state_prover);

        let proof = proof_generator
            .prove_ancestry_with_block_roots(&old_block.slot, &latest_block.state_root.to_string())
            .await
            .unwrap();

        match proof {
            AncestryProof::BlockRoots {
                block_roots_index,
                block_root_proof,
            } => {
                let is_valid_proof = verify_merkle_proof(
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

        let proof_generator = ProofGenerator::new(consensus, state_prover);

        let proof = proof_generator
            .prove_ancestry_with_block_roots(&old_block.slot, &latest_block.state_root.to_string())
            .await
            .unwrap();

        match proof {
            AncestryProof::BlockRoots {
                block_roots_index,
                mut block_root_proof,
            } => {
                // Make proof invalid
                block_root_proof[0] = Node::default();

                let is_valid_proof = verify_merkle_proof(
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

        let proof_generator = ProofGenerator::new(consensus, state_prover);

        let proof = proof_generator
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
                let is_valid_proof = verify_merkle_proof(
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

                let is_valid_proof = verify_merkle_proof(
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

        let proof_generator = ProofGenerator::new(consensus, state_prover);

        let proof = proof_generator
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
                let is_valid_proof = verify_merkle_proof(
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

                let is_valid_proof = verify_merkle_proof(
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

    #[tokio_test]
    async fn test_receipts_proof_valid() {
        let execution_block = get_mock_block_with_txs(18615160);
        let receipts = get_mock_block_receipts(18615160);

        let (consensus, state_prover, _, _) = setup_block_and_provers(7807119).await;
        let proof_generator = ProofGenerator::new(consensus, state_prover);
        let proof = proof_generator
            .generate_receipt_proof(&receipts, 1)
            .unwrap();

        let bytes: Result<[u8; 32], _> = execution_block.receipts_root[0..32].try_into();
        let root = Root::from_bytes(bytes.unwrap());

        let valid_proof = verify_trie_proof(root, 1, proof.clone());

        assert!(valid_proof.is_ok());
    }

    #[tokio_test]
    async fn test_receipts_proof_invalid() {
        let execution_block = get_mock_block_with_txs(18615160);
        let receipts = get_mock_block_receipts(18615160);

        let (consensus, state_prover, _, _) = setup_block_and_provers(7807119).await;
        let proof_generator = ProofGenerator::new(consensus, state_prover);
        let proof = proof_generator
            .generate_receipt_proof(&receipts, 1)
            .unwrap();

        let bytes: Result<[u8; 32], _> = execution_block.receipts_root[0..32].try_into();
        let root = Root::from_bytes(bytes.unwrap());

        let invalid_proof = verify_trie_proof(root, 2, proof);

        assert!(invalid_proof.is_err());
    }
}
