pub mod errors;
pub mod proof_generator;
pub mod state_prover;
mod test_helpers;
pub mod types;
pub mod utils;

use self::{
    errors::ProverError,
    proof_generator::{ProofGenerator, ProofGeneratorAPI},
    state_prover::StateProver,
    types::ProverConfig,
    utils::get_tx_index,
};
use async_trait::async_trait;
use consensus_types::ssz_rs::{Merkleized, Node};
use consensus_types::sync_committee_rs::{
    consensus_types::BeaconBlockHeader,
    constants::{Root, SLOTS_PER_HISTORICAL_ROOT},
};
use consensus_types::{
    consensus::{to_beacon_header, BeaconBlockAlias},
    proofs::{
        AncestryProof, BatchVerificationData, BlockProofsBatch, ReceiptProof, TransactionProof,
        TransactionProofsBatch, UpdateVariant,
    },
};
use eth::consensus::ConsensusRPC;
use ethers::types::{Block, Transaction, TransactionReceipt, H256};
use eyre::{eyre, Context, Result};
use indexmap::IndexMap;
use log::{debug, error, info};
use mockall::automock;
use std::sync::Arc;
use types::BatchContentGroups;
use types::EnrichedContent;

#[async_trait]
pub trait ProverAPI {
    /// Receives a batch of messages and returns a batched data structure containing
    /// the messages grouped by block number and tx hash.
    fn batch_messages(&self, contents: &[EnrichedContent]) -> BatchContentGroups;
    /// Receives a batch of contents and returns a batched data structure with
    /// the same groupping (per block and per transaction) enhanced with all the neccessary
    /// proofs up to the provided light client update. If a proof could not be generated for a  
    /// message then this messsage is ommitted from the returning structure.
    async fn batch_generate_proofs(
        &self,
        batch_content_groups: BatchContentGroups,
        update: UpdateVariant,
    ) -> Result<BatchVerificationData, ProverError>;
}

/// This is the basic prover implemntation. It uses the proof generator to
/// generate a set of proofs from a given update up to a set of batched events.
///
/// It employs 2 levels of batching:
/// - batching per block (i.e. all messages in a batch belong to the same block
/// share the same ancestry proof from the recent block to the target block) .
///
/// - batching per transaction (i.e. all messages in a batch that belong to the
/// same transaction share the same transaction and receipt_root proof to the
/// target block, as well as the same ancestry proof.
pub struct Prover<PG> {
    proof_generator: PG,
}

impl Prover<ProofGenerator<ConsensusRPC, StateProver>> {
    pub fn with_config(consensus_rpc: Arc<ConsensusRPC>, prover_config: ProverConfig) -> Self {
        let state_prover = StateProver::new(
            prover_config.network,
            prover_config.state_prover_rpc.clone(),
        );
        let proof_generator = ProofGenerator::new(consensus_rpc, state_prover.clone());

        Prover { proof_generator }
    }
}

#[automock]
#[async_trait]
impl<PG: ProofGeneratorAPI + Sync> ProverAPI for Prover<PG> {
    fn batch_messages(&self, contents: &[EnrichedContent]) -> BatchContentGroups {
        let mut groups: BatchContentGroups = IndexMap::new();

        for content in contents {
            groups
                .entry(content.exec_block.number.unwrap().as_u64())
                .or_default()
                .entry(content.tx_hash)
                .or_default()
                .push(content.clone());
        }

        debug!("Batched messages into {} block groups", groups.len());
        groups
    }

    async fn batch_generate_proofs(
        &self,
        batch_content_groups: BatchContentGroups,
        update: UpdateVariant,
    ) -> Result<BatchVerificationData, ProverError> {
        let recent_block = update.recent_block();

        let mut block_proofs_batch: Vec<BlockProofsBatch> = vec![];
        for (_, block_groups) in &batch_content_groups {
            let (mut beacon_block, exec_block, receipts) =
                Self::get_block_of_batch(block_groups).unwrap();
            let block_hash = beacon_block.hash_tree_root()?;

            let ancestry_proof = self
                .get_ancestry_proof(beacon_block.slot, &recent_block)
                .await;
            if ancestry_proof.is_err() {
                error!("Error generating ancestry proof {:?}", ancestry_proof.err());
                continue;
            }

            let mut block_proof = BlockProofsBatch {
                ancestry_proof: ancestry_proof.unwrap(),
                target_block: to_beacon_header(&beacon_block)
                    .map_err(|e| ProverError::InvalidDataError(e.to_string()))?,
                transactions_proofs: vec![],
            };

            for (tx_hash, contents) in block_groups {
                let tx_index = get_tx_index(&receipts, tx_hash)
                    .map_err(|e| ProverError::InvalidDataError(e.to_string()))?;

                let transaction_proof = self
                    .get_transaction_proof(&beacon_block, block_hash, tx_index)
                    .await;
                if transaction_proof.is_err() {
                    error!(
                        "Error generating tx proof {} {:?}",
                        tx_hash,
                        transaction_proof.err()
                    );
                    continue;
                }

                let receipt_proof = self
                    .get_receipt_proof(&exec_block, block_hash, &receipts, tx_index)
                    .await;
                if receipt_proof.is_err() {
                    error!(
                        "Error generating receipt proof {} {:?}",
                        tx_hash,
                        receipt_proof.err()
                    );
                    continue;
                }

                let tx_level_verification = TransactionProofsBatch {
                    transaction_proof: transaction_proof.unwrap(),
                    receipt_proof: receipt_proof.unwrap(),
                    content: contents.iter().map(|m| m.content.clone()).collect(),
                };

                block_proof.transactions_proofs.push(tx_level_verification);
            }

            block_proofs_batch.push(block_proof);
        }

        Ok(BatchVerificationData {
            update,
            target_blocks: block_proofs_batch,
        })
    }
}

impl<PG: ProofGeneratorAPI> Prover<PG> {
    pub fn new(proof_generator: PG) -> Self {
        Prover { proof_generator }
    }

    /// Returns the first block of a batch of messages. Used to get the block
    /// that this group of messages is related to.
    pub fn get_block_of_batch(
        batch: &IndexMap<H256, Vec<EnrichedContent>>,
    ) -> Result<
        (
            BeaconBlockAlias,
            Block<Transaction>,
            Vec<TransactionReceipt>,
        ),
        &'static str,
    > {
        let messages = batch.values().next().ok_or("Batch is empty")?;
        let first_content = messages.first().ok_or("No messages in the batch")?;

        let exec_block = first_content.exec_block.clone();
        let beacon_block = first_content.beacon_block.clone();
        let receipts = first_content.receipts.clone();

        Ok((beacon_block, exec_block, receipts))
    }

    /// Fetches an ancestry proof from the recent block state to the target block
    /// using either the block_roots or the historical_roots beacon state property.
    pub async fn get_ancestry_proof(
        &self,
        target_block_slot: u64,
        recent_block: &BeaconBlockHeader,
    ) -> Result<AncestryProof> {
        info!(
            "Will create proof from {} to {}",
            recent_block.slot, target_block_slot
        );
        if target_block_slot >= recent_block.slot {
            return Err(eyre!(
                "Target block slot {} is greater than recent block slot {}",
                target_block_slot,
                recent_block.slot
            ));
        }

        let is_in_block_roots_range = target_block_slot < recent_block.slot
            && recent_block.slot <= target_block_slot + SLOTS_PER_HISTORICAL_ROOT as u64;

        let recent_block_state_id = recent_block.state_root.to_string();

        let proof = if is_in_block_roots_range {
            self.proof_generator
                .prove_ancestry_with_block_roots(&target_block_slot, recent_block_state_id.as_str())
        } else {
            self.proof_generator
                .prove_ancestry_with_historical_summaries(
                    &target_block_slot,
                    &recent_block_state_id,
                )
        }
        .await
        .wrap_err(format!(
            "Failed to generate ancestry proof for block {:?}",
            target_block_slot
        ))?;

        debug!(
            "Got full ancestry proof from {} to {}",
            recent_block.slot, target_block_slot
        );
        Ok(proof)
    }

    /// Fetches a proof from a specific receipt to the beacon block root
    pub async fn get_receipt_proof(
        &self,
        exec_block: &Block<Transaction>,
        block_hash: Root,
        receipts: &[TransactionReceipt],
        tx_index: u64,
    ) -> Result<ReceiptProof> {
        let receipt_proof = self
            .proof_generator
            .generate_receipt_proof(receipts, tx_index)
            .wrap_err(format!(
                "Failed to generate receipt proof for block {} and tx: {}",
                block_hash, tx_index
            ))?;

        let receipts_root_proof = self
            .proof_generator
            .generate_receipts_root_proof(block_hash.to_string().as_str())
            .await
            .wrap_err(format!(
                "Failed to generate receipts root proof for block {} and tx: {}",
                block_hash, tx_index
            ))?;

        let receipt_proof = ReceiptProof {
            receipt_proof,
            receipts_root_proof: receipts_root_proof.witnesses,
            receipts_root_gindex: receipts_root_proof.gindex,
            receipts_root: Node::from_bytes(exec_block.receipts_root.as_bytes().try_into()?),
        };

        debug!(
            "Got receipt proof for block {} and tx: {}",
            block_hash, tx_index
        );
        Ok(receipt_proof)
    }

    /// Fetches a proof from a specific transaction to the beacon block root
    pub async fn get_transaction_proof(
        &self,
        beacon_block: &BeaconBlockAlias,
        block_hash: Root,
        tx_index: u64,
    ) -> Result<TransactionProof> {
        let transaction =
            beacon_block.body.execution_payload().transactions()[tx_index as usize].clone();

        let proof = self
            .proof_generator
            .generate_transaction_proof(block_hash.to_string().as_str(), tx_index)
            .await
            .wrap_err(format!(
                "Failed to generate tx proof for block {}, and tx: {}",
                block_hash, tx_index
            ))?;

        let transaction_proof: TransactionProof = TransactionProof {
            transaction_index: tx_index,
            transaction_gindex: proof.gindex,
            transaction_proof: proof.witnesses,
            transaction,
        };

        debug!("Got tx proof for block {} and tx: {}", block_hash, tx_index);
        Ok(transaction_proof)
    }
}

#[cfg(test)]
mod tests {
    use super::state_prover::MockStateProver;
    use crate::prover::proof_generator::MockProofGenerator;
    use crate::prover::test_helpers::test_utils::*;
    use crate::prover::{Prover, ProverAPI};
    use consensus_types::common::ContentVariant;
    use consensus_types::consensus::to_beacon_header;
    use consensus_types::proofs::{AncestryProof, BatchVerificationData};
    use eth::consensus::MockConsensusRPC;
    use eth::execution::MockExecutionRPC;
    use ethers::types::H256;

    fn setup() -> (MockConsensusRPC, MockExecutionRPC, MockStateProver) {
        let consensus_rpc = MockConsensusRPC::new();
        let execution_rpc = MockExecutionRPC::new();
        let state_prover = MockStateProver::new();

        (consensus_rpc, execution_rpc, state_prover)
    }

    #[tokio::test]
    async fn test_batch_generate_proofs() {
        let mock_update = get_mock_update(true, 1000, 505);
        let batch_content_groups = get_mock_batch_message_groups();

        let (_consensus_rpc, _execution_rpc, _state_prover) = setup();

        let mut proof_generator = MockProofGenerator::<MockConsensusRPC, MockStateProver>::new();
        proof_generator
            .expect_prove_ancestry_with_block_roots()
            .returning(|_, _| {
                Ok(AncestryProof::BlockRoots {
                    block_roots_index: 0,
                    block_root_proof: vec![],
                })
            });
        proof_generator
            .expect_generate_transaction_proof()
            .returning(|_, _| Ok(Default::default()));
        proof_generator
            .expect_generate_receipts_root_proof()
            .returning(|_| Ok(Default::default()));
        proof_generator
            .expect_generate_receipt_proof()
            .returning(|_, _| Ok(Default::default()));

        let prover = Prover::new(proof_generator);

        let res = prover
            .batch_generate_proofs(batch_content_groups, mock_update.clone())
            .await;
        assert!(res.is_ok());

        let BatchVerificationData {
            update,
            target_blocks,
        } = res.unwrap();

        assert_eq!(update, mock_update);
        assert_eq!(target_blocks.len(), 3);
        assert_eq!(target_blocks[0].transactions_proofs.len(), 1);
        assert_eq!(target_blocks[1].transactions_proofs.len(), 2);
        assert_eq!(target_blocks[2].transactions_proofs.len(), 1);

        for (i, target_block) in target_blocks.iter().enumerate() {
            for j in 0..target_block.transactions_proofs.len() {
                let content_count = target_blocks[i].transactions_proofs[j]
                    .content
                    .iter()
                    .filter(|c| matches!(c, ContentVariant::Message(_)))
                    .count();
                if i == 1 && j == 0 {
                    assert_eq!(content_count, 2);
                } else {
                    assert_eq!(content_count, 1);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_get_ancestry_proof_block_roots() {
        let mut proof_generator = MockProofGenerator::<MockConsensusRPC, MockStateProver>::new();

        let recent_block = get_mock_beacon_block(1000);
        let recent_block_header = to_beacon_header(&recent_block).unwrap();
        let target_block_slot = 505;

        let proof = AncestryProof::BlockRoots {
            block_roots_index: 0,
            block_root_proof: vec![],
        };

        proof_generator
            .expect_prove_ancestry_with_block_roots()
            .returning(move |_, _| Ok(proof.clone()));

        let prover = Prover::new(proof_generator);

        let res = prover
            .get_ancestry_proof(target_block_slot, &recent_block_header)
            .await;
        assert!(res.is_ok());
        // Assert is blockroots
        assert!(matches!(res.unwrap(), AncestryProof::BlockRoots { .. }));
    }

    #[tokio::test]
    async fn test_get_ancestry_proof_historical_roots() {
        let mut proof_generator = MockProofGenerator::<MockConsensusRPC, MockStateProver>::new();

        let recent_block = get_mock_beacon_block(10000);
        let recent_block_header = to_beacon_header(&recent_block).unwrap();
        let target_block_slot = 1000;

        let proof = AncestryProof::HistoricalRoots {
            block_root_proof: Default::default(),
            block_summary_root: Default::default(),
            block_summary_root_proof: Default::default(),
            block_summary_root_gindex: Default::default(),
        };

        proof_generator
            .expect_prove_ancestry_with_historical_summaries()
            .returning(move |_, _| Ok(proof.clone()));

        let prover = Prover::new(proof_generator);

        let res = prover
            .get_ancestry_proof(target_block_slot, &recent_block_header)
            .await;
        assert!(res.is_ok());
        // Assert is blockroots
        assert!(matches!(
            res.unwrap(),
            AncestryProof::HistoricalRoots { .. }
        ));
    }

    #[tokio::test]
    async fn test_batch_contents() {
        let _consensus_rpc = MockConsensusRPC::new();
        let mut execution_rpc = MockExecutionRPC::new();

        execution_rpc.expect_get_blocks().returning(move |_| {
            Ok(vec![
                Some(get_mock_exec_block(1)),
                Some(get_mock_exec_block(2)),
                Some(get_mock_exec_block(2)),
                Some(get_mock_exec_block(2)),
                Some(get_mock_exec_block(3)),
            ])
        });

        let get_tx_hash = H256::from_low_u64_be;

        let mock_message1 = get_mock_message(1, 1, get_tx_hash(1));
        let mock_message2 = get_mock_message(2, 2, get_tx_hash(2));
        let mock_message3 = get_mock_message(2, 2, get_tx_hash(2));
        let mock_message4 = get_mock_message(2, 2, get_tx_hash(3));
        let mock_message5 = get_mock_message(3, 3, get_tx_hash(4));

        let messages = [
            mock_message1.clone(),
            mock_message2.clone(),
            mock_message3.clone(),
            mock_message4.clone(),
            mock_message5.clone(),
        ];

        let proof_generator = MockProofGenerator::<MockConsensusRPC, MockStateProver>::new();
        let prover = Prover::new(proof_generator);

        let result = prover.batch_messages(messages.as_ref());

        assert_eq!(result.len(), 3);
        assert_eq!(result.get(&1).unwrap().len(), 1);
        assert_eq!(result.get(&2).unwrap().len(), 2);
        assert_eq!(result.get(&3).unwrap().len(), 1);
        assert_eq!(
            result.get(&1).unwrap().get(&get_tx_hash(1)).unwrap(),
            &vec![mock_message1]
        );
        assert_eq!(
            result.get(&2).unwrap().get(&get_tx_hash(2)).unwrap(),
            &vec![mock_message2, mock_message3]
        );
        assert_eq!(
            result.get(&2).unwrap().get(&get_tx_hash(3)).unwrap(),
            &vec![mock_message4]
        );
        assert_eq!(
            result.get(&3).unwrap().get(&get_tx_hash(4)).unwrap(),
            &vec![mock_message5]
        );
    }
}
