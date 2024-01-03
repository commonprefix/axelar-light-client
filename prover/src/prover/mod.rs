pub mod proof_generator;
pub mod state_prover;
mod test_helpers;
pub mod types;
pub mod utils;

use std::sync::Arc;

use self::{
    proof_generator::{ProofGenerator, ProofGeneratorAPI},
    state_prover::StateProver,
    types::ProverConfig,
    utils::{get_tx_hash_from_cc_id, get_tx_index},
};
use consensus_types::{
    common::ContentVariant,
    consensus::{to_beacon_header, BeaconBlockAlias},
    proofs::{
        AncestryProof, BatchVerificationData, BlockProofsBatch, ReceiptProof, TransactionProof,
        TransactionProofsBatch, UpdateVariant,
    },
};

use eth::consensus::ConsensusRPC;
use ethers::types::{Block, Transaction, TransactionReceipt, H256};
use eyre::{anyhow, Context, Result};
use indexmap::IndexMap;
use ssz_rs::{Merkleized, Node};
use sync_committee_rs::{
    consensus_types::BeaconBlockHeader,
    constants::{Root, SLOTS_PER_HISTORICAL_ROOT},
};
use types::BatchMessageGroups;
use types::EnrichedMessage;

pub struct Prover<PG> {
    proof_generator: PG,
}

impl Prover<ProofGenerator<ConsensusRPC, StateProver>> {
    pub fn with_config(consensus_rpc: Arc<ConsensusRPC>, prover_config: ProverConfig) -> Self {
        let state_prover = StateProver::new(prover_config.state_prover_rpc.clone());
        let proof_generator = ProofGenerator::new(consensus_rpc, state_prover.clone());

        Prover { proof_generator }
    }
}

impl<PG: ProofGeneratorAPI> Prover<PG> {
    pub fn new(proof_generator: PG) -> Self {
        Prover { proof_generator }
    }

    pub async fn batch_messages(
        &self,
        messages: &[EnrichedMessage],
        update: &UpdateVariant,
    ) -> Result<BatchMessageGroups> {
        let recent_block_slot = match update {
            UpdateVariant::Finality(update) => update.finalized_header.beacon.slot,
            UpdateVariant::Optimistic(update) => update.attested_header.beacon.slot,
        };

        // Reality check
        if !messages
            .iter()
            .all(|m| m.beacon_block.slot < recent_block_slot)
        {
            return Err(anyhow!("Messages provided are not preceeding the update"));
        }

        let mut groups: BatchMessageGroups = IndexMap::new();

        for message in messages {
            let tx_hash = get_tx_hash_from_cc_id(&message.message.cc_id)?;

            groups
                .entry(message.exec_block.number.unwrap().as_u64())
                .or_default()
                .entry(tx_hash)
                .or_default()
                .push(message.clone());
        }

        Ok(groups)
    }

    /// Generates proofs for a batch of messages.
    pub async fn batch_generate_proofs(
        &self,
        batch_message_groups: BatchMessageGroups,
        update: UpdateVariant,
    ) -> Result<BatchVerificationData> {
        let recent_block = match update.clone() {
            UpdateVariant::Finality(update) => update.finalized_header.beacon,
            UpdateVariant::Optimistic(update) => update.attested_header.beacon,
        };

        let mut block_proofs_batch: Vec<BlockProofsBatch> = vec![];
        for (_, block_groups) in &batch_message_groups {
            let (mut beacon_block, exec_block, receipts) =
                Self::get_block_of_batch(block_groups).unwrap();
            let block_hash = beacon_block.hash_tree_root()?;

            let ancestry_proof = self
                .get_ancestry_proof(beacon_block.slot, &recent_block)
                .await?;
            let mut block_proof = BlockProofsBatch {
                ancestry_proof,
                target_block: to_beacon_header(&beacon_block)?,
                transactions_proofs: vec![],
            };

            for (tx_hash, messages) in block_groups {
                let tx_index = get_tx_index(&receipts, tx_hash)?;

                let transaction_proof = self
                    .get_transaction_proof(&beacon_block, block_hash, tx_index)
                    .await?;
                let receipt_proof = self
                    .get_receipt_proof(&exec_block, block_hash, &receipts, tx_index)
                    .await?;

                let tx_level_verification = TransactionProofsBatch {
                    transaction_proof,
                    receipt_proof,
                    content: messages
                        .iter()
                        .map(|m| ContentVariant::Message(m.message.clone()))
                        .collect(),
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

    pub fn get_block_of_batch(
        batch: &IndexMap<H256, Vec<EnrichedMessage>>,
    ) -> Result<
        (
            BeaconBlockAlias,
            Block<Transaction>,
            Vec<TransactionReceipt>,
        ),
        &'static str,
    > {
        let messages = batch.values().next().ok_or("Batch is empty")?;
        let first_message = messages.first().ok_or("No messages in the batch")?;

        let exec_block = first_message.exec_block.clone();
        let beacon_block = first_message.beacon_block.clone();
        let receipts = first_message.receipts.clone();

        Ok((beacon_block, exec_block, receipts))
    }

    /**
     * Generates an ancestry proof from the recent block state to the target block
     * using either the block_roots or the historical_roots beacon state property.
     */
    pub async fn get_ancestry_proof(
        &self,
        target_block_slot: u64,
        recent_block: &BeaconBlockHeader,
    ) -> Result<AncestryProof> {
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

        Ok(proof)
    }

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
            receipts_root: Node::from_bytes(exec_block.receipts_root.as_bytes().try_into()?),
        };

        Ok(receipt_proof)
    }

    pub async fn get_transaction_proof(
        &self,
        beacon_block: &BeaconBlockAlias,
        block_hash: Root,
        tx_index: u64,
    ) -> Result<TransactionProof> {
        let transaction =
            beacon_block.body.execution_payload.transactions[tx_index as usize].clone();

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

        Ok(transaction_proof)
    }
}

#[cfg(test)]
mod tests {
    use super::state_prover::MockStateProver;
    use crate::prover::proof_generator::MockProofGenerator;
    use crate::prover::test_helpers::test_utils::*;
    use crate::prover::Prover;
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
        let batch_message_groups = get_mock_batch_message_groups();

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
            .batch_generate_proofs(batch_message_groups, mock_update.clone())
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

        for i in 0..target_blocks.len() {
            for j in 0..target_blocks[i].transactions_proofs.len() {
                let messages_count = target_blocks[i].transactions_proofs[j]
                    .content
                    .iter()
                    .filter(|c| matches!(c, ContentVariant::Message(_)))
                    .count();
                if i == 1 && j == 0 {
                    assert_eq!(messages_count, 2);
                } else {
                    assert_eq!(messages_count, 1);
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
    async fn test_batch_messages() {
        let _consensus_rpc = MockConsensusRPC::new();
        let mut execution_rpc = MockExecutionRPC::new();

        let update = get_mock_update(true, 1000, 505);

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

        let result = prover
            .batch_messages(messages.as_ref(), &update)
            .await
            .unwrap();

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
