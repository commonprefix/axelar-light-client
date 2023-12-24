pub mod consensus;
pub mod execution;
mod mocks;
pub mod state_prover;
pub mod types;
pub mod utils;

use self::utils::{get_tx_hash_from_cc_id, get_tx_index};
use crate::prover::{consensus::ConsensusProverAPI, execution::ExecutionProverAPI};
use consensus_types::{
    consensus::{to_beacon_header, BeaconBlockAlias},
    proofs::{
        AncestryProof, BatchVerificationData, BlockProofsBatch, ReceiptProof, TransactionProof,
        TransactionProofsBatch, UpdateVariant
    },
};
use types::EnrichedMessage;
use ethers::{
    types::{Block, Transaction, TransactionReceipt, H256},
    utils::rlp::encode,
};
use eyre::{anyhow, Context, Result};
use indexmap::IndexMap;
use ssz_rs::{Merkleized, Node};
use sync_committee_rs::{consensus_types::BeaconBlockHeader, constants::Root};
use types::BatchMessageGroups;

pub struct Prover {
    consensus_prover: Box<dyn ConsensusProverAPI>,
    execution_prover: Box<dyn ExecutionProverAPI>,
}

impl Prover {
    pub fn new(
        consensus_prover: Box<dyn ConsensusProverAPI>,
        execution_prover: Box<dyn ExecutionProverAPI>,
    ) -> Self {
        Prover {
            consensus_prover,
            execution_prover,
        }
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
                    messages: messages.iter().map(|m| m.message.clone()).collect(),
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
        let first_message = messages.get(0).ok_or("No messages in the batch")?;

        let exec_block = first_message.exec_block.clone();
        let beacon_block = first_message.beacon_block.clone();
        let receipts = first_message.receipts.clone();

        Ok((beacon_block, exec_block, receipts))
    }

    pub async fn get_ancestry_proof(
        &self,
        target_block_slot: u64,
        recent_block: &BeaconBlockHeader,
    ) -> Result<AncestryProof> {
        let ancestry_proof = self
            .consensus_prover
            .prove_ancestry(
                target_block_slot as usize,
                recent_block.slot as usize,
                &recent_block.state_root.to_string(),
            )
            .await
            .wrap_err(format!(
                "Failed to generate ancestry proof for block {:?}",
                target_block_slot
            ))?;

        Ok(ancestry_proof)
    }

    pub async fn get_receipt_proof(
        &self,
        exec_block: &Block<Transaction>,
        block_hash: Root,
        receipts: &[TransactionReceipt],
        tx_index: u64,
    ) -> Result<ReceiptProof> {
        let receipt = encode(&receipts[tx_index as usize].clone());

        let receipt_proof = self
            .execution_prover
            .generate_receipt_proof(exec_block, receipts, tx_index)
            .wrap_err(format!(
                "Failed to generate receipt proof for block {} and tx: {}",
                block_hash, tx_index
            ))?;

        let receipts_root_proof = self
            .consensus_prover
            .generate_receipts_root_proof(block_hash.to_string().as_str())
            .await
            .wrap_err(format!(
                "Failed to generate receipts root proof for block {} and tx: {}",
                block_hash, tx_index
            ))?;

        let receipt_proof = ReceiptProof {
            receipt: receipt.to_vec(),
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
            .consensus_prover
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
    use crate::prover::consensus::MockConsensusProver;
    use crate::prover::execution::MockExecutionProver;
    use crate::prover::Prover;

    use super::state_prover::MockStateProver;
    use super::types::{BatchMessageGroups, EnrichedMessage};
    use consensus_types::consensus::{BeaconBlockAlias, FinalityUpdate, OptimisticUpdate};
    use consensus_types::proofs::{
        AncestryProof, BatchVerificationData, CrossChainId, Message, UpdateVariant
    };
    use eth::consensus::MockConsensusRPC;
    use eth::execution::MockExecutionRPC;
    use ethers::types::{Block, Transaction, TransactionReceipt, H256};
    use indexmap::IndexMap;

    fn get_mock_update(
        is_optimistic: bool,
        attested_slot: u64,
        finality_slot: u64,
    ) -> UpdateVariant {
        if is_optimistic {
            let mut update = OptimisticUpdate::default();
            update.attested_header.beacon.slot = attested_slot;
            UpdateVariant::Optimistic(update)
        } else {
            let mut update = FinalityUpdate::default();
            update.finalized_header.beacon.slot = finality_slot;
            update.attested_header.beacon.slot = attested_slot;
            UpdateVariant::Finality(update)
        }
    }

    fn get_mock_message(slot: u64, block_number: u64, tx_hash: H256) -> EnrichedMessage {
        EnrichedMessage {
            message: Message {
                cc_id: CrossChainId {
                    chain: "ethereum".parse().unwrap(),
                    id: format!("{:x}:test", tx_hash).parse().unwrap(),
                },
                source_address: "0x0000000".parse().unwrap(),
                destination_chain: "polygon".parse().unwrap(),
                destination_address: "0x0000000".parse().unwrap(),
                payload_hash: Default::default(),
            },
            tx_hash,
            exec_block: get_mock_exec_block_with_txs(block_number),
            beacon_block: get_mock_beacon_block(slot),
            receipts: (1..100)
                .map(|i| {
                    let mut receipt = TransactionReceipt::default();
                    receipt.transaction_hash = H256::from_low_u64_be(i);
                    receipt
                })
                .collect(),
        }
    }

    fn setup() -> (MockConsensusRPC, MockExecutionRPC, MockStateProver) {
        let consensus_rpc = MockConsensusRPC::new();
        let execution_rpc = MockExecutionRPC::new();
        let state_prover = MockStateProver::new();

        (consensus_rpc, execution_rpc, state_prover)
    }

    /*
        Setup the following batch scenario:

        * block 1 -> tx 1 -> message 1
        * block 2 -> tx 2 -> message 2
        *   \            \
        *    \            -> message 3
        *     \
        *      --->  tx 3 -> message 4
        *
        * block 3 -> tx 4 -> message 5
    */
    fn get_mock_batch_message_groups() -> BatchMessageGroups {
        let mut messages = vec![];
        for i in 0..6 {
            let m = get_mock_message(i, i, H256::from_low_u64_be(i));
            messages.push(m);
        }

        let mut groups: BatchMessageGroups = IndexMap::new();
        let mut blockgroup1 = IndexMap::new();
        let mut blockgroup2 = IndexMap::new();
        let mut blockgroup3 = IndexMap::new();

        blockgroup1.insert(messages[1].tx_hash, vec![messages[1].clone()]);
        blockgroup2.insert(
            messages[2].tx_hash,
            vec![messages[2].clone(), messages[3].clone()],
        );
        blockgroup2.insert(messages[4].tx_hash, vec![messages[4].clone()]);
        blockgroup3.insert(messages[5].tx_hash, vec![messages[5].clone()]);

        groups.insert(1, blockgroup1);
        groups.insert(2, blockgroup2);
        groups.insert(3, blockgroup3);

        groups
    }

    fn get_mock_beacon_block(slot: u64) -> BeaconBlockAlias {
        let mut block = BeaconBlockAlias::default();
        block.slot = slot;
        block.body.execution_payload.transactions = ssz_rs::List::default();
        for _ in 1..10 {
            block
                .body
                .execution_payload
                .transactions
                .push(sync_committee_rs::consensus_types::Transaction::default());
        }
        block
    }

    fn get_mock_exec_block(block_number: u64) -> Block<H256> {
        let mut block = Block::default();
        block.number = Some(ethers::types::U64::from(block_number));
        block
    }

    fn get_mock_exec_block_with_txs(block_number: u64) -> Block<Transaction> {
        let mut block = Block::<Transaction>::default();
        block.number = Some(ethers::types::U64::from(block_number));
        block
    }

    #[tokio::test]
    async fn test_batch_generate_proofs() {
        let mock_update = get_mock_update(true, 1000, 505);
        let batch_message_groups = get_mock_batch_message_groups();

        let (_consensus_rpc, _execution_rpc, _state_prover) = setup();

        let mut consensus_prover = MockConsensusProver::new();
        consensus_prover
            .expect_prove_ancestry()
            .returning(|_, _, _| {
                Ok(AncestryProof::BlockRoots {
                    block_roots_index: 0,
                    block_root_proof: vec![],
                })
            });
        consensus_prover
            .expect_generate_transaction_proof()
            .returning(|_, _| Ok(Default::default()));
        consensus_prover
            .expect_generate_receipts_root_proof()
            .returning(|_| Ok(Default::default()));

        let mut execution_prover = MockExecutionProver::new();
        execution_prover
            .expect_generate_receipt_proof()
            .returning(|_, _, _| Ok(Default::default()));

        let prover = Prover::new(Box::new(consensus_prover), Box::new(execution_prover));

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
        assert_eq!(target_blocks[0].transactions_proofs[0].messages.len(), 1);
        assert_eq!(target_blocks[1].transactions_proofs[0].messages.len(), 2);
        assert_eq!(target_blocks[1].transactions_proofs[1].messages.len(), 1);
        assert_eq!(target_blocks[2].transactions_proofs[0].messages.len(), 1);
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

        let consensus_prover = MockConsensusProver::new();
        let execution_prover = MockExecutionProver::new();

        let prover = Prover::new(Box::new(consensus_prover), Box::new(execution_prover));

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
        // assert_eq!(
        //     result
        //         .get(&2)
        //         .unwrap()
        //         .get(&get_tx_hash(2))
        //         .unwrap(),
        //     &vec![mock_message2.message, mock_message3.message]
        // );
        // assert_eq!(
        //     result
        //         .get(&2)
        //         .unwrap()
        //         .get(&get_tx_hash(3))
        //         .unwrap(),
        //     &vec![mock_message4.message]
        // );
        // assert_eq!(
        //     result
        //         .get(&3)
        //         .unwrap()
        //         .get(&get_tx_hash(4))
        //         .unwrap(),
        //     &vec![mock_message5.message]
        // );
    }
}
