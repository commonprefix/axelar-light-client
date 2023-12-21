pub mod consensus;
pub mod execution;
mod mocks;
pub mod state_prover;
pub mod types;
mod utils;

use self::utils::{get_tx_hash_from_cc_id, get_tx_index};
use crate::prover::{consensus::ConsensusProverAPI, execution::ExecutionProverAPI};
use consensus_types::{
    consensus::{to_beacon_header, BeaconBlockAlias},
    proofs::{
        ReceiptProof,
        TransactionProof, UpdateVariant, BatchedEventProofs, BatchedBlockProofs, AncestryProof,
    },
};
use eth::{
    consensus::EthBeaconAPI, execution::EthExecutionAPI, types::{InternalMessage, BatchMessageGroups},
    utils::calc_slot_from_timestamp,
};
use ethers::{types::{Block, Transaction, TransactionReceipt}, utils::rlp::encode};
use eyre::{anyhow, Context, Result};
use ssz_rs::{Merkleized, Node};
use sync_committee_rs::{constants::Root, consensus_types::BeaconBlockHeader};
use std::collections::HashMap;

pub struct Prover<'a> {
    consensus_rpc: &'a dyn EthBeaconAPI,
    execution_rpc: &'a dyn EthExecutionAPI,
    consensus_prover: &'a dyn ConsensusProverAPI,
    execution_prover: &'a dyn ExecutionProverAPI,
}

impl<'a> Prover<'a> {
    pub fn new(
        consensus_rpc: &'a dyn EthBeaconAPI,
        execution_rpc: &'a dyn EthExecutionAPI,
        consensus_prover: &'a dyn ConsensusProverAPI,
        execution_prover: &'a dyn ExecutionProverAPI,
    ) -> Self {
        Prover {
            consensus_rpc,
            execution_rpc,
            consensus_prover,
            execution_prover,
        }
    }

    pub async fn batch_messages(&self, messages: &Vec<InternalMessage>, update: &UpdateVariant) -> Result<BatchMessageGroups> {
        let recent_block_slot = match update {
            UpdateVariant::Finality(update) => update.finalized_header.beacon.slot,
            UpdateVariant::Optimistic(update) => update.attested_header.beacon.slot,
        };

        let messages_before_slot = self.filter_messages_before_slot(messages, recent_block_slot).await?;
        let mut groups: BatchMessageGroups = HashMap::new();

        for message in messages_before_slot {
            let tx_hash = get_tx_hash_from_cc_id(&message.message.cc_id)?;
            let block_num = message.block_number;

            groups
                .entry(block_num)
                .or_insert_with(HashMap::new)
                .entry(tx_hash)
                .or_insert_with(Vec::new)
                .push(message.message);
        }

        Ok(groups)
    }

    async fn batch_generate_proofs(&self, batch_message_groups: BatchMessageGroups, update: UpdateVariant) ->  Result<()> {
        let recent_block = match update {
            UpdateVariant::Finality(update) => update.finalized_header.beacon,
            UpdateVariant::Optimistic(update) => update.attested_header.beacon,
        };

        let mut update_level_verifications: Vec<BatchedEventProofs> = vec![];
        for (target_block_num, block_groups) in &batch_message_groups {
            let (exec_block, mut beacon_block) = self.get_block(target_block_num.clone()).await?;
            let target_block_slot = calc_slot_from_timestamp(exec_block.timestamp.as_u64());
            let block_hash = beacon_block.hash_tree_root()?;

            let ancestry_proof = self.get_ancestry_proof(target_block_slot, &recent_block).await?;

            let mut update_level_verification = BatchedEventProofs {
                ancestry_proof,
                target_block: to_beacon_header(&beacon_block)?,
                tx_level_verification: vec![],
            };

            for (tx_hash, messages) in block_groups {
                let receipts = self.execution_rpc.get_block_receipts(target_block_num.clone()).await?;
                let tx_index = get_tx_index(&receipts, tx_hash)?;

                let transaction_proof = self.get_transaction_proof(&beacon_block, block_hash, tx_index).await?;
                let receipt_proof = self.get_receipt_proof(&exec_block, block_hash, receipts, tx_index).await?;

                let tx_level_verification = BatchedBlockProofs {
                    transaction_proof,
                    receipt_proof,
                    messages: messages.clone()
                };

                update_level_verification.tx_level_verification.push(tx_level_verification);
            }

            update_level_verifications.push(update_level_verification);
        }

        Ok(())
    }

    pub async fn get_ancestry_proof(&self, target_block_slot: u64, recent_block: &BeaconBlockHeader) -> Result<AncestryProof> {
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

    pub async fn get_receipt_proof(&self, exec_block: &Block<Transaction>, block_hash: Root, receipts: Vec<TransactionReceipt>, tx_index: u64) -> Result<ReceiptProof> {
        let receipt = encode(&receipts[tx_index as usize].clone());

        let receipt_proof = self
            .execution_prover
            .generate_receipt_proof(&exec_block, &receipts, tx_index)
            .wrap_err(format!(
                "Failed to generate receipt proof for block {} and tx: {}",
                block_hash, tx_index
            ))?;

        let receipts_root_proof = self
            .consensus_prover
            .generate_receipts_root_proof(&block_hash.to_string().as_str())
            .await
            .wrap_err(format!(
                "Failed to generate receipts root proof for block {} and tx: {}",
                block_hash, tx_index
            ))?;

        let receipt_proof = ReceiptProof {
            receipt: receipt.to_vec(),
            receipt_proof,
            receipts_root_proof: receipts_root_proof.witnesses,
            receipts_root: Node::from_bytes(
                exec_block.receipts_root.as_bytes().try_into()?,
            ),
        };

        Ok(receipt_proof)
    }

    pub async fn get_transaction_proof(&self, beacon_block: &BeaconBlockAlias, block_hash: Root, tx_index: u64) -> Result<TransactionProof> {
        let transaction = beacon_block.body.execution_payload.transactions[tx_index as usize].clone();

        let proof = self
            .consensus_prover
            .generate_transaction_proof(&block_hash.to_string().as_str(), tx_index)
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

    pub async fn get_block(&self, block_num: u64) -> Result<(Block<Transaction>, BeaconBlockAlias)> {
        let exec_block = self
            .execution_rpc
            .get_block_with_txs(block_num)
            .await
            .wrap_err(format!("Failed to get exec block {}", block_num))?
            .ok_or_else(|| anyhow!("Could not find execution block {:?}", block_num))?;

        let block_slot = calc_slot_from_timestamp(exec_block.timestamp.as_u64());

        let beacon_block = self
            .consensus_rpc
            .get_beacon_block(block_slot)
            .await
            .wrap_err(format!("Failed to get beacon block {}", block_num))?;

        Ok((exec_block, beacon_block))
    }

    async fn filter_messages_before_slot(&self, messages: &Vec<InternalMessage>, slot: u64) -> Result<Vec<InternalMessage>> {
        let block_nums = messages.iter().map(|m| m.block_number).collect::<Vec<u64>>();
        let blocks = self
            .execution_rpc
            .get_blocks(block_nums.as_slice())
            .await?;


        let mut messages_before_slot: Vec<InternalMessage> = vec![];

        for (i, message) in messages.iter().enumerate() {
            if blocks[i].is_none() {
                println!("Block is none, txHash of msg: {:?}, msg slot: {:?}, ", messages[i].tx_hash, slot);
                continue
            }

            let block = blocks[i].as_ref().unwrap();
            if calc_slot_from_timestamp(block.timestamp.as_u64()) >= slot {
                println!("Message.slot > slot, txHash of msg: {:?}, msg slot: {:?}, max slot {:?}", messages[i].tx_hash, calc_slot_from_timestamp(block.timestamp.as_u64()), slot);
                continue
            }

            messages_before_slot.push(message.clone());
        }

        Ok(messages_before_slot)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use crate::prover::consensus::{ConsensusProver, MockConsensusProver};
    use crate::prover::execution::MockExecutionProver;
    use crate::prover::Prover;

    use super::state_prover::MockStateProver;
    use consensus_types::consensus::{BeaconBlockAlias, FinalityUpdate, OptimisticUpdate};
    use consensus_types::proofs::{CrossChainId, Message, UpdateVariant};
    use eth::consensus::MockConsensusRPC;
    use eth::error::RPCError;
    use eth::execution::MockExecutionRPC;
    use eth::types::InternalMessage;
    use eth::utils::calc_timestamp_from_slot;
    use ethers::types::{Block, Transaction, TransactionReceipt, H256};
    use eyre::{anyhow, Result};
    use mockall::predicate;

    fn get_block_with_txs(block_num: u64) -> Result<Option<Block<Transaction>>> {
        let filename = format!("./src/prover/testdata/execution_blocks/{}.json", block_num);
        let file = File::open(filename).unwrap();
        let res: Option<Block<Transaction>> = Some(serde_json::from_reader(file).unwrap());
        Ok(res)
    }

    fn get_block_receipts(block_num: u64) -> Result<Vec<TransactionReceipt>> {
        let filename = format!(
            "./src/prover/testdata/execution_blocks/receipts/{}.json",
            block_num
        );
        let file = File::open(filename).unwrap();
        let res: Vec<TransactionReceipt> = serde_json::from_reader(file).unwrap();
        Ok(res)
    }

    fn get_beacon_block(slot: u64) -> Result<BeaconBlockAlias, RPCError> {
        let filename = format!("./src/prover/testdata/beacon_blocks/{}.json", slot);
        let file = File::open(filename).unwrap();
        let res: BeaconBlockAlias = serde_json::from_reader(file).unwrap();
        Ok(res)
    }

    fn get_mock_update(
        is_optimistic: bool,
        attested_slot: u64,
        finality_slot: u64,
    ) -> UpdateVariant {
        if is_optimistic {
            let mut update = OptimisticUpdate::default();
            update.attested_header.beacon.slot = attested_slot;
            return UpdateVariant::Optimistic(update);
        } else {
            let mut update = FinalityUpdate::default();
            update.finalized_header.beacon.slot = finality_slot;
            update.attested_header.beacon.slot = attested_slot;
            return UpdateVariant::Finality(update);
        };
    }

    fn get_mock_exec_block(block_number: u64, timestamp: u64) -> Block<H256> {
        let mut block = Block::default();
        block.number = Some(ethers::types::U64::from(block_number));
        block.timestamp = ethers::types::U256::from(timestamp);
        block
    }

    fn get_mock_message(block_number: u64, tx_hash: H256) -> InternalMessage {
        InternalMessage {
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
            block_hash: Default::default(),
            tx_hash,
            block_number,
        }
    }

    fn setup(
        target_block_slot: u64,
        target_block_num: u64,
        mock: bool,
    ) -> (MockConsensusRPC, MockExecutionRPC, MockStateProver) {
        let mut consensus_rpc = MockConsensusRPC::new();
        let mut execution_rpc = MockExecutionRPC::new();
        let state_prover = MockStateProver::new();

        if mock {
            consensus_rpc
                .expect_get_beacon_block()
                .with(predicate::eq(target_block_slot))
                .returning(move |_| get_beacon_block(target_block_slot)); // Provide a mock result

            execution_rpc
                .expect_get_block_with_txs()
                .with(predicate::eq(target_block_num))
                .returning(move |_| get_block_with_txs(target_block_num));

            execution_rpc
                .expect_get_block_receipts()
                .with(predicate::eq(target_block_num))
                .returning(move |_| get_block_receipts(target_block_num));
        }

        (consensus_rpc, execution_rpc, state_prover)
    }

    #[tokio::test]
    async fn test_batch_messages() {
        let consensus_rpc = MockConsensusRPC::new();
        let mut execution_rpc = MockExecutionRPC::new();
        let state_prover = MockStateProver::new();

        let update = get_mock_update(true, 1000, 505);

        execution_rpc.expect_get_blocks().returning(move |_| {
            return Ok(vec![
                Some(get_mock_exec_block(1, calc_timestamp_from_slot(501))),
                Some(get_mock_exec_block(2, calc_timestamp_from_slot(502))),
                Some(get_mock_exec_block(2, calc_timestamp_from_slot(502))),
                Some(get_mock_exec_block(2, calc_timestamp_from_slot(502))),
                Some(get_mock_exec_block(3, calc_timestamp_from_slot(503))),
            ]);
        });

        let get_tx_hash = |i| H256::from_low_u64_be(i);

        let mock_message1 = get_mock_message(1, get_tx_hash(1));
        let mock_message2 = get_mock_message(2, get_tx_hash(2));
        let mock_message3 = get_mock_message(2, get_tx_hash(2));
        let mock_message4 = get_mock_message(2, get_tx_hash(3));
        let mock_message5 = get_mock_message(3, get_tx_hash(4));

        let messages = [
            mock_message1.clone(),
            mock_message2.clone(),
            mock_message3.clone(),
            mock_message4.clone(),
            mock_message5.clone(),
        ];

        let consensus_prover = MockConsensusProver::new();
        let execution_prover = MockExecutionProver::new();

        let prover = Prover::new(
            &consensus_rpc,
            &execution_rpc,
            &consensus_prover,
            &execution_prover,
        );

        let result = prover.batch_messages(&messages.to_vec(), &update).await.unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result.get(&1).unwrap().len(), 1);
        assert_eq!(result.get(&2).unwrap().len(), 2);
        assert_eq!(result.get(&3).unwrap().len(), 1);
        assert_eq!(
            result
                .get(&1)
                .unwrap()
                .get(&get_tx_hash(1))
                .unwrap(),
            &vec![mock_message1.message]
        );
        assert_eq!(
            result
                .get(&2)
                .unwrap()
                .get(&get_tx_hash(2))
                .unwrap(),
            &vec![mock_message2.message, mock_message3.message]
        );
        assert_eq!(
            result
                .get(&2)
                .unwrap()
                .get(&get_tx_hash(3))
                .unwrap(),
            &vec![mock_message4.message]
        );
        assert_eq!(
            result
                .get(&3)
                .unwrap()
                .get(&get_tx_hash(4))
                .unwrap(),
            &vec![mock_message5.message]
        );
    }

    #[tokio::test]
    async fn test_filter_messages_before_slot_with_none() {
        let consensus_rpc = MockConsensusRPC::new();
        let mut execution_rpc = MockExecutionRPC::new();
        let state_prover = MockStateProver::new();

        execution_rpc.expect_get_blocks().returning(move |_| {
            return Ok(vec![
                Some(get_mock_exec_block(5, calc_timestamp_from_slot(501))),
                None,
                Some(get_mock_exec_block(7, calc_timestamp_from_slot(503)))
            ]);
        });

        let messages = [
            get_mock_message(1, Default::default()),
            get_mock_message(2, Default::default()),
            get_mock_message(3, Default::default()),
        ];

        let consensus_prover = MockConsensusProver::new();
        let execution_prover = MockExecutionProver::new();

        let prover = Prover::new(
            &consensus_rpc,
            &execution_rpc,
            &consensus_prover,
            &execution_prover,
        );

        let result = prover.filter_messages_before_slot(&messages.to_vec(), 505).await.unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].block_number, 1);
        assert_eq!(result[1].block_number, 3);
    }

    #[tokio::test]
    async fn test_filter_messages_before_slot() {
        let consensus_rpc = MockConsensusRPC::new();
        let mut execution_rpc = MockExecutionRPC::new();
        let state_prover = MockStateProver::new();

        execution_rpc.expect_get_blocks().returning(move |_| {
            return Ok(vec![
                Some(get_mock_exec_block(5, calc_timestamp_from_slot(501))),
                Some(get_mock_exec_block(6, calc_timestamp_from_slot(502))),
                Some(get_mock_exec_block(7, calc_timestamp_from_slot(503)))
            ]);
        });

        let messages = [
            get_mock_message(1, Default::default()),
            get_mock_message(2, Default::default()),
            get_mock_message(3, Default::default()),
        ];

        let consensus_prover = MockConsensusProver::new();
        let execution_prover = MockExecutionProver::new();

        let prover = Prover::new(
            &consensus_rpc,
            &execution_rpc,
            &consensus_prover,
            &execution_prover,
        );

        let result = prover.filter_messages_before_slot(&messages.to_vec(), 502).await.unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].block_number, 1);
    }
}
