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
        TransactionProof, UpdateVariant, BatchedEventProofs, BatchedBlockProofs, AncestryProof, BatchMessageProof,
    },
};
use eth::{
    consensus::EthBeaconAPI, execution::EthExecutionAPI, types::{InternalMessage},
    utils::calc_slot_from_timestamp,
};
use types::BatchMessageGroups;
use ethers::{types::{Block, Transaction, TransactionReceipt}, utils::rlp::encode};
use eyre::{anyhow, Context, Result};
use ssz_rs::{Merkleized, Node};
use sync_committee_rs::{constants::Root, consensus_types::BeaconBlockHeader};
use indexmap::IndexMap;

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
        let mut groups: BatchMessageGroups = IndexMap::new();

        for message in messages_before_slot {
            let tx_hash = get_tx_hash_from_cc_id(&message.message.cc_id)?;
            let block_num = message.block_number;

            groups
                .entry(block_num)
                .or_insert_with(IndexMap::new)
                .entry(tx_hash)
                .or_insert_with(Vec::new)
                .push(message.message);
        }

        Ok(groups)
    }

    pub async fn batch_generate_proofs(&self, batch_message_groups: BatchMessageGroups, update: UpdateVariant) ->  Result<BatchMessageProof> {
        let recent_block = match update.clone() {
            UpdateVariant::Finality(update) => update.finalized_header.beacon,
            UpdateVariant::Optimistic(update) => update.attested_header.beacon,
        };

        let mut update_level_verifications: Vec<BatchedEventProofs> = vec![];
        for (target_block_num, block_groups) in &batch_message_groups {
            let (exec_block, mut beacon_block) = self.get_block(*target_block_num).await?;
            let target_block_slot = calc_slot_from_timestamp(exec_block.timestamp.as_u64());
            let block_hash = beacon_block.hash_tree_root()?;

            let ancestry_proof = self.get_ancestry_proof(target_block_slot, &recent_block).await?;

            let mut update_level_verification = BatchedEventProofs {
                ancestry_proof,
                target_block: to_beacon_header(&beacon_block)?,
                tx_level_verification: vec![],
            };

            for (tx_hash, messages) in block_groups {
                let receipts = self.execution_rpc.get_block_receipts(*target_block_num).await?;
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

        Ok(BatchMessageProof {
            update,
            update_level_verifications
        })
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
            .generate_receipt_proof(exec_block, &receipts, tx_index)
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

    pub async fn get_block(&self, block_num: u64) -> Result<(Block<Transaction>, BeaconBlockAlias)> {
        let exec_block: Block<Transaction> = self
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
    

    use crate::prover::consensus::MockConsensusProver;
    use crate::prover::execution::MockExecutionProver;
    use crate::prover::Prover;

    use super::state_prover::MockStateProver;
    use super::types::BatchMessageGroups;
    use consensus_types::consensus::{BeaconBlockAlias, FinalityUpdate, OptimisticUpdate};
    use consensus_types::proofs::{UpdateVariant, CrossChainId, Message, AncestryProof, BatchMessageProof};
    use eth::consensus::MockConsensusRPC;
    use eth::execution::MockExecutionRPC;
    use eth::types::InternalMessage;
    use eth::utils::calc_timestamp_from_slot;
    use ethers::types::{Block, Transaction, TransactionReceipt, H256};
    use eyre::Result;
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

    fn get_mock_block_receipts(tx_hashes: Vec<H256>) -> Result<Vec<TransactionReceipt>> {
        let receipts: Vec<TransactionReceipt> = tx_hashes
            .into_iter()
            .map(|tx_hash| {
                let mut receipt = TransactionReceipt::default();
                receipt.transaction_hash = tx_hash;
                receipt
            })
            .collect();

        Ok(receipts)
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
    ) -> (MockConsensusRPC, MockExecutionRPC, MockStateProver) {
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
        let mut groups: BatchMessageGroups = IndexMap::new();

        let mut blockgroup1: IndexMap<H256, Vec<Message>> = IndexMap::new();
        let mut blockgroup2: IndexMap<H256, Vec<Message>> = IndexMap::new();
        let mut blockgroup3: IndexMap<H256, Vec<Message>> = IndexMap::new();

        let message1 = get_mock_message(1, H256::from_low_u64_be(1));
        let message2 = get_mock_message(2, H256::from_low_u64_be(2));
        let message3 = get_mock_message(2, H256::from_low_u64_be(2));
        let message4 = get_mock_message(2, H256::from_low_u64_be(3));
        let message5 = get_mock_message(3, H256::from_low_u64_be(4));

        blockgroup1.insert(message1.tx_hash, vec![message1.message]);
        blockgroup2.insert(message2.tx_hash, vec![message2.message, message3.message]);
        blockgroup2.insert(message4.tx_hash, vec![message4.message]);
        blockgroup3.insert(message5.tx_hash, vec![message5.message]);

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
            block.body.execution_payload.transactions.push(sync_committee_rs::consensus_types::Transaction::default());
        }
        block
    }
  
    fn get_mock_exec_block(block_number: u64, timestamp: u64) -> Block<H256> {
        let mut block = Block::default();
        block.number = Some(ethers::types::U64::from(block_number));
        block.timestamp = ethers::types::U256::from(timestamp);
        block
    }

    fn get_mock_exec_block_with_txs(block_number: u64, timestamp: u64) -> Block<Transaction> {
        let mut block = Block::<Transaction>::default();
        block.number = Some(ethers::types::U64::from(block_number));
        block.timestamp = ethers::types::U256::from(timestamp);
        block
    }

    #[tokio::test]
    async fn test_batch_generate_proofs() {
        let mock_update = get_mock_update(true, 1000, 505);
        let batch_message_groups = get_mock_batch_message_groups();

        let get_mock_slot_from_block_num = |block_num| block_num;

        let (mut consensus_rpc, mut execution_rpc, _state_prover) = setup();
        consensus_rpc
            .expect_get_beacon_block()
            .returning(move |i| Ok(get_mock_beacon_block(i)));
        execution_rpc
            .expect_get_block_with_txs()
            .returning(move |i| Ok(Some(get_mock_exec_block_with_txs(i, calc_timestamp_from_slot(get_mock_slot_from_block_num(i))))));
        execution_rpc
            .expect_get_block_receipts()
            .returning(move |i|  {
                let tx_hashes = if i == 1 {
                    vec![H256::from_low_u64_be(1)]
                }
                else if i == 2 {
                    vec![H256::from_low_u64_be(2), H256::from_low_u64_be(3)]
                }
                else {
                    vec![H256::from_low_u64_be(4)]
                };

                Ok(get_mock_block_receipts(tx_hashes).unwrap())
        });
        let mut consensus_prover = MockConsensusProver::new();
        consensus_prover.expect_prove_ancestry().returning(|_, _, _| Ok(AncestryProof::BlockRoots { block_roots_index: 0, block_root_proof: vec![] }));
        consensus_prover.expect_generate_transaction_proof().returning(|_, _| Ok(Default::default()));
        consensus_prover.expect_generate_receipts_root_proof().returning(|_| Ok(Default::default()));
        let mut execution_prover = MockExecutionProver::new();
        execution_prover.expect_generate_receipt_proof().returning(|_, _, _| Ok(Default::default()));

        let prover = Prover::new(
            &consensus_rpc,
            &execution_rpc,
            &consensus_prover,
            &execution_prover,
        );

        let res = prover.batch_generate_proofs(batch_message_groups, mock_update.clone()).await;
        assert!(res.is_ok());

        let BatchMessageProof { update, update_level_verifications } = res.unwrap();

        assert_eq!(update, mock_update);
        assert_eq!(update_level_verifications.len(), 3);
        assert_eq!(update_level_verifications[0].tx_level_verification.len(), 1);
        assert_eq!(update_level_verifications[1].tx_level_verification.len(), 2);
        assert_eq!(update_level_verifications[2].tx_level_verification.len(), 1);
        assert_eq!(update_level_verifications[0].tx_level_verification[0].messages.len(), 1);
        assert_eq!(update_level_verifications[1].tx_level_verification[0].messages.len(), 2);
        assert_eq!(update_level_verifications[1].tx_level_verification[1].messages.len(), 1);
        assert_eq!(update_level_verifications[2].tx_level_verification[0].messages.len(), 1);

        assert_eq!(update_level_verifications[0].tx_level_verification[0].messages, vec![get_mock_message(1, H256::from_low_u64_be(1)).message]);
    }

    #[tokio::test]
    async fn test_batch_messages() {
        let consensus_rpc = MockConsensusRPC::new();
        let mut execution_rpc = MockExecutionRPC::new();

        let update = get_mock_update(true, 1000, 505);

        execution_rpc.expect_get_blocks().returning(move |_| {
            Ok(vec![
                Some(get_mock_exec_block(1, calc_timestamp_from_slot(501))),
                Some(get_mock_exec_block(2, calc_timestamp_from_slot(502))),
                Some(get_mock_exec_block(2, calc_timestamp_from_slot(502))),
                Some(get_mock_exec_block(2, calc_timestamp_from_slot(502))),
                Some(get_mock_exec_block(3, calc_timestamp_from_slot(503))),
            ])
        });

        let get_tx_hash = H256::from_low_u64_be;

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

        execution_rpc.expect_get_blocks().returning(move |_| {
            Ok(vec![
                Some(get_mock_exec_block(5, calc_timestamp_from_slot(501))),
                None,
                Some(get_mock_exec_block(7, calc_timestamp_from_slot(503)))
            ])
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

        execution_rpc.expect_get_blocks().returning(move |_| {
            Ok(vec![
                Some(get_mock_exec_block(5, calc_timestamp_from_slot(501))),
                Some(get_mock_exec_block(6, calc_timestamp_from_slot(502))),
                Some(get_mock_exec_block(7, calc_timestamp_from_slot(503)))
            ])
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
