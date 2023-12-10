pub mod consensus;
pub mod execution;
mod mocks;
pub mod state_prover;
pub mod types;
mod utils;

use self::types::ProofAuxiliaryData;
use crate::prover::{consensus::ConsensusProverAPI, execution::ExecutionProverAPI};
use consensus_types::{
    consensus::to_beacon_header,
    proofs::{MessageProof, ReceiptProof, TransactionProof, UpdateVariant},
};
use eth::{
    consensus::EthBeaconAPI, execution::EthExecutionAPI, types::InternalMessage,
    utils::calc_slot_from_timestamp,
};
use eyre::{anyhow, Context, Result};
use ssz_rs::{Merkleized, Node};

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

    pub async fn prove_event(
        &self,
        message: &mut InternalMessage,
        update: UpdateVariant,
    ) -> Result<MessageVerification> {
        let proof_data = self
            .gather_proof_data(message, &update)
            .await
            .wrap_err(format!(
                "Failed to gather proof data for message {:?}",
                message
            ))?;

        let ProofAuxiliaryData {
            mut target_beacon_block,
            target_execution_block,
            receipts,
            recent_block_header,
        } = proof_data;

        let block_id = target_beacon_block.hash_tree_root()?.to_string();
        let tx_index = self
            .execution_prover
            .get_tx_index(&receipts, &message.message.cc_id)?;
        let transaction =
            target_beacon_block.body.execution_payload.transactions[tx_index as usize].clone();

        let log_index_str = message.message.cc_id.id.split(':').nth(1).unwrap();
        let log_index: usize = log_index_str.parse()?;

        let mut logs_before_tx = 0;
        for idx in 0..tx_index {
            logs_before_tx += receipts.get(idx as usize).unwrap().logs.len();
        }

        let colon_position = message.message.cc_id.id.find(':').unwrap();
        // TODO: Remove on production
        message.message.cc_id.id = format!(
            "{}:{}",
            &message.message.cc_id.id[..colon_position],
            log_index - logs_before_tx
        )
        .try_into()?;

        // Execution Proofs
        let receipt_proof = self
            .execution_prover
            .generate_receipt_proof(&target_execution_block, &receipts, tx_index)
            .wrap_err(format!(
                "Failed to generate receipt proof for message {:?}",
                message
            ))?;

        // Consensus Proofs
        let transaction_proof = self
            .consensus_prover
            .generate_transaction_proof(&block_id, tx_index)
            .await
            .wrap_err(format!(
                "Failed to generate transaction proof for message {:?}",
                message
            ))?;

        let receipts_root_proof = self
            .consensus_prover
            .generate_receipts_root_proof(&block_id)
            .await
            .wrap_err(format!(
                "Failed to generate receipts root proof for message {:?}",
                message
            ))?;

        let ancestry_proof = self
            .consensus_prover
            .prove_ancestry(
                target_beacon_block.slot as usize,
                recent_block_header.slot as usize,
                &recent_block_header.state_root.to_string(),
            )
            .await
            .wrap_err(format!(
                "Failed to generate ancestry proof for message {:?}",
                message
            ))?;

        Ok(MessageVerification {
            message: message.message.clone(),
            proofs: MessageProof {
                update: update.clone(),
                target_block: to_beacon_header(&target_beacon_block)?,
                ancestry_proof,
                transaction_proof: TransactionProof {
                    transaction_index: tx_index,
                    transaction_gindex: transaction_proof.gindex,
                    transaction_proof: transaction_proof.witnesses,
                    transaction,
                },
                receipt_proof: ReceiptProof {
                    receipt_proof,
                    receipts_root_proof: receipts_root_proof.witnesses,
                    receipts_root: Node::from_bytes(
                        target_execution_block.receipts_root.as_bytes().try_into()?,
                    ),
                },
            },
        })
    }

    async fn gather_proof_data(
        &self,
        message: &InternalMessage,
        update: &UpdateVariant,
    ) -> Result<ProofAuxiliaryData> {
        let target_execution_block = self
            .execution_rpc
            .get_block_with_txs(message.block_number)
            .await
            .wrap_err(format!(
                "Failed to get execution block {}",
                message.block_number
            ))?
            .ok_or_else(|| anyhow!("Could not find execution block {:?}", message.block_number))?;

        let target_block_slot = calc_slot_from_timestamp(target_execution_block.timestamp.as_u64());

        let target_beacon_block = self
            .consensus_rpc
            .get_beacon_block(target_block_slot)
            .await
            .wrap_err(format!(
                "Failed to get beacon block {}",
                message.block_number
            ))?;

        let receipts: Vec<ethers::types::TransactionReceipt> = self
            .execution_rpc
            .get_block_receipts(message.block_number)
            .await
            .wrap_err(format!(
                "Failed to get receipts for block {}",
                message.block_number
            ))?;

        let recent_block_header = match update.clone() {
            UpdateVariant::Finality(update) => update.finalized_header.beacon,
            UpdateVariant::Optimistic(update) => update.attested_header.beacon,
        };

        Ok(ProofAuxiliaryData {
            target_execution_block,
            target_beacon_block,
            receipts,
            recent_block_header,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::state_prover::MockStateProver;
    use consensus_types::consensus::{BeaconBlockAlias, FinalityUpdate, OptimisticUpdate};
    use consensus_types::proofs::{CrossChainId, Message, UpdateVariant};
    use eth::consensus::MockConsensusRPC;
    use eth::error::RPCError;
    use eth::execution::MockExecutionRPC;
    use eth::types::InternalMessage;
    use ethers::types::{Block, Transaction, TransactionReceipt};
    use eyre::Result;
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

    fn get_mock_message(block_number: u64) -> InternalMessage {
        InternalMessage {
            message: Message {
                cc_id: CrossChainId {
                    chain: "ethereum".parse().unwrap(),
                    id: "test:test".parse().unwrap(),
                },
                source_address: "0x0000000".parse().unwrap(),
                destination_chain: "polygon".parse().unwrap(),
                destination_address: "0x0000000".parse().unwrap(),
                payload_hash: Default::default(),
            },
            block_hash: Default::default(),
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

    // #[tokio::test]
    // async fn test_gather_proof_data_finality() {
    //     let target_block_slot = 7807119;
    //     let target_block_num = 18615160;

    //     let (consensus_rpc, execution_rpc, state_prover) =
    //         setup(target_block_slot, target_block_num, true);

    //     let prover = Prover::new(&consensus_rpc, &execution_rpc, &state_prover);
    //     let message = get_mock_message(target_block_num);
    //     let update = get_mock_update(false, 1000, 500);

    //     let result = prover.gather_proof_data(&message, &update).await.unwrap();

    //     assert_eq!(
    //         result.target_execution_block,
    //         get_block_with_txs(target_block_num).unwrap().unwrap()
    //     );
    //     assert_eq!(
    //         result.receipts,
    //         get_block_receipts(target_block_num).unwrap()
    //     );
    //     assert_eq!(
    //         result.target_beacon_block,
    //         get_beacon_block(target_block_slot).unwrap()
    //     );
    //     match update {
    //         UpdateVariant::Finality(update) => {
    //             assert_eq!(result.recent_block_header, update.finalized_header.beacon)
    //         }
    //         _ => panic!("Wrong update variant"),
    //     }
    // }

    // #[tokio::test]
    // async fn test_gather_proof_data_optimistic() {
    //     let target_block_slot = 7807119;
    //     let target_block_num = 18615160;

    //     let (consensus_rpc, execution_rpc, state_prover) =
    //         setup(target_block_slot, target_block_num, true);

    //     let prover = Prover::new(&consensus_rpc, &execution_rpc, &state_prover);
    //     let message = get_mock_message(target_block_num);
    //     let update = get_mock_update(true, 1000, 500);

    //     let result = prover.gather_proof_data(&message, &update).await.unwrap();

    //     assert_eq!(
    //         result.target_execution_block,
    //         get_block_with_txs(target_block_num).unwrap().unwrap()
    //     );
    //     assert_eq!(
    //         result.receipts,
    //         get_block_receipts(target_block_num).unwrap()
    //     );
    //     assert_eq!(
    //         result.target_beacon_block,
    //         get_beacon_block(target_block_slot).unwrap()
    //     );
    //     match update {
    //         UpdateVariant::Optimistic(update) => {
    //             assert_eq!(result.recent_block_header, update.attested_header.beacon)
    //         }
    //         _ => panic!("Wrong update variant"),
    //     }
    // }

    // #[tokio::test]
    // async fn test_gather_proof_data_invalid_execution() {
    //     let target_block_slot = 7807119;
    //     let target_block_num = 18615160;

    //     let (consensus_rpc, mut execution_rpc, state_prover) =
    //         setup(target_block_slot, target_block_num, false);

    //     execution_rpc
    //         .expect_get_block_with_txs()
    //         .with(predicate::always())
    //         .returning(move |_| Err(anyhow!("Invalid execution block")));

    //     let prover = Prover::new(&consensus_rpc, &execution_rpc, &state_prover);
    //     let message = get_mock_message(target_block_num);
    //     let update = get_mock_update(true, 1000, 500);

    //     let result = prover.gather_proof_data(&message, &update).await;

    //     assert!(result.is_err())
    // }

    // #[tokio::test]
    // async fn test_gather_proof_data_invalid_consensus() {
    //     let target_block_slot = 7807119;
    //     let target_block_num = 18615160;

    //     let (mut consensus_rpc, mut execution_rpc, state_prover) =
    //         setup(target_block_slot, target_block_num, false);

    //     consensus_rpc
    //         .expect_get_beacon_block()
    //         .with(predicate::eq(target_block_slot))
    //         .returning(move |_| Err(RPCError::NotFoundError("test".into()))); // Provide a mock result

    //     execution_rpc
    //         .expect_get_block_with_txs()
    //         .with(predicate::eq(target_block_num))
    //         .returning(move |_| get_block_with_txs(target_block_num));

    //     let prover = Prover::new(&consensus_rpc, &execution_rpc, &state_prover);
    //     let message = get_mock_message(target_block_num);
    //     let update = get_mock_update(true, 1000, 500);

    //     let result = prover.gather_proof_data(&message, &update).await;

    //     assert!(result.is_err())
    // }
}
