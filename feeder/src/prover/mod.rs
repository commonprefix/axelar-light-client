mod consensus;
mod execution;
mod mocks;
pub mod types;
mod utils;

use crate::{
    eth::{
        consensus::{ConsensusRPC, EthBeaconAPI},
        execution::{ExecutionAPI, ExecutionRPC},
        state_prover::StateProver,
        utils::calc_slot_from_timestamp,
    },
    prover::{
        consensus::{generate_receipts_root_proof, generate_transaction_proof, prove_ancestry},
        execution::{generate_receipt_proof, get_tx_index},
    },
    types::InternalMessage,
};
use consensus_types::consensus::to_beacon_header;
use consensus_types::lightclient::MessageVerification;
use consensus_types::proofs::{MessageProof, ReceiptProof, TransactionProof, UpdateVariant};
use eyre::{anyhow, Result};
use ssz_rs::{Merkleized, Node};

pub struct Prover {
    execution_rpc: ExecutionRPC,
    consensus_rpc: ConsensusRPC,
    state_prover: StateProver,
}

impl Prover {
    pub fn new(
        execution_rpc: ExecutionRPC,
        consensus_rpc: ConsensusRPC,
        state_prover: StateProver,
    ) -> Self {
        Prover {
            execution_rpc,
            consensus_rpc,
            state_prover,
        }
    }

    pub async fn prove_event(
        &self,
        message: InternalMessage,
        update: UpdateVariant,
    ) -> Result<MessageVerification> {
        let target_block = self
            .execution_rpc
            .get_block_with_txs(message.block_number)
            .await?
            .ok_or_else(|| anyhow!("Block not found"))?;

        let target_block_slot = calc_slot_from_timestamp(target_block.timestamp.as_u64());
        let mut target_beacon_block = self
            .consensus_rpc
            .get_beacon_block(target_block_slot)
            .await?;
        let block_id = target_beacon_block.hash_tree_root()?.to_string();

        // let mut header = self
        //     .consensus_rpc
        //     .get_beacon_block_header(target_block_slot)
        //     .await?;

        let receipts = self
            .execution_rpc
            .get_block_receipts(target_block.number.unwrap().as_u64())
            .await?;

        let recent_block = match update.clone() {
            UpdateVariant::Finality(update) => update.finalized_header.beacon,
            UpdateVariant::Optimistic(update) => update.attested_header.beacon,
        };

        let tx_index = get_tx_index(&receipts, &message.message.cc_id)?;
        let transaction =
            target_beacon_block.body.execution_payload.transactions[tx_index as usize].clone();

        // Execution Proofs
        let receipt_proof = generate_receipt_proof(&target_block, &receipts, tx_index)?;
        println!("Got receipts proof");

        // Consensus Proofs
        let transaction_proof =
            generate_transaction_proof(&self.state_prover, &block_id, tx_index).await?;
        println!("Got transactions proof");

        let receipts_root_proof =
            generate_receipts_root_proof(&self.state_prover, &block_id).await?;
        println!("Got receipts root proof");

        let ancestry_proof = prove_ancestry(
            &self.consensus_rpc,
            &self.state_prover,
            target_beacon_block.slot as usize,
            recent_block.slot as usize,
            &recent_block.state_root.to_string(),
        )
        .await?;
        println!("Got ancestry proof");

        Ok(MessageVerification {
            message: message.message,
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
                        target_block.receipts_root.as_bytes().try_into()?,
                    ),
                },
            },
        })
    }
}
