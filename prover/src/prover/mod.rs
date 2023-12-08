mod consensus;
mod execution;
mod mocks;
pub mod state_prover;
pub mod types;
mod utils;

use crate::prover::{
    consensus::{generate_receipts_root_proof, generate_transaction_proof, prove_ancestry},
    execution::{generate_receipt_proof, get_tx_index},
};
use consensus_types::lightclient::MessageVerification;
use consensus_types::{
    consensus::to_beacon_header,
    proofs::{MessageProof, ReceiptProof, TransactionProof, UpdateVariant},
};
use eth::{
    consensus::{ConsensusRPC, EthBeaconAPI},
    execution::{ExecutionAPI, ExecutionRPC},
    types::InternalMessage,
    utils::calc_slot_from_timestamp,
};
use ethers::utils::rlp::encode;
use eyre::{anyhow, Context, Result};
use ssz_rs::{Merkleized, Node};

use self::{state_prover::StateProver, types::ProofAuxiliaryData};

pub struct Prover<'a> {
    consensus_rpc: &'a ConsensusRPC,
    execution_rpc: &'a ExecutionRPC,
    state_prover: &'a StateProver,
}

impl<'a> Prover<'a> {
    pub fn new(
        consensus_rpc: &'a ConsensusRPC,
        execution_rpc: &'a ExecutionRPC,
        state_prover: &'a StateProver,
    ) -> Self {
        Prover {
            consensus_rpc,
            execution_rpc,
            state_prover,
        }
    }

    pub async fn prove_event(
        &self,
        message: &mut InternalMessage,
        update: UpdateVariant,
    ) -> Result<MessageVerification> {
        let proof_data = self
            .gather_proof_data(&message, &update)
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
        let tx_index = get_tx_index(&receipts, &message.message.cc_id)?;
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
        let receipt_proof =
            generate_receipt_proof(&target_execution_block, &receipts, tx_index).wrap_err(
                format!("Failed to generate receipt proof for message {:?}", message),
            )?;

        // Consensus Proofs
        let transaction_proof = generate_transaction_proof(self.state_prover, &block_id, tx_index)
            .await
            .wrap_err(format!(
                "Failed to generate transaction proof for message {:?}",
                message
            ))?;

        let receipts_root_proof = generate_receipts_root_proof(self.state_prover, &block_id)
            .await
            .wrap_err(format!(
                "Failed to generate receipts root proof for message {:?}",
                message
            ))?;

        let ancestry_proof = prove_ancestry(
            self.consensus_rpc,
            self.state_prover,
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

        let receipts = self
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
