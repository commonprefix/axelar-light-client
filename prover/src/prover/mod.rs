mod consensus;
mod execution;
mod mocks;
pub mod state_prover;
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
use consensus_types::{
    consensus::{to_beacon_header, BeaconBlockAlias},
    lightclient::{MessageProof, ReceiptProof, TransactionProof, UpdateVariant},
};
use eth::{
    consensus::{ConsensusRPC, EthBeaconAPI},
    execution::{ExecutionAPI, ExecutionRPC},
    types::InternalMessage,
    utils::calc_slot_from_timestamp,
};
use ethers::types::{Block, Transaction, TransactionReceipt};
use ethers::utils::rlp::encode;
use eyre::{anyhow, Result};
use ssz_rs::{Merkleized, Node};
use sync_committee_rs::consensus_types::BeaconBlockHeader;

// Neccessary data for proving a message
struct ProofData {
    // Target execution block that contains the transaction/log.
    target_execution_block: Block<Transaction>,
    // Target beacon block that contains the target execution block.
    target_beacon_block: BeaconBlockAlias,
    // Receipts of the target execution block.
    receipts: Vec<TransactionReceipt>,
    // Block header of the most recent block. (Either finalized or attested depending or the UpdateVariant)
    recent_block_header: BeaconBlockHeader,
}

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
    ) -> Result<MessageProof> {
        let proof_data = self.gather_proof_data(&message, &update).await;
        if proof_data.is_err() {
            return Err(anyhow!("Failed to gather data for message {:?}", message));
        };

        let ProofData {
            mut target_beacon_block,
            target_execution_block,
            receipts,
            recent_block_header,
        } = proof_data.unwrap();

        let block_id = target_beacon_block.hash_tree_root()?.to_string();
        let tx_index = get_tx_index(&receipts, &message.message.cc_id)?;
        let transaction =
            target_beacon_block.body.execution_payload.transactions[tx_index as usize].clone();
        let receipt = encode(&receipts[tx_index as usize].clone());

        // Execution Proofs
        let receipt_proof = generate_receipt_proof(&target_execution_block, &receipts, tx_index)?;

        // Consensus Proofs
        let transaction_branch =
            generate_transaction_branch(&self.state_prover, &block_id, tx_index).await?;

        let receipts_branch = generate_receipts_root_branch(&self.state_prover, &block_id).await?;

        let ancestry_proof = prove_ancestry(
            &self.consensus_rpc,
            &self.state_prover,
            target_beacon_block.slot as usize,
            recent_block_header.slot as usize,
            &recent_block_header.state_root.to_string(),
        )
        .await?;

        Ok(MessageProof {
            update: update.clone(),
            target_block: to_beacon_header(&target_beacon_block)?,
            ancestry_proof,
            transaction_proof: TransactionProof {
                transaction_index: tx_index,
                transaction_gindex: transaction_branch.gindex,
                transaction_branch: transaction_branch.witnesses,
                transaction,
            },
            receipt_proof: ReceiptProof {
                receipt: receipt.to_vec(),
                receipt_proof,
                receipts_root_proof: receipts_branch.witnesses,
                receipts_root: Node::from_bytes(
                    target_execution_block.receipts_root.as_bytes().try_into()?,
                ),
            },
        })
    }

    async fn gather_proof_data(
        &self,
        message: &InternalMessage,
        update: &UpdateVariant,
    ) -> Result<ProofData> {
        let target_execution_block = self
            .execution_rpc
            .get_block_with_txs(message.block_number)
            .await?
            .ok_or_else(|| anyhow!("Block not found"))?;
        let target_block_slot = calc_slot_from_timestamp(target_execution_block.timestamp.as_u64());

        let target_beacon_block = self
            .consensus_rpc
            .get_beacon_block(target_block_slot)
            .await?;

        let receipts = self
            .execution_rpc
            .get_block_receipts(target_execution_block.number.unwrap().as_u64())
            .await?;

        let recent_block_header = match update.clone() {
            UpdateVariant::Finality(update) => update.finalized_header.beacon,
            UpdateVariant::Optimistic(update) => update.attested_header.beacon,
        };

        Ok(ProofData {
            target_execution_block,
            target_beacon_block,
            receipts,
            recent_block_header,
        })
    }
}
