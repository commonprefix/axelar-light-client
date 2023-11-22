mod consensus;
mod execution;

use std::time::Instant;

use crate::{
    eth::{consensus::ConsensusRPC, execution::ExecutionRPC, utils::calc_slot_from_timestamp},
    prover::{
        consensus::{
            generate_exec_payload_branch, generate_receipts_branch, generate_transactions_branch,
            prove_ancestry,
        },
        execution::{generate_receipt_proof, generate_transaction_proof},
    },
    types::InternalMessage,
};
use consensus_types::lightclient::CrossChainId;
use consensus_types::{
    consensus::to_beacon_header,
    lightclient::{EventVerificationData, ReceiptProof, UpdateVariant},
};
use ethers::types::TransactionReceipt;
use eyre::{anyhow, Result};
use ssz_rs::Merkleized;
use sync_committee_rs::constants::Bytes32;

pub struct Prover {
    execution_rpc: ExecutionRPC,
    consensus_rpc: ConsensusRPC,
}

impl Prover {
    pub fn new(execution_rpc: ExecutionRPC, consensus_rpc: ConsensusRPC) -> Self {
        Prover {
            execution_rpc,
            consensus_rpc,
        }
    }

    pub async fn prove_event(
        &self,
        message: InternalMessage,
        update: UpdateVariant,
    ) -> Result<EventVerificationData> {
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

        let receipts = self
            .execution_rpc
            .get_block_receipts(target_block.number.unwrap().as_u64())
            .await?;

        let recent_block = match update.clone() {
            UpdateVariant::Finality(update) => update.finalized_header.beacon,
            UpdateVariant::Optimistic(update) => update.attested_header.beacon,
        };

        let mut recent_block_state = self.consensus_rpc.get_state(recent_block.slot).await?;
        let tx_index = self.get_tx_index(&receipts, &message.message.cc_id)?;

        let now = Instant::now();

        // Execution Proofs
        let receipt_proof = generate_receipt_proof(&target_block, &receipts, tx_index)?;
        println!(
            "Got receipts proof: {:?} {}",
            receipt_proof.len(),
            now.elapsed().as_secs()
        );

        let transaction_proof = generate_transaction_proof(&target_block, tx_index)?;
        println!("Got transactions proof: {}", now.elapsed().as_millis());

        // Consensus Proofs
        let transactions_branch = generate_transactions_branch(&mut target_beacon_block)?;
        println!("Got transactions branch: {}", now.elapsed().as_millis());

        let receipts_branch = generate_receipts_branch(&mut target_beacon_block)?;
        println!("Got receipts branch: {}", now.elapsed().as_millis());

        let exec_payload_branch = generate_exec_payload_branch(&mut target_beacon_block)?;
        println!("Got exec_payload branch: {}", now.elapsed().as_millis());

        let ancestry_proof = prove_ancestry(&mut recent_block_state, target_beacon_block.slot)?;
        println!("Got ancestry proof {}", now.elapsed().as_millis());

        Ok(EventVerificationData {
            message: message.message,
            update: update.clone(),
            target_block: to_beacon_header(&target_beacon_block)?,
            block_roots_root: recent_block_state.block_roots.hash_tree_root()?,
            ancestry_proof,
            receipt_proof: ReceiptProof {
                transaction_index: tx_index,
                receipt_proof,
                receipts_branch,
                transaction_proof,
                transactions_branch,
                exec_payload_branch,
                transactions_root: Bytes32::try_from(target_block.transactions_root.as_bytes())?,
                receipts_root: Bytes32::try_from(target_block.receipts_root.as_bytes())?,
                execution_payload_root: target_beacon_block
                    .body
                    .execution_payload
                    .hash_tree_root()?,
            },
        })
    }

    fn get_tx_index(
        &self,
        receipts: &Vec<TransactionReceipt>,
        cc_id: &CrossChainId,
    ) -> Result<u64> {
        let tx_hash = cc_id.id.split_once(':').unwrap().0;

        let tx_index = receipts
            .iter()
            .position(|r| r.transaction_hash.to_string() == tx_hash)
            .unwrap();

        Ok(tx_index as u64)
    }
}
