use std::time::Instant;

use crate::{
    eth::{consensus::ConsensusRPC, execution::ExecutionRPC, utils::calc_slot_from_timestamp},
    types::InternalMessage,
};
use consensus_types::proofs::{AncestryProof, BlockRootsProof};
use consensus_types::{
    consensus::BeaconStateType,
    lightclient::{EventVerificationData, ReceiptProof, UpdateVariant},
};
use eyre::{anyhow, Result};
use ssz_rs::Merkleized;
use sync_committee_rs::constants::{BLOCK_ROOTS_INDEX, SLOTS_PER_HISTORICAL_ROOT};

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

    pub async fn generate_proof(
        &self,
        message: InternalMessage,
        update: UpdateVariant,
    ) -> Result<EventVerificationData> {
        let target_block = self.execution_rpc.get_block(message.block_number).await?;
        if target_block.is_none() {
            return Err(eyre::eyre!("Block not found"));
        }
        let target_block_slot = calc_slot_from_timestamp(target_block.unwrap().timestamp.as_u64());
        let target_beacon_block_header = self
            .consensus_rpc
            .get_beacon_block_header(target_block_slot)
            .await?;

        let recent_block = match update.clone() {
            UpdateVariant::Finality(update) => update.finalized_header.beacon,
            UpdateVariant::Optimistic(update) => update.attested_header.beacon,
        };

        let mut recent_block_state = self.consensus_rpc.get_state(recent_block.slot).await?;
        let ancestry_proof = self
            .prove_ancestry(
                &mut recent_block_state,
                recent_block.slot,
                target_block_slot,
            )
            .await?;

        println!("Ancestry Proof: {:#?}", ancestry_proof);

        Ok(EventVerificationData {
            message: message.message,
            update: update.clone(),
            target_block: target_beacon_block_header,
            block_roots_root: recent_block_state.block_roots.hash_tree_root().unwrap(),
            ancestry_proof,
            receipt_proof: ReceiptProof::default(),
        })
    }

    pub async fn prove_ancestry(
        &self,
        recent_block_state: &mut BeaconStateType,
        recent_block_slot: u64,
        interested_block_slot: u64,
    ) -> Result<AncestryProof> {
        let is_in_block_roots_range = interested_block_slot < recent_block_slot
            && recent_block_slot <= interested_block_slot + SLOTS_PER_HISTORICAL_ROOT as u64;
        if !is_in_block_roots_range {
            return Err(anyhow!("Invalid slot"));
        }

        let block_index = interested_block_slot as usize % SLOTS_PER_HISTORICAL_ROOT;

        println!("Generating proof from block roots to block_roots root");
        let start = Instant::now();
        let proof = ssz_rs::generate_proof(&mut recent_block_state.block_roots, &[block_index])?;
        println!("Generated proof: {:?}", start.elapsed());

        let block_roots_proof = BlockRootsProof {
            block_header_index: block_index as u64,
            block_header_branch: proof,
        };

        println!("Generating proof block roots to state root");
        let start = Instant::now();
        let block_roots_branch =
            ssz_rs::generate_proof(recent_block_state, &[BLOCK_ROOTS_INDEX as usize])?;
        println!("Generated proof: {:?}", start.elapsed());
        Ok(AncestryProof::BlockRoots {
            block_roots_proof,
            block_roots_branch,
        })
        //}
    }
}
