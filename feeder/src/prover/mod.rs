use std::{backtrace, time::Instant};

use crate::{
    error,
    eth::{consensus::ConsensusRPC, execution::ExecutionRPC, utils::calc_slot_from_timestamp},
    types::{FinalityOrOptimisticUpdate, Message},
};
use eyre::{anyhow, Result};
use ssz_rs::Merkleized;
use sync_committee_rs::{
    constants::{BLOCK_ROOTS_INDEX, SLOTS_PER_HISTORICAL_ROOT},
    types::{AncestryProof, BlockRootsProof},
    util::compute_epoch_at_slot,
};
use types::consensus::{BeaconBlockHeader, BeaconHeader, BeaconStateType};

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
        message: Message,
        update: FinalityOrOptimisticUpdate,
    ) -> Result<()> {
        let interested_block = self.execution_rpc.get_block(message.block_number).await?;
        if interested_block.is_none() {
            return Err(eyre::eyre!("Block not found"));
        }
        let interested_block_slot =
            calc_slot_from_timestamp(interested_block.unwrap().timestamp.as_u64());

        let recent_block = match update {
            FinalityOrOptimisticUpdate::Finality(update) => update.finalized_header.beacon,
            FinalityOrOptimisticUpdate::Optimistic(update) => update.attested_header.beacon,
        };

        let ancestry_proof = self
            .prove_ancestry(recent_block, interested_block_slot)
            .await?;

        println!("Ancestry Proof: {:#?}", ancestry_proof);

        Ok(())
    }

    pub async fn prove_ancestry(
        &self,
        recent_block: BeaconBlockHeader,
        interested_block_slot: u64,
    ) -> Result<AncestryProof> {
        println!("Downloading state");
        let start = Instant::now();
        let mut state = self.consensus_rpc.get_state(recent_block.slot).await?;
        println!("Downloaded state: {:?}", start.elapsed());

        let is_in_block_roots_range = interested_block_slot < recent_block.slot
            && recent_block.slot <= interested_block_slot + SLOTS_PER_HISTORICAL_ROOT as u64;
        if !is_in_block_roots_range {
            return Err(anyhow!("Invalid slot"));
        }

        let block_index = interested_block_slot as usize % SLOTS_PER_HISTORICAL_ROOT;

        println!("Generating proof from block roots to block_roots root");
        let start = Instant::now();
        let proof = ssz_rs::generate_proof(&mut state.block_roots, &[block_index])?;
        println!("Generated proof: {:?}", start.elapsed());

        let block_roots_proof = BlockRootsProof {
            block_header_index: block_index as u64,
            block_header_branch: proof,
        };

        println!("Generating proof block roots to state root");
        let start = Instant::now();
        let block_roots_branch = ssz_rs::generate_proof(&mut state, &[BLOCK_ROOTS_INDEX as usize])?;
        println!("Generated proof: {:?}", start.elapsed());
        Ok(AncestryProof::BlockRoots {
            block_roots_proof,
            block_roots_branch,
        })
        //}
    }
}
