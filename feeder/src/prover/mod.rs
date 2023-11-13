use crate::{
    eth::{consensus::ConsensusRPC, execution::ExecutionRPC, utils::calc_slot_from_timestamp},
    types::{BeaconStateType, ExecutionProof, FinalityOrOptimisticUpdate, Message, Proof},
};
use eyre::Result;
use ssz_rs::Merkleized;
use sync_committee_primitives::{
    constants::{BLOCK_ROOTS_INDEX, SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT},
    types::{AncestryProof, BlockRootsProof},
    util::compute_epoch_at_slot,
};
use types::consensus::{BeaconBlockHeader, BeaconHeader};

struct Prover {
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
    ) -> Result<Proof> {
        let block = self.execution_rpc.get_block(message.block_number).await?;
        let slot = calc_slot_from_timestamp(block.timestamp.as_u64());
        let recent_block: BeaconHeader;
        match update {
            FinalityOrOptimisticUpdate::Finality(update) => {
                recent_block = update.finalized_header;
            }
            FinalityOrOptimisticUpdate::Optimistic(update) => {
                recent_block = update.attested_header;
            }
        }

        let state = self
            .consensus_rpc
            .get_state(recent_block.beacon.slot.as_u64(), false)
            .await?;

        let ancestry_proof = self.prove_ancestry(&mut state, recent_block.beacon).await?;

        let proof = Proof {
            update,
            ancestry_proof,
            execution_proof: ExecutionProof {},
        };

        return Ok(proof);
    }

    pub fn prove_ancestry(
        &self,
        state: &mut BeaconStateType,
        mut header: BeaconBlockHeader,
    ) -> Result<AncestryProof> {
        // Check if block root should still be part of the block roots vector on the beacon state
        let epoch_for_header = compute_epoch_at_slot(header.slot) as usize;
        let epoch_for_state = compute_epoch_at_slot(state.slot) as usize;

        if epoch_for_state.saturating_sub(epoch_for_header)
            >= SLOTS_PER_HISTORICAL_ROOT / SLOTS_PER_EPOCH as usize
        {
            // todo:  Historical root proofs
            unimplemented!()
        } else {
            // Get index of block root in the block roots
            let block_root = header
                .hash_tree_root()
                .expect("hash tree root should be valid");
            let block_index = state
                .block_roots
                .as_ref()
                .into_iter()
                .position(|root| root == &block_root)
                .expect("Block root should exist in block_roots");

            let proof = ssz_rs::generate_proof(&mut state.block_roots, &[block_index])?;

            let block_roots_proof = BlockRootsProof {
                block_header_index: block_index as u64,
                block_header_branch: proof,
            };

            let block_roots_branch = ssz_rs::generate_proof(state, &[BLOCK_ROOTS_INDEX as usize])?;
            Ok(AncestryProof::BlockRoots {
                block_roots_proof,
                block_roots_branch,
            })
        }
    }
}
