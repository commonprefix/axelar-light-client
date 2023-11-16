use std::sync::Arc;
use std::time::Instant;

use crate::{
    eth::{consensus::ConsensusRPC, execution::ExecutionRPC, utils::calc_slot_from_timestamp},
    types::InternalMessage,
};
use cita_trie::{MemoryDB, PatriciaTrie, Trie};
use consensus_types::{
    consensus::BeaconStateType,
    lightclient::{EventVerificationData, ReceiptProof, UpdateVariant},
};
use consensus_types::{
    lightclient::CrossChainId,
    proofs::{AncestryProof, BlockRootsProof},
};
use ethers::{
    types::{Block, TransactionReceipt, H256},
    utils::rlp::{encode, Encodable, RlpStream},
};
use eyre::{anyhow, Result};
use hasher::{Hasher, HasherKeccak};
use ssz_rs::{get_generalized_index, Merkleized, Node, SszVariableOrIndex};
use sync_committee_rs::{
    consensus_types::{BeaconBlock, BeaconBlockHeader},
    constants::{BLOCK_ROOTS_INDEX, SLOTS_PER_HISTORICAL_ROOT},
};

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
        let target_block = target_block.unwrap();
        let target_block_slot = calc_slot_from_timestamp(target_block.timestamp.as_u64());

        let mut target_beacon_block_header = self
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
                &mut target_beacon_block_header,
            )
            .await?;

        let receipts = self
            .execution_rpc
            .get_block_receipts(target_block.number.unwrap().as_u64())
            .await?;
        let receipt_index = self.get_receipt_index(receipts, &message.message.cc_id)?;
        let receipts_proof = self.prove_log_receipt(target_block, receipt_index).await?;

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
        target_block: &mut BeaconBlockHeader,
    ) -> Result<AncestryProof> {
        let is_in_block_roots_range = target_block.slot < recent_block_slot
            && recent_block_slot <= target_block.slot + SLOTS_PER_HISTORICAL_ROOT as u64;
        if !is_in_block_roots_range {
            return Err(anyhow!("Invalid slot"));
        }

        let block_index = get_generalized_index(
            &recent_block_state.block_roots,
            &[SszVariableOrIndex::Index(
                target_block.slot as usize % SLOTS_PER_HISTORICAL_ROOT,
            )],
        );

        println!("Generating proof from block roots to block_roots root");
        let start = Instant::now();
        let proof = ssz_rs::generate_proof(&mut recent_block_state.block_roots, &[block_index])?;
        println!("Generated proof: {:?}", start.elapsed());

        let block_roots_proof = BlockRootsProof {
            block_header_index: block_index as u64,
            block_header_branch: proof.clone(),
        };

        // println!(
        //     "{:?}",
        //     ssz_rs::verify_merkle_proof(
        //         &target_block.hash_tree_root()?,
        //         &proof[..],
        //         &GeneralizedIndex(block_index),
        //         &recent_block_state.block_roots.hash_tree_root()?
        //     )
        // );

        println!("Generating proof block roots to state root");
        let start = Instant::now();
        let block_roots_branch =
            ssz_rs::generate_proof(recent_block_state, &[BLOCK_ROOTS_INDEX as usize])?;
        println!("Generated proof: {:?}", start.elapsed());

        Ok(AncestryProof::BlockRoots {
            block_roots_proof,
            block_roots_branch,
        })
    }

    pub async fn prove_log_receipt(&self, block: Block<H256>, index: u64) -> Result<()> {
        let receipts = self
            .execution_rpc
            .get_block_receipts(block.number.unwrap().as_u64())
            .await?;

        let mut trie = self.generate_receipts_trie(receipts);
        let trie_root = trie.root().unwrap();
        let root = H256::from_slice(&trie_root[0..32]);

        if block.receipts_root != root {
            println!("Receipts root mismatch");
            return Ok(());
            //return Err(anyhow!("Invalid receipts root from trie generation"));
        }

        let log_index = encode(&index);
        let proof = trie
            .get_proof(log_index.to_vec().as_slice())
            .map_err(|e| anyhow!("Failed to generate proof: {:?}", e))?;

        // For themoukos
        let is_proof_valid = trie.verify_proof(&trie_root, &log_index, proof);
        println!("Is proof valid: {:?}", is_proof_valid.is_ok());

        Ok(())
    }

    // pub async fn prove_receipts_root_to_exec_payload(beaconBlock: BeaconBlock) -> Result<()> {

    // }

    fn generate_receipts_trie(
        &self,
        receipts: Vec<TransactionReceipt>,
    ) -> PatriciaTrie<MemoryDB, HasherKeccak> {
        let memdb = Arc::new(MemoryDB::new(true));
        let hasher = Arc::new(HasherKeccak::new());
        let mut trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));
        for (i, receipt) in receipts.iter().enumerate() {
            let key = encode(&i);
            let value = self.encode_receipt(receipt);
            trie.insert(key.to_vec(), value).unwrap();
        }

        trie
    }

    pub fn encode_receipt(&self, receipt: &TransactionReceipt) -> Vec<u8> {
        let legacy_receipt_encoded = receipt.rlp_bytes();
        if let Some(tx_type) = receipt.transaction_type {
            let tx_type = tx_type.as_u64();
            if tx_type == 0 {
                legacy_receipt_encoded.to_vec()
            } else {
                [&tx_type.to_be_bytes()[7..8], &legacy_receipt_encoded].concat()
            }
        } else {
            legacy_receipt_encoded.to_vec()
        }
    }

    fn get_receipt_index(
        &self,
        receipts: Vec<TransactionReceipt>,
        cc_id: &CrossChainId,
    ) -> Result<u64> {
        let tx_index = cc_id
            .id
            .split_once(":")
            .and_then(|f| f.0.parse().ok())
            .unwrap();

        let event_index = receipts
            .iter()
            .position(|r| r.transaction_index == tx_index)
            .unwrap();

        assert!(event_index == tx_index.as_usize(), "Event index mismatch");

        Ok(event_index as u64)
    }
}
