use std::sync::Arc;
use std::time::Instant;

use crate::{
    eth::{consensus::ConsensusRPC, execution::ExecutionRPC, utils::calc_slot_from_timestamp},
    types::InternalMessage,
};
use cita_trie::{MemoryDB, PatriciaTrie, Trie};
use consensus_types::{
    consensus::{to_beacon_header, BeaconBlockAlias, BeaconStateType},
    lightclient::{EventVerificationData, ReceiptProof, UpdateVariant},
};
use consensus_types::{
    lightclient::CrossChainId,
    proofs::{AncestryProof, BlockRootsProof},
};
use ethers::{
    types::{Block, Transaction, TransactionReceipt, H256},
    utils::rlp::{self, encode, Encodable},
};
use eyre::{anyhow, Result};
use hasher::HasherKeccak;
use ssz_rs::{get_generalized_index, GeneralizedIndex, Merkleized, Node, SszVariableOrIndex};
use sync_committee_rs::{
    consensus_types::BeaconBlockHeader,
    constants::{Bytes32, BLOCK_ROOTS_INDEX, SLOTS_PER_HISTORICAL_ROOT},
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
        let target_block = self
            .execution_rpc
            .get_block_with_txs(message.block_number)
            .await?;
        if target_block.is_none() {
            return Err(eyre::eyre!("Block not found"));
        }
        let target_block = target_block.unwrap();
        let target_block_slot = calc_slot_from_timestamp(target_block.timestamp.as_u64());

        let mut target_beacon_block = self
            .consensus_rpc
            .get_beacon_block(target_block_slot)
            .await?;

        let mut beacon_block_header = to_beacon_header(&target_beacon_block)?;

        let recent_block = match update.clone() {
            UpdateVariant::Finality(update) => update.finalized_header.beacon,
            UpdateVariant::Optimistic(update) => update.attested_header.beacon,
        };

        // let mut recent_block_state = self.consensus_rpc.get_state(recent_block.slot).await?;
        // let ancestry_proof = self
        //     .prove_ancestry(
        //         &mut recent_block_state,
        //         recent_block.slot,
        //         &mut beacon_block_header,
        //     )
        //     .await?;
        let ancestry_proof = AncestryProof::BlockRoots {
            block_roots_proof: BlockRootsProof::default(),
            block_roots_branch: Vec::<Node>::default(),
        };

        let receipts = self
            .execution_rpc
            .get_block_receipts(target_block.number.unwrap().as_u64())
            .await?;
        println!("Got receipts: {:?}", receipts.len());

        let tx_index = self.get_tx_index(receipts, &message.message.cc_id)?;
        println!("Got tx index: {:?}", tx_index);
        let receipts_proof = self.prove_receipt(&target_block, tx_index).await?;
        println!("Got receipts proof: {:?}", receipts_proof.len());
        let transactions_proof = self.prove_transaction(&target_block, tx_index).await?;
        println!("Got transactions proof: {:?}", transactions_proof.len());

        let transactions_root_branch = self
            .prove_transactions_root_to_exec_payload(&mut target_beacon_block)
            .await?;
        println!(
            "Got transactions root branch: {:?}",
            transactions_root_branch.len()
        );

        let receipts_root_branch = self
            .prove_receipts_root_to_exec_payload(&mut target_beacon_block)
            .await?;
        let execution_payload_branch = self
            .prove_exec_payload_to_beacon_block(&mut target_beacon_block)
            .await?;

        Ok(EventVerificationData {
            message: message.message,
            update: update.clone(),
            target_block: beacon_block_header,
            block_roots_root: Node::default(), //recent_block_state.block_roots.hash_tree_root()?,
            ancestry_proof,
            receipt_proof: ReceiptProof {
                transaction_index: tx_index,
                receipt_branch: receipts_proof,
                receipts_root_branch,
                transaction_branch: transactions_proof,
                transactions_root_branch: transactions_root_branch,
                execution_payload_branch,
                transactions_root: Bytes32::try_from(target_block.receipts_root.as_bytes())?,
                receipts_root: Bytes32::try_from(target_block.receipts_root.as_bytes())?,
                execution_payload_root: target_beacon_block
                    .body
                    .execution_payload
                    .hash_tree_root()?,
            },
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

    pub async fn prove_transaction(
        &self,
        block: &Block<Transaction>,
        index: u64,
    ) -> Result<Vec<Vec<u8>>> {
        let mut trie = self.generate_tx_trie(block.transactions.clone());
        let trie_root = trie.root().unwrap();

        // Reality check
        if block.transactions_root != H256::from_slice(&trie_root[0..32]) {
            return Err(anyhow!("Invalid transactions root from trie generation"));
        }

        let tx_index = encode(&index);
        let proof = trie
            .get_proof(tx_index.to_vec().as_slice())
            .map_err(|e| anyhow!("Failed to generate proof: {:?}", e))?;

        Ok(proof)
    }

    pub async fn prove_receipt(
        &self,
        block: &Block<Transaction>,
        index: u64,
    ) -> Result<Vec<Vec<u8>>> {
        let receipts = self
            .execution_rpc
            .get_block_receipts(block.number.unwrap().as_u64())
            .await?;

        let mut trie = self.generate_receipts_trie(receipts);
        let trie_root = trie.root().unwrap();

        // Reality check
        if block.receipts_root != H256::from_slice(&trie_root[0..32]) {
            return Err(anyhow!("Invalid transactions root from trie generation"));
        }

        let log_index = encode(&index);
        let proof = trie
            .get_proof(log_index.to_vec().as_slice())
            .map_err(|e| anyhow!("Failed to generate proof: {:?}", e))?;

        Ok(proof)
    }

    pub async fn prove_exec_payload_to_beacon_block(
        &self,
        beacon_block: &mut BeaconBlockAlias,
    ) -> Result<Vec<Node>> {
        let path = vec![SszVariableOrIndex::Name("execution_payload")];
        let g_index = get_generalized_index(&beacon_block.body, &path);
        let proof = ssz_rs::generate_proof(&mut beacon_block.body, &[g_index])?;

        Ok(proof)
    }

    pub async fn prove_transactions_root_to_exec_payload(
        &self,
        beacon_block: &mut BeaconBlockAlias,
    ) -> Result<Vec<Node>> {
        let path = vec![SszVariableOrIndex::Name("transactions")];
        // println!("{:#?}", beacon_block.body.execution_payload);
        let g_index = get_generalized_index(&beacon_block.body.execution_payload, &path);
        let proof = ssz_rs::generate_proof(&mut beacon_block.body.execution_payload, &[g_index])?;

        Ok(proof)
    }

    pub async fn prove_receipts_root_to_exec_payload(
        &self,
        beacon_block: &mut BeaconBlockAlias,
    ) -> Result<Vec<Node>> {
        let path = vec![SszVariableOrIndex::Name("receipts_root")];
        let g_index = get_generalized_index(&beacon_block.body.execution_payload, &path);
        let proof = ssz_rs::generate_proof(&mut beacon_block.body.execution_payload, &[g_index])?;

        Ok(proof)
    }

    fn generate_tx_trie(
        &self,
        transactions: Vec<Transaction>,
    ) -> PatriciaTrie<MemoryDB, HasherKeccak> {
        let memdb = Arc::new(MemoryDB::new(true));
        let hasher = Arc::new(HasherKeccak::new());
        let mut trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));
        for (i, tx) in transactions.iter().enumerate() {
            let key = encode(&i);
            let value = tx.rlp().to_vec();
            trie.insert(key.to_vec(), value).unwrap();
        }

        trie
    }

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

    fn get_tx_index(&self, receipts: Vec<TransactionReceipt>, cc_id: &CrossChainId) -> Result<u64> {
        let tx_hash = cc_id.id.split_once(":").unwrap().0;

        let tx_index = receipts
            .iter()
            .position(|r| r.transaction_hash.to_string() == tx_hash)
            .unwrap();

        Ok(tx_index as u64)
    }
}
