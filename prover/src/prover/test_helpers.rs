use cita_trie::{MemoryDB, PatriciaTrie, Trie};

use ethers::{
    types::{Block, Transaction, TransactionReceipt},
    utils::rlp::encode,
};
use eyre::{anyhow, Result};
use hasher::HasherKeccak;
use std::{fs::File, sync::Arc};
use sync_committee_rs::constants::Root;

pub fn verify_trie_proof(root: Root, key: u64, proof_bytes: Vec<Vec<u8>>) -> Result<Vec<u8>> {
    let memdb = Arc::new(MemoryDB::new(true));
    let hasher = Arc::new(HasherKeccak::new());

    let trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));
    let proof = trie.verify_proof(
        root.as_bytes(),
        encode(&key).to_vec().as_slice(),
        proof_bytes,
    );

    if proof.is_err() {
        return Err(anyhow!("Invalid proof"));
    }

    match proof.unwrap() {
        Some(value) => Ok(value),
        None => Err(anyhow!("Invalid proof")),
    }
}

pub fn get_mock_block_with_txs(block_number: u64) -> Block<Transaction> {
    let filename = format!(
        "./src/prover/testdata/execution_blocks/{}.json",
        block_number
    );
    let file = File::open(filename).unwrap();
    let res: Option<Block<Transaction>> = serde_json::from_reader(file).unwrap();
    res.unwrap()
}

pub fn get_mock_block_receipts(block_number: u64) -> Vec<TransactionReceipt> {
    let filename = format!(
        "./src/prover/testdata/execution_blocks/receipts/{}.json",
        block_number
    );
    let file = File::open(filename).unwrap();
    let res: Vec<TransactionReceipt> = serde_json::from_reader(file).unwrap();
    res
}