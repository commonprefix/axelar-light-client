use std::sync::Arc;

use cita_trie::{MemoryDB, PatriciaTrie, Trie};
use ethers::{
    types::{Block, Transaction, TransactionReceipt, H256},
    utils::rlp::{encode, Encodable},
};
use eyre::{anyhow, Result};
use hasher::HasherKeccak;

/**
 * Generates an MPT proof from a transaction to the transactions_root.
*/
pub fn generate_transaction_proof(block: &Block<Transaction>, index: u64) -> Result<Vec<Vec<u8>>> {
    let mut trie = generate_trie(block.transactions.clone(), encode_transaction);
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

/**
 * Generates an MPT proof from a receipt to the receipts_root.
*/
pub fn generate_receipt_proof(
    block: &Block<Transaction>,
    receipts: &Vec<TransactionReceipt>,
    index: u64,
) -> Result<Vec<Vec<u8>>> {
    let mut trie = generate_trie(receipts.clone(), encode_receipt);
    let trie_root = trie.root().unwrap();

    // Reality check
    if block.receipts_root != H256::from_slice(&trie_root[0..32]) {
        return Err(anyhow!("Invalid receipts root from trie generation"));
    }

    let log_index = encode(&index);
    let proof = trie
        .get_proof(log_index.to_vec().as_slice())
        .map_err(|e| anyhow!("Failed to generate proof: {:?}", e))?;

    Ok(proof)
}

fn generate_trie<T>(
    leaves: Vec<T>,
    encode_fn: fn(&T) -> Vec<u8>,
) -> PatriciaTrie<MemoryDB, HasherKeccak> {
    let memdb = Arc::new(MemoryDB::new(true));
    let hasher = Arc::new(HasherKeccak::new());
    let mut trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));
    for (i, leaf) in leaves.iter().enumerate() {
        let key = encode(&i);
        let value = encode_fn(leaf);
        trie.insert(key.to_vec(), value).unwrap();
    }

    trie
}

fn encode_transaction(transaction: &Transaction) -> Vec<u8> {
    transaction.rlp().to_vec()
}

fn encode_receipt(receipt: &TransactionReceipt) -> Vec<u8> {
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
