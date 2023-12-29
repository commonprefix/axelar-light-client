use std::{str::FromStr, sync::Arc};

use cita_trie::{PatriciaTrie, MemoryDB, Trie};
use consensus_types::proofs::CrossChainId;
use ethers::{types::{TransactionReceipt, H256}, utils::rlp::{encode, RlpStream}};
use eyre::{anyhow, Result};
use hasher::HasherKeccak;
use ssz_rs::SszVariableOrIndex;

use super::types::BatchMessageGroups;

pub fn parse_path(path: &Vec<SszVariableOrIndex>) -> String {
    let mut path_str = String::new();
    for p in path {
        match p {
            SszVariableOrIndex::Name(name) => path_str.push_str(&format!(",{}", name)),
            SszVariableOrIndex::Index(index) => path_str.push_str(&format!(",{}", index)),
        }
    }
    path_str[1..].to_string() // remove first comma
}

pub fn get_tx_index(receipts: &[TransactionReceipt], tx_hash: &H256) -> Result<u64> {
    let tx_index = receipts
        .iter()
        .position(|r| format!("{:x}", r.transaction_hash) == format!("{:x}", tx_hash));

    match tx_index {
        Some(index) => Ok(index as u64),
        None => Err(anyhow!("Transaction not found in receipts. {:?}", tx_hash)),
    }
}

pub fn get_tx_hash_from_cc_id(cc_id: &CrossChainId) -> Result<H256> {
    let tx_hash = cc_id
        .id
        .split_once(':')
        .ok_or_else(|| anyhow!("Invalid CrossChainId format. {:?}", cc_id))?
        .0;

    Ok(H256::from_str(tx_hash)?)
}

pub fn generate_trie<T>(
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

pub fn encode_receipt(receipt: &TransactionReceipt) -> Vec<u8> {
    let mut stream = RlpStream::new();
    stream.begin_list(4);
    stream.append(&receipt.status.unwrap());
    stream.append(&receipt.cumulative_gas_used);
    stream.append(&receipt.logs_bloom);
    stream.append_list(&receipt.logs);

    let legacy_receipt_encoded = stream.out();
    let tx_type = receipt.transaction_type.unwrap().as_u64();

    match tx_type {
        0 => legacy_receipt_encoded.to_vec(),
        _ => [&tx_type.to_be_bytes()[7..8], &legacy_receipt_encoded].concat(),
    }
}

#[cfg(not(tarpaulin_include))]
pub fn debug_print_batch_message_groups(batch_message_groups: &BatchMessageGroups) {
    for (block_number, message_groups) in batch_message_groups {
        let block_count = message_groups.len();
        for (tx_hash, messages) in message_groups {
            let message_count = messages.len();
            println!(
                "Block number: {}, Block count: {}, Tx hash: {}, Message count: {}",
                block_number, block_count, tx_hash, message_count
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use consensus_types::proofs::CrossChainId;
    use ethers::types::{TransactionReceipt, H256};
    use ssz_rs::SszVariableOrIndex;

    use crate::prover::utils::{get_tx_hash_from_cc_id, get_tx_index, parse_path};

    fn get_mock_receipt() -> TransactionReceipt {
        TransactionReceipt {
            transaction_hash: H256::random(),
            ..Default::default()
        }
    }

    #[test]
    fn test_get_tx_index_valid() {
        let receipts = vec![get_mock_receipt(), get_mock_receipt(), get_mock_receipt()];

        for (i, receipt) in receipts.iter().enumerate() {
            let tx_hash = receipt.transaction_hash;

            let index = get_tx_index(&receipts, &tx_hash).unwrap();
            assert_eq!(index, i as u64);
        }
    }

    #[test]
    fn test_get_tx_index_invalid() {
        let receipts = vec![get_mock_receipt(), get_mock_receipt(), get_mock_receipt()];
        let random_tx_hash = H256::random();

        let index = get_tx_index(&receipts, &random_tx_hash);
        assert!(index.is_err())
    }

    #[test]
    fn test_get_tx_index_invalid_cc_id_format() {
        let cc_id = CrossChainId {
            id: "invalid_format".parse().unwrap(),
            chain: "ethereum".parse().unwrap(),
        };

        let result = get_tx_hash_from_cc_id(&cc_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_path_names_only() {
        let path = vec![SszVariableOrIndex::Name("a"), SszVariableOrIndex::Name("b")];
        assert_eq!(parse_path(&path), "a,b");
    }

    #[test]
    fn test_parse_path_indexes_only() {
        let path = vec![SszVariableOrIndex::Index(1), SszVariableOrIndex::Index(2)];
        assert_eq!(parse_path(&path), "1,2");
    }

    #[test]
    fn test_parse_path_mixed() {
        let path = vec![SszVariableOrIndex::Name("a"), SszVariableOrIndex::Index(1)];
        assert_eq!(parse_path(&path), "a,1");
    }
}
