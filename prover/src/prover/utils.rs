use std::str::FromStr;

use consensus_types::proofs::CrossChainId;
use ethers::types::{TransactionReceipt, H256};
use eyre::{Result, anyhow};
use ssz_rs::SszVariableOrIndex;

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

mod tests {
    use consensus_types::proofs::CrossChainId;
    use ethers::types::{TransactionReceipt, H256};
    use crate::prover::{utils::{get_tx_index, get_tx_hash_from_cc_id}, execution::ExecutionProver};

    fn get_mock_receipt() -> TransactionReceipt {
        let mut receipt = TransactionReceipt::default();
        receipt.transaction_hash = H256::random();
        receipt

    }

    #[test]
    fn test_get_tx_index_valid() {
        let receipts = vec![get_mock_receipt(), get_mock_receipt(), get_mock_receipt()];
        let execution_prover = ExecutionProver::new();

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
        let receipts = vec![get_mock_receipt()];
        let execution_prover = ExecutionProver::new();

        let cc_id = CrossChainId {
            id: "invalid_format".parse().unwrap(),
            chain: "ethereum".parse().unwrap(),
        };

        let result = get_tx_hash_from_cc_id(&cc_id);
        assert!(result.is_err());
    }
}