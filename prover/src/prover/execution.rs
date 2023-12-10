use cita_trie::Trie;
use consensus_types::lightclient::CrossChainId;
use ethers::{
    types::{Block, Transaction, TransactionReceipt, H256},
    utils::rlp::encode,
};
use eyre::{anyhow, Result};

pub trait ExecutionProverAPI {
    fn generate_receipt_proof(
        &self,
        block: &Block<Transaction>,
        receipts: &[TransactionReceipt],
        index: u64,
    ) -> Result<Vec<Vec<u8>>>;
    fn get_tx_index(&self, receipts: &[TransactionReceipt], cc_id: &CrossChainId) -> Result<u64>;
}

pub struct ExecutionProver;

impl ExecutionProver {
    pub fn new() -> Self {
        ExecutionProver {}
    }
}

impl ExecutionProverAPI for ExecutionProver {
    /**
     * Generates an MPT proof from a receipt to the receipts_root.
     */
    fn generate_receipt_proof(
        &self,
        block: &Block<Transaction>,
        receipts: &[TransactionReceipt],
        index: u64,
    ) -> Result<Vec<Vec<u8>>> {
        let mut trie = utils::generate_trie(receipts.to_owned(), utils::encode_receipt);
        let trie_root = trie.root().unwrap();

        // Reality check
        if block.receipts_root != H256::from_slice(&trie_root[0..32]) {
            return Err(anyhow!(
                "Invalid receipts root from trie generation: {}",
                block.number.unwrap()
            ));
        }

        let receipt_index: cosmos_sdk_proto::prost::bytes::BytesMut = encode(&index);
        let proof = trie
            .get_proof(receipt_index.to_vec().as_slice())
            .map_err(|e| anyhow!("Failed to generate proof: {:?}", e))?;

        Ok(proof)
    }

    fn get_tx_index(&self, receipts: &[TransactionReceipt], cc_id: &CrossChainId) -> Result<u64> {
        let tx_hash = cc_id
            .id
            .split_once(':')
            .ok_or_else(|| anyhow!("Invalid CrossChainId format. {:?}", cc_id))?
            .0;

        let tx_index = receipts
            .iter()
            .position(|r| format!("0x{:x}", r.transaction_hash) == tx_hash);

        match tx_index {
            Some(index) => Ok(index as u64),
            None => Err(anyhow!("Transaction not found in receipts. {:?}", cc_id)),
        }
    }
}

mod utils {
    use cita_trie::{MemoryDB, PatriciaTrie, Trie};
    use ethers::types::TransactionReceipt;
    use ethers::utils::rlp::{encode, Encodable};
    use hasher::HasherKeccak;
    use std::sync::Arc;

    pub(crate) fn generate_trie<T>(
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

    pub(crate) fn encode_receipt(receipt: &TransactionReceipt) -> Vec<u8> {
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
}

#[cfg(test)]
mod tests {
    use crate::prover::{
        execution::{ExecutionProver, ExecutionProverAPI},
        mocks::mock_execution_rpc::MockExecutionRPC,
    };
    use cita_trie::{MemoryDB, PatriciaTrie, Trie};
    use consensus_types::proofs::CrossChainId;
    use eth::execution::EthExecutionAPI;
    use ethers::{
        types::{TransactionReceipt, H256},
        utils::rlp::encode,
    };
    use eyre::{anyhow, Result};
    use hasher::HasherKeccak;
    use std::sync::Arc;
    use sync_committee_rs::constants::Root;
    use tokio::test as tokio_test;

    fn verify_trie_proof(root: Root, key: u64, proof_bytes: Vec<Vec<u8>>) -> Result<Vec<u8>> {
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

    fn get_mock_receipt() -> TransactionReceipt {
        let mut receipt = TransactionReceipt::default();
        receipt.transaction_hash = H256::random();
        receipt
    }

    #[tokio_test]
    async fn test_receipts_proof_valid() {
        let execution_rpc = MockExecutionRPC::new();
        let execution_block = execution_rpc
            .get_block_with_txs(18615160)
            .await
            .unwrap()
            .unwrap();
        let receipts = execution_rpc.get_block_receipts(18615160).await.unwrap();

        let execution_prover = ExecutionProver::new();
        let proof = execution_prover
            .generate_receipt_proof(&execution_block, &receipts, 1)
            .unwrap();

        let bytes: Result<[u8; 32], _> = execution_block.receipts_root[0..32].try_into();
        let root = Root::from_bytes(bytes.unwrap());

        let valid_proof = verify_trie_proof(root, 1, proof.clone());

        assert!(valid_proof.is_ok());
    }

    #[tokio_test]
    async fn test_receipts_proof_invalid() {
        let execution_rpc = MockExecutionRPC::new();
        let execution_block = execution_rpc
            .get_block_with_txs(18615160)
            .await
            .unwrap()
            .unwrap();
        let receipts = execution_rpc.get_block_receipts(18615160).await.unwrap();

        let execution_prover = ExecutionProver::new();
        let proof = execution_prover
            .generate_receipt_proof(&execution_block, &receipts, 1)
            .unwrap();

        let bytes: Result<[u8; 32], _> = execution_block.receipts_root[0..32].try_into();
        let root = Root::from_bytes(bytes.unwrap());

        let invalid_proof = verify_trie_proof(root, 2, proof);

        assert!(invalid_proof.is_err());
    }

    #[test]
    fn test_get_tx_index_valid() {
        let receipts = vec![get_mock_receipt(), get_mock_receipt(), get_mock_receipt()];
        let execution_prover = ExecutionProver::new();

        for (i, receipt) in receipts.iter().enumerate() {
            let cc_id = CrossChainId {
                id: format!("0x{:x}:15", receipt.transaction_hash)
                    .parse()
                    .unwrap(),
                chain: "ethereum".parse().unwrap(),
            };

            let index = execution_prover.get_tx_index(&receipts, &cc_id).unwrap();
            assert_eq!(index, i as u64);
        }
    }

    #[test]
    fn test_get_tx_index_invalid() {
        let receipts = vec![get_mock_receipt(), get_mock_receipt(), get_mock_receipt()];
        let random_tx_hash = H256::random();
        let execution_prover = ExecutionProver::new();

        let cc_id = CrossChainId {
            id: format!("0x{:x}:15", random_tx_hash).parse().unwrap(),
            chain: "ethereum".parse().unwrap(),
        };
        let index = execution_prover.get_tx_index(&receipts, &cc_id);
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

        let result = execution_prover.get_tx_index(&receipts, &cc_id);
        assert!(result.is_err());
    }
}
