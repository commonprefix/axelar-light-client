use cita_trie::Trie;
use ethers::{
    core::k256::elliptic_curve::generic_array::iter,
    types::{Block, Transaction, TransactionReceipt, H256},
    utils::rlp::encode,
};
use eyre::{anyhow, Result};
use mockall::automock;

pub trait ExecutionProverAPI {
    fn generate_receipt_proof(
        &self,
        block: &Block<Transaction>,
        receipts: &[TransactionReceipt],
        index: u64,
    ) -> Result<Vec<Vec<u8>>>;
}

#[derive(Clone)]
pub struct ExecutionProver;

impl Default for ExecutionProver {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionProver {
    pub fn new() -> Self {
        ExecutionProver {}
    }
}

#[automock]
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

        let receipt_index = encode(&index);
        let proof = trie
            .get_proof(receipt_index.to_vec().as_slice())
            .map_err(|e| anyhow!("Failed to generate proof: {:?}", e))?;

        Ok(proof)
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

    use eth::execution::EthExecutionAPI;
    use ethers::utils::rlp::encode;
    use eyre::{anyhow, Result};
    use hasher::HasherKeccak;
    use std::sync::Arc;
    use sync_committee_rs::constants::Root;
    use tokio::test as tokio_test;

    fn verify_trie_proof(root: Root, key: u64, proof: Vec<Vec<u8>>) -> Result<Vec<u8>> {
        let memdb = Arc::new(MemoryDB::new(true));
        let hasher = Arc::new(HasherKeccak::new());

        let trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));
        let proof = trie.verify_proof(root.as_bytes(), encode(&key).to_vec().as_slice(), proof);

        if proof.is_err() {
            return Err(anyhow!("Invalid proof"));
        }

        match proof.unwrap() {
            Some(value) => Ok(value),
            None => Err(anyhow!("Invalid proof")),
        }
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
}
