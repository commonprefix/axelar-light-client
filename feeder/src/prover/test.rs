#[cfg(test)]

mod tests {
    use cita_trie::{MemoryDB, PatriciaTrie, Trie};
    use consensus_types::consensus::BeaconBlockAlias;
    use ethers::{
        types::{Block, Transaction, TransactionReceipt},
        utils::rlp::encode,
    };
    use hasher::HasherKeccak;
    use ssz_rs::{GeneralizedIndex, Merkleized};
    use std::{fs::File, sync::Arc};
    use sync_committee_rs::constants::Root;

    // Execution payload to beacon block body
    const EXECUTION_PAYLOAD_G_INDEX: usize = 25;

    // Generalized indices to execution payload
    const RECEIPTS_ROOT_G_INDEX: usize = 19;
    const TRANSACTIONS_G_INDEX: usize = 29;

    use crate::{
        eth::{
            consensus::ConsensusRPC,
            constants::{CONSENSUS_RPC, EXECUTION_RPC},
            execution::ExecutionRPC,
        },
        prover::{
            consensus::{
                generate_exec_payload_branch, generate_receipts_branch,
                generate_transactions_branch,
            },
            execution::{generate_receipt_proof, generate_transaction_proof},
            Prover,
        },
    };

    pub fn get_beacon_block() -> BeaconBlockAlias {
        let file = File::open("./src/prover/testdata/beacon_block.json").unwrap();
        serde_json::from_reader(file).unwrap()
    }

    pub fn get_execution_block() -> Block<Transaction> {
        let file = File::open("./src/prover/testdata/execution_block.json").unwrap();
        serde_json::from_reader(file).unwrap()
    }

    pub fn get_receipts() -> Vec<TransactionReceipt> {
        let file = File::open("./src/prover/testdata/receipts.json").unwrap();
        serde_json::from_reader(file).unwrap()
    }

    pub fn verify_trie_proof(root: Root, key: u64, proof_bytes: Vec<Vec<u8>>) -> Option<Vec<u8>> {
        let memdb = Arc::new(MemoryDB::new(true));
        let hasher = Arc::new(HasherKeccak::new());

        let trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));
        trie.verify_proof(
            root.as_bytes(),
            encode(&key).to_vec().as_slice(),
            proof_bytes,
        )
        .unwrap()
    }

    pub fn get_prover() -> Prover {
        let execution = ExecutionRPC::new(EXECUTION_RPC);
        let consensus = ConsensusRPC::new(CONSENSUS_RPC);
        Prover::new(execution, consensus)
    }

    #[test]
    fn test_execution_payload_branch() {
        let mut beacon_block = get_beacon_block();
        let proof = generate_exec_payload_branch(&mut beacon_block).unwrap();

        let is_proof_valid = ssz_rs::verify_merkle_proof(
            &beacon_block
                .body
                .execution_payload
                .hash_tree_root()
                .unwrap(),
            proof.as_slice(),
            &GeneralizedIndex(EXECUTION_PAYLOAD_G_INDEX),
            &beacon_block.body.hash_tree_root().unwrap(),
        );

        assert!(is_proof_valid);
    }

    #[test]
    fn test_receipts_branch() {
        let mut beacon_block = get_beacon_block();
        let proof = generate_receipts_branch(&mut beacon_block).unwrap();

        let is_proof_valid = ssz_rs::verify_merkle_proof(
            &beacon_block
                .body
                .execution_payload
                .receipts_root
                .hash_tree_root()
                .unwrap(),
            proof.as_slice(),
            &GeneralizedIndex(RECEIPTS_ROOT_G_INDEX),
            &beacon_block
                .body
                .execution_payload
                .hash_tree_root()
                .unwrap(),
        );

        assert!(is_proof_valid);
    }

    #[test]
    fn test_transactions_branch() {
        let mut beacon_block = get_beacon_block();
        let proof = generate_transactions_branch(&mut beacon_block).unwrap();

        let is_proof_valid = ssz_rs::verify_merkle_proof(
            &beacon_block
                .body
                .execution_payload
                .transactions
                .hash_tree_root()
                .unwrap(),
            proof.as_slice(),
            &GeneralizedIndex(TRANSACTIONS_G_INDEX),
            &beacon_block
                .body
                .execution_payload
                .hash_tree_root()
                .unwrap(),
        );

        assert!(is_proof_valid);
    }

    #[test]
    fn test_transactions_proof() {
        let mut execution_block = get_execution_block();
        let _prover = get_prover();

        let proof = generate_transaction_proof(&mut execution_block, 1).unwrap();
        let bytes: Result<[u8; 32], _> = execution_block.transactions_root[0..32].try_into();
        let root = Root::from_bytes(bytes.unwrap());

        let valid_proof = verify_trie_proof(root, 1, proof.clone());
        let invalid_proof = verify_trie_proof(root, 2, proof);

        assert!(valid_proof.is_some());
        assert!(invalid_proof.is_none())
    }

    #[test]
    fn test_receipts_proof() {
        let mut execution_block = get_execution_block();
        let receipts = &get_receipts();

        let proof = generate_receipt_proof(&mut execution_block, receipts, 1).unwrap();
        let bytes: Result<[u8; 32], _> = execution_block.receipts_root[0..32].try_into();
        let root = Root::from_bytes(bytes.unwrap());

        let valid_proof = verify_trie_proof(root, 1, proof.clone());
        let invalid_proof = verify_trie_proof(root, 2, proof);

        assert!(valid_proof.is_some());
        assert!(invalid_proof.is_none())
    }
}
