#[cfg(test)]
pub mod test_utils {
    use cita_trie::{MemoryDB, PatriciaTrie, Trie};
    use consensus_types::sync_committee_rs::consensus_types::BeaconBlock;
    use consensus_types::sync_committee_rs::constants::Root;
    use consensus_types::{
        common::ContentVariant,
        consensus::{BeaconBlockAlias, FinalityUpdate, OptimisticUpdate},
        proofs::{CrossChainId, Message, UpdateVariant},
    };
    use ethers::{
        types::{Block, Transaction, TransactionReceipt, H256},
        utils::rlp::encode,
    };
    use eyre::{anyhow, Result};
    use hasher::HasherKeccak;
    use indexmap::IndexMap;
    use std::{fs::File, sync::Arc};

    use crate::prover::types::{BatchContentGroups, EnrichedContent};

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

    pub fn get_mock_update(
        is_optimistic: bool,
        attested_slot: u64,
        finality_slot: u64,
    ) -> UpdateVariant {
        if is_optimistic {
            let mut update = OptimisticUpdate::default();
            update.attested_header.beacon.slot = attested_slot;
            UpdateVariant::Optimistic(update)
        } else {
            let mut update = FinalityUpdate::default();
            update.finalized_header.beacon.slot = finality_slot;
            update.attested_header.beacon.slot = attested_slot;
            UpdateVariant::Finality(update)
        }
    }

    pub fn get_mock_message(slot: u64, block_number: u64, tx_hash: H256) -> EnrichedContent {
        let message = Message {
            cc_id: CrossChainId {
                chain: "ethereum".parse().unwrap(),
                id: format!("{:x}:test", tx_hash).parse().unwrap(),
            },
            source_address: "0x0000000".parse().unwrap(),
            destination_chain: "polygon".parse().unwrap(),
            destination_address: "0x0000000".parse().unwrap(),
            payload_hash: Default::default(),
        };

        EnrichedContent {
            content: ContentVariant::Message(message),
            tx_hash,
            exec_block: get_mock_exec_block_with_txs(block_number),
            beacon_block: get_mock_beacon_block(slot),
            receipts: (1..100)
                .map(|i| TransactionReceipt {
                    transaction_hash: H256::from_low_u64_be(i),
                    ..Default::default()
                })
                .collect(),
            id: "id1".to_string(),
            delivery_tag: 1
        }
    }

    /*
        Setup the following batch scenario:

        * block 1 -> tx 1 -> message 1
        * block 2 -> tx 2 -> message 2
        *   \            \
        *    \            -> message 3
        *     \
        *      --->  tx 3 -> message 4
        *
        * block 3 -> tx 4 -> message 5
    */
    pub fn get_mock_batch_message_groups() -> BatchContentGroups {
        let mut messages = vec![];
        for i in 0..6 {
            let m = get_mock_message(i, i, H256::from_low_u64_be(i));
            messages.push(m);
        }

        let mut groups: BatchContentGroups = IndexMap::new();
        let mut blockgroup1 = IndexMap::new();
        let mut blockgroup2 = IndexMap::new();
        let mut blockgroup3 = IndexMap::new();

        blockgroup1.insert(messages[1].tx_hash, vec![messages[1].clone()]);
        blockgroup2.insert(
            messages[2].tx_hash,
            vec![messages[2].clone(), messages[3].clone()],
        );
        blockgroup2.insert(messages[4].tx_hash, vec![messages[4].clone()]);
        blockgroup3.insert(messages[5].tx_hash, vec![messages[5].clone()]);

        groups.insert(1, blockgroup1);
        groups.insert(2, blockgroup2);
        groups.insert(3, blockgroup3);

        groups
    }

    pub fn get_mock_beacon_block(slot: u64) -> BeaconBlockAlias {
        let mut block = BeaconBlock {
            slot,
            ..Default::default()
        };

        for _ in 1..10 {
            block
                .body
                .execution_payload_mut()
                .transactions_mut()
                .push(consensus_types::sync_committee_rs::consensus_types::Transaction::default());
        }
        block
    }

    pub fn get_mock_exec_block(block_number: u64) -> Block<H256> {
        Block {
            number: Some(ethers::types::U64::from(block_number)),
            ..Default::default()
        }
    }

    pub fn get_mock_exec_block_with_txs(block_number: u64) -> Block<Transaction> {
        Block {
            number: Some(ethers::types::U64::from(block_number)),
            ..Default::default()
        }
    }
}
