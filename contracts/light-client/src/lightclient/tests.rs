#[cfg(test)]
pub mod tests {
    use std::fs::File;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::lightclient::helpers::test_helpers::{filter_message_variants, get_batched_data};
    use crate::lightclient::helpers::{
        calc_sync_period, compare_message_with_log, extract_logs_from_receipt_proof,
        hex_str_to_bytes, is_proof_valid, parse_log, parse_logs_from_receipt,
        verify_block_roots_proof, verify_historical_roots_proof, verify_transaction_proof,
        verify_trie_proof,
    };
    use crate::{
        lightclient::error::ConsensusError,
        lightclient::helpers::test_helpers::{get_bootstrap, get_config, get_update},
        lightclient::LightClient,
        lightclient::{self},
    };
    use cosmwasm_std::testing::mock_env;
    use cosmwasm_std::Timestamp;
    use types::alloy_primitives::Address;
    use types::consensus::Bootstrap;
    use types::execution::ReceiptLog;
    use types::lightclient::LightClientState;
    use types::proofs::{AncestryProof, UpdateVariant};
    use types::ssz_rs::{Bitvector, Merkleized, Node};
    use types::sync_committee_rs::consensus_types::Transaction;
    use types::sync_committee_rs::constants::{Bytes32, Root};
    use types::sync_committee_rs::{
        consensus_types::BeaconBlockHeader,
        constants::{BlsPublicKey, BlsSignature},
    };

    pub fn init_lightclient(bootstrap: Option<Bootstrap>) -> LightClient {
        let bootstrap = if bootstrap.is_some() {
            bootstrap.unwrap()
        } else {
            get_bootstrap()
        };
        let config = get_config();
        let mut env = mock_env();
        env.block.time = Timestamp::from_seconds(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );

        let mut client = LightClient::new(&config, None, &env);
        let res = client.bootstrap(&bootstrap);
        if let Err(e) = res {
            panic!("Error bootstrapping: {}", e);
        }

        client
    }

    #[test]
    fn test_is_proof_valid() {
        let mut update = get_update(862);

        // success
        assert!(is_proof_valid(
            &update.attested_header.beacon.state_root,
            &mut update.finalized_header.beacon,
            &update.finality_branch,
            6,
            41
        ));

        // change depth, fail
        assert!(!is_proof_valid(
            &update.attested_header.beacon.state_root,
            &mut update.finalized_header.beacon,
            &update.finality_branch,
            5,
            41
        ));

        // change index, fail
        assert!(!is_proof_valid(
            &update.attested_header.beacon.state_root,
            &mut update.finalized_header.beacon,
            &update.finality_branch,
            6,
            40
        ));

        // tamper with the state root, fail
        let mut invalid_update = update.clone();
        invalid_update.attested_header.beacon.state_root.0[0] = 0;
        assert!(!is_proof_valid(
            &invalid_update.attested_header.beacon.state_root,
            &mut invalid_update.finalized_header.beacon,
            &invalid_update.finality_branch,
            6,
            40
        ));

        // tamper with the body of the finalized header, fail
        let mut invalid_update = update.clone();
        invalid_update.finalized_header.beacon.body_root.0[0] = 0;
        assert!(!is_proof_valid(
            &invalid_update.attested_header.beacon.state_root,
            &mut invalid_update.finalized_header.beacon,
            &invalid_update.finality_branch,
            6,
            40
        ));

        // tamper with the proof, fail
        let mut invalid_update = update.clone();
        invalid_update.finality_branch[0] = Bytes32::default();
        assert!(!is_proof_valid(
            &invalid_update.attested_header.beacon.state_root,
            &mut invalid_update.finalized_header.beacon,
            &invalid_update.finality_branch,
            6,
            40
        ));
    }

    #[test]
    fn test_verify_trie_proof() {
        let verification_data = get_batched_data(false).1;
        let proofs = verification_data.target_blocks[0].transactions_proofs[0].clone();
        let receipt_proof = proofs.receipt_proof.clone();
        let transaction_proof = proofs.transaction_proof;

        let res = verify_trie_proof(
            receipt_proof.receipts_root,
            transaction_proof.transaction_index,
            receipt_proof.receipt_proof,
        );
        assert!(res.is_some());

        let receipt_result = parse_logs_from_receipt(&res.unwrap());
        // verify_trie_proof returns the leaf, a receipt with logs in this case
        assert!(receipt_result.is_ok());

        // break the receipts_root, fail
        let mut invalid_receipt_proof = proofs.receipt_proof.clone();
        invalid_receipt_proof.receipts_root.0[0] = 0;
        assert!(verify_trie_proof(
            invalid_receipt_proof.receipts_root,
            transaction_proof.transaction_index,
            invalid_receipt_proof.receipt_proof,
        )
        .is_none());

        // change the transaction index, fail
        let invalid_receipt_proof = proofs.receipt_proof.clone();
        assert!(verify_trie_proof(
            invalid_receipt_proof.receipts_root,
            transaction_proof.transaction_index + 1,
            invalid_receipt_proof.receipt_proof,
        )
        .is_none());

        // change the proof, fail
        let mut invalid_receipt_proof = proofs.receipt_proof.clone();
        invalid_receipt_proof.receipt_proof[0] = vec![];
        assert!(verify_trie_proof(
            invalid_receipt_proof.receipts_root,
            transaction_proof.transaction_index,
            invalid_receipt_proof.receipt_proof,
        )
        .is_none());
    }

    #[test]
    fn test_verify_block_roots_proof() {
        let data = get_batched_data(false).1;
        let (block_roots_index, block_root_proof) = match &data.target_blocks[0].ancestry_proof {
            AncestryProof::BlockRoots {
                block_roots_index,
                block_root_proof,
            } => (block_roots_index, block_root_proof),
            AncestryProof::HistoricalRoots { .. } => {
                panic!("Unexpected.")
            }
        };
        let update = match data.update {
            UpdateVariant::Finality(update) => update,
            UpdateVariant::Optimistic(..) => {
                panic!("Unexpected")
            }
        };

        let recent_block = update.finalized_header.beacon;
        let target_block_root = data.target_blocks[0]
            .target_block
            .clone()
            .hash_tree_root()
            .unwrap();

        assert!(verify_block_roots_proof(
            &block_roots_index,
            &block_root_proof,
            &target_block_root,
            &recent_block.state_root,
        )
        .is_ok());

        // change block roots index, fail
        assert!(verify_block_roots_proof(
            &(block_roots_index + 1),
            &block_root_proof,
            &target_block_root,
            &recent_block.state_root,
        )
        .is_err());

        // change block roots proof, fail
        let mut invalid_block_root_proof = block_root_proof.clone();
        invalid_block_root_proof[0] = Node::default();
        assert!(verify_block_roots_proof(
            &block_roots_index,
            &invalid_block_root_proof,
            &target_block_root,
            &recent_block.state_root,
        )
        .is_err());

        // change target block, fail
        assert!(verify_block_roots_proof(
            &block_roots_index,
            &block_root_proof,
            &Node::default(),
            &recent_block.state_root,
        )
        .is_err());

        // change recent block state_root, fail
        assert!(verify_block_roots_proof(
            &block_roots_index,
            &block_root_proof,
            &target_block_root,
            &Node::default(),
        )
        .is_err());
    }

    #[test]
    fn test_verify_historical_roots_proof() {
        let verification_data = get_batched_data(true).1;
        let (
            block_root_proof,
            block_summary_root,
            block_summary_root_proof,
            block_summary_root_gindex,
        ) = match &verification_data.target_blocks[0].ancestry_proof {
            AncestryProof::BlockRoots { .. } => {
                panic!("Unexpected.")
            }
            AncestryProof::HistoricalRoots {
                block_root_proof,
                block_summary_root,
                block_summary_root_proof,
                block_summary_root_gindex,
            } => (
                block_root_proof,
                block_summary_root,
                block_summary_root_proof,
                block_summary_root_gindex,
            ),
        };

        let update = match verification_data.update {
            UpdateVariant::Finality(update) => update,
            UpdateVariant::Optimistic(..) => {
                panic!("Unexpected")
            }
        };

        let recent_block = update.finalized_header.beacon;
        let target_block = verification_data.target_blocks[0].target_block.clone();

        assert!(verify_historical_roots_proof(
            &block_root_proof,
            &block_summary_root_proof,
            &block_summary_root,
            &block_summary_root_gindex,
            &target_block,
            &recent_block.state_root
        )
        .is_ok());

        // change block roots proof, fail
        let mut invalid_proof = block_root_proof.clone();
        invalid_proof[0] = Node::default();
        assert!(verify_historical_roots_proof(
            &invalid_proof,
            &block_summary_root_proof,
            &block_summary_root,
            &block_summary_root_gindex,
            &target_block,
            &recent_block.state_root
        )
        .is_err());

        // change the block_summary_root_proof, fail
        let mut invalid_proof = block_summary_root_proof.clone();
        invalid_proof[0] = Node::default();
        assert!(verify_historical_roots_proof(
            &block_root_proof,
            &invalid_proof,
            &block_summary_root,
            &block_summary_root_gindex,
            &target_block,
            &recent_block.state_root
        )
        .is_err());

        // change the block_summary_root, fail
        assert!(verify_historical_roots_proof(
            &block_root_proof,
            &block_summary_root_proof,
            &Root::default(),
            &block_summary_root_gindex,
            &target_block,
            &recent_block.state_root
        )
        .is_err());

        // change the block_summary_root_gindex, fail
        assert!(verify_historical_roots_proof(
            &block_root_proof,
            &block_summary_root_proof,
            &block_summary_root,
            &(block_summary_root_gindex + 1),
            &target_block,
            &recent_block.state_root
        )
        .is_err());

        // change the target_block, fail
        assert!(verify_historical_roots_proof(
            &block_root_proof,
            &block_summary_root_proof,
            &block_summary_root,
            &block_summary_root_gindex,
            &BeaconBlockHeader::default(),
            &recent_block.state_root
        )
        .is_err());

        // change the state_root, fail
        assert!(verify_historical_roots_proof(
            &block_root_proof,
            &block_summary_root_proof,
            &block_summary_root,
            &(block_summary_root_gindex + 1),
            &target_block,
            &Root::default()
        )
        .is_err());
    }

    #[test]
    fn test_parse_logs_from_receipt() {
        let verification_data = get_batched_data(false).1;
        let proofs = verification_data.target_blocks[0].transactions_proofs[0].clone();
        let mut receipt = verify_trie_proof(
            proofs.receipt_proof.receipts_root,
            proofs.transaction_proof.transaction_index,
            proofs.receipt_proof.receipt_proof.clone(),
        )
        .unwrap();

        let logs_result = parse_logs_from_receipt(&receipt);
        assert!(logs_result.is_ok());

        let logs = logs_result.unwrap().0;
        let first_log = logs.get(0).unwrap();
        let expected_address: [u8; 20] = vec![
            160, 184, 105, 145, 198, 33, 139, 54, 193, 209, 157, 74, 46, 158, 176, 206, 54, 6, 235,
            72,
        ]
        .try_into()
        .unwrap();
        let expected_topics: Vec<[u8; 32]> = vec![
            vec![
                221, 242, 82, 173, 27, 226, 200, 155, 105, 194, 176, 104, 252, 55, 141, 170, 149,
                43, 167, 241, 99, 196, 161, 22, 40, 245, 90, 77, 245, 35, 179, 239,
            ]
            .try_into()
            .unwrap(),
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 136, 230, 160, 194, 221, 210, 111, 238, 182,
                79, 3, 154, 44, 65, 41, 111, 203, 63, 86, 64,
            ]
            .try_into()
            .unwrap(),
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 79, 211, 156, 158, 21, 30, 80, 88, 7, 121, 189,
                4, 177, 247, 236, 195, 16, 7, 159, 211,
            ]
            .try_into()
            .unwrap(),
        ];
        let expected_data: Vec<u8> = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
            198, 78, 221, 99,
        ];

        assert_eq!(first_log.address, expected_address);
        assert_eq!(first_log.topics, expected_topics);
        assert_eq!(first_log.data, expected_data);

        let logs_result = extract_logs_from_receipt_proof(
            &proofs.receipt_proof,
            proofs.transaction_proof.transaction_index,
            &verification_data.target_blocks[0]
                .target_block
                .clone()
                .hash_tree_root()
                .unwrap(),
        );
        let logs = logs_result.unwrap().0;
        let first_log = logs.get(0).unwrap();

        assert_eq!(first_log.address, expected_address);
        assert_eq!(first_log.topics, expected_topics);
        assert_eq!(first_log.data, expected_data);

        // providing an empty arrary should return error
        assert!(parse_logs_from_receipt(&vec![]).is_err());

        // providing invalid receipt should return error
        receipt[0] = 0;
        receipt[1] = 0;
        receipt[2] = 0;
        assert!(parse_logs_from_receipt(&receipt).is_err());
    }

    #[test]
    fn test_extract_logs_from_receipt_proof() {
        let verification_data = get_batched_data(false).1;
        let proofs = verification_data.target_blocks[0].transactions_proofs[0].clone();
        let target_block_root = verification_data.target_blocks[0]
            .target_block
            .clone()
            .hash_tree_root()
            .unwrap();

        assert!(extract_logs_from_receipt_proof(
            &proofs.receipt_proof,
            proofs.transaction_proof.transaction_index,
            &target_block_root,
        )
        .is_ok());

        // change the receipt proof, fail
        let mut proof = proofs.receipt_proof.clone();
        proof.receipts_root = Root::default();
        assert!(extract_logs_from_receipt_proof(
            &proofs.receipt_proof,
            proofs.transaction_proof.transaction_index,
            &Root::default()
        )
        .is_err());

        let mut proof = proofs.receipt_proof.clone();
        proof.receipt_proof[0] = vec![];
        assert!(extract_logs_from_receipt_proof(
            &proofs.receipt_proof,
            proofs.transaction_proof.transaction_index,
            &Root::default()
        )
        .is_err());

        // change transaction index, fail
        assert!(extract_logs_from_receipt_proof(
            &proofs.receipt_proof,
            proofs.transaction_proof.transaction_index + 1,
            &target_block_root,
        )
        .is_err());

        // change the target_block root, fail
        assert!(extract_logs_from_receipt_proof(
            &proofs.receipt_proof,
            proofs.transaction_proof.transaction_index,
            &Root::default()
        )
        .is_err());
    }

    #[test]
    fn test_verify_transaction_proof() {
        let verification_data = get_batched_data(false).1;
        let transaction_proof = verification_data.target_blocks[0].transactions_proofs[0]
            .transaction_proof
            .clone();
        let target_block_root = &verification_data.target_blocks[0]
            .target_block
            .clone()
            .hash_tree_root()
            .unwrap();

        assert!(verify_transaction_proof(&transaction_proof, &target_block_root).is_ok());

        // change the transaction bytecode, fail
        let mut invalid_proof = transaction_proof.clone();
        invalid_proof.transaction = Transaction::default();
        assert!(verify_transaction_proof(&invalid_proof, &target_block_root).is_err());

        // change the transaction proof, fail
        let mut invalid_proof = transaction_proof.clone();
        invalid_proof.transaction_proof[0] = Node::default();
        assert!(verify_transaction_proof(&invalid_proof, &target_block_root).is_err());

        // change the transaction gindex, fail
        let mut invalid_proof = transaction_proof.clone();
        invalid_proof.transaction_gindex = invalid_proof.transaction_gindex + 1;
        assert!(verify_transaction_proof(&invalid_proof, &target_block_root).is_err());
    }

    #[test]
    fn test_compare_message_with_log() {
        let verification_data = get_batched_data(false).1;
        let transaction_proofs = verification_data.target_blocks[0].transactions_proofs[0].clone();
        let message = filter_message_variants(&transaction_proofs)[0].clone();
        let receipt_proof = transaction_proofs.receipt_proof;
        let transaction_proof = transaction_proofs.transaction_proof;

        let log_index_str = message.cc_id.id.split(':').nth(1).unwrap();
        let log_index: usize = log_index_str.parse().unwrap();
        let logs = extract_logs_from_receipt_proof(
            &receipt_proof,
            transaction_proof.transaction_index,
            &verification_data.target_blocks[0]
                .target_block
                .clone()
                .hash_tree_root()
                .unwrap(),
        )
        .unwrap();
        let log = logs.0[log_index].clone();

        assert!(compare_message_with_log(&message, &log, &transaction_proof.transaction).is_ok());

        // test source address check
        let mut modified_log = log.clone();
        // TODO: don't hardcode
        assert_eq!(
            modified_log.address,
            hex::decode("4f4495243837681061c4743b74b3eedf548d56a5")
                .unwrap()
                .as_slice()
        );
        assert!(
            compare_message_with_log(&message, &modified_log, &transaction_proof.transaction)
                .is_ok()
        );
        modified_log.address = Address::ZERO.to_vec().try_into().unwrap();
        assert!(
            compare_message_with_log(&message, &modified_log, &transaction_proof.transaction)
                .is_err()
        );

        // test transaction hash check
        let mut modified_message = message.clone();
        assert_eq!(
            modified_message.cc_id.id.split(':').next().unwrap(),
            "0xc3f20082fe6416efefcec8148c91ce28cd79a026d2062076f67f48a7095eabb9"
        );
        assert!(
            compare_message_with_log(&modified_message, &log, &transaction_proof.transaction)
                .is_ok()
        );
        modified_message.cc_id.id = String::from("foo:bar").try_into().unwrap();
        assert!(
            compare_message_with_log(&modified_message, &log, &transaction_proof.transaction)
                .is_err()
        );
        modified_message.cc_id.id = String::from("0x1234567:bar").try_into().unwrap();
        assert!(
            compare_message_with_log(&modified_message, &log, &transaction_proof.transaction)
                .is_err()
        );

        // test source_address check
        let mut modified_message = message.clone();
        assert_eq!(
            modified_message.source_address.to_string().to_lowercase(),
            "0xce16f69375520ab01377ce7b88f5ba8c48f8d666"
        );
        assert!(
            compare_message_with_log(&modified_message, &log, &transaction_proof.transaction)
                .is_ok()
        );
        modified_message.source_address = Address::ZERO.to_string().try_into().unwrap();
        assert!(
            compare_message_with_log(&modified_message, &log, &transaction_proof.transaction)
                .is_err()
        );

        // test destination_chain check
        let mut modified_message = message.clone();
        assert_eq!(
            modified_message
                .destination_chain
                .to_string()
                .to_lowercase(),
            "polygon"
        );
        assert!(
            compare_message_with_log(&modified_message, &log, &transaction_proof.transaction)
                .is_ok()
        );
        modified_message.destination_chain = String::from("none").try_into().unwrap();
        assert!(
            compare_message_with_log(&modified_message, &log, &transaction_proof.transaction)
                .is_err()
        );

        // test destination_address check
        let mut modified_message = message.clone();
        assert_eq!(
            modified_message.destination_address.to_string(),
            "0xce16F69375520ab01377ce7B88f5BA8C48F8D666"
        );
        assert!(
            compare_message_with_log(&modified_message, &log, &transaction_proof.transaction)
                .is_ok()
        );
        modified_message.destination_address = Address::ZERO.to_string().try_into().unwrap();
        assert!(
            compare_message_with_log(&modified_message, &log, &transaction_proof.transaction)
                .is_err()
        );

        // test payload_hash check
        let mut modified_message = message.clone();
        assert_eq!(
            hex::encode(modified_message.payload_hash),
            "51217189ef268163d2f8d62d908f0337e978c554f6978b4d494ff24310c6abd7"
        );
        assert!(
            compare_message_with_log(&modified_message, &log, &transaction_proof.transaction)
                .is_ok()
        );
        modified_message.payload_hash = Default::default();
        assert!(
            compare_message_with_log(&modified_message, &log, &transaction_proof.transaction)
                .is_err()
        );

        // failure on invalid log
        let log = ReceiptLog::default();
        assert!(compare_message_with_log(&message, &log, &transaction_proof.transaction).is_err());
    }

    #[test]
    fn test_verify_parse_log() {
        let file = File::open("testdata/receipt_log.json").unwrap();
        let log: ReceiptLog = serde_json::from_reader(file).unwrap();

        let parsing_result = parse_log(&log);
        assert!(parsing_result.is_ok());
        let event = parsing_result.unwrap();
        assert_eq!(
            event.source_address.unwrap().to_string().to_lowercase(),
            "0xce16f69375520ab01377ce7b88f5ba8c48f8d666"
        );
        assert_eq!(
            event.destination_chain.unwrap().to_string().to_lowercase(),
            "fantom"
        );
        assert_eq!(
            event
                .destination_address
                .unwrap()
                .to_string()
                .to_lowercase(),
            "0xce16f69375520ab01377ce7b88f5ba8c48f8d666"
        );
        assert_eq!(
            event.payload_hash.unwrap(),
            [
                68, 249, 93, 245, 6, 157, 169, 86, 138, 243, 82, 53, 145, 70, 138, 171, 153, 223,
                14, 249, 200, 50, 140, 182, 107, 223, 224, 230, 18, 217, 208, 55
            ]
        );

        // fails to decode without topic 0 (function signature)
        let mut broken_log = log.clone();
        broken_log.topics.remove(0);
        assert!(parse_log(&broken_log).is_err());

        // fails to decode with malformed topics
        let mut broken_log = log.clone();
        broken_log.topics.remove(broken_log.topics.len() - 1);
        assert!(parse_log(&broken_log).is_err());
        broken_log.topics = vec![];
        assert!(parse_log(&broken_log).is_err());

        // fails to decode with malformed data
        let mut broken_log = log.clone();
        broken_log.data = vec![1, 2, 3];
        assert!(parse_log(&broken_log).is_err());
    }

    #[test]
    fn test_hex_str_to_bytes_with_prefix() {
        let mut hex_str = "0x1a2b3c";
        let mut expected_bytes = vec![0x1a, 0x2b, 0x3c];
        let mut result =
            hex_str_to_bytes(hex_str).expect("Failed to convert hex string with prefix");
        assert_eq!(
            result, expected_bytes,
            "Bytes do not match expected output for prefixed hex string"
        );

        hex_str = "1a2b3c";
        expected_bytes = vec![0x1a, 0x2b, 0x3c];
        result = hex_str_to_bytes(hex_str).expect("Failed to convert hex string without prefix");
        assert_eq!(
            result, expected_bytes,
            "Bytes do not match expected output for non-prefixed hex string"
        );

        let invalid_hex_str = "zzz";
        let result = hex_str_to_bytes(invalid_hex_str);
        assert!(result.is_err(), "Expected an error for invalid hex string");

        let empty_str = "";
        let result = hex_str_to_bytes(empty_str).expect("Failed to convert empty string");
        assert!(result.is_empty(), "Result should be empty for empty string");
    }

    #[test]
    fn test_calc_sync_period() {
        assert_eq!(calc_sync_period(8191), 0);
        assert_eq!(calc_sync_period(8192), 1);
        assert_eq!(calc_sync_period(7930324), 968);
    }

    #[test]
    fn test_verify_update_participation() {
        let lightclient = init_lightclient(None);

        let mut update = get_update(862);
        update.sync_aggregate.sync_committee_bits = Bitvector::default();

        let err = lightclient.verify_update(&update).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InsufficientParticipation.to_string()
        );
    }

    #[test]
    fn test_verify_update_time() {
        let lightclient = init_lightclient(None);

        let mut update = get_update(862);
        update.signature_slot = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 12;
        let mut err = lightclient.verify_update(&update).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidTimestamp.to_string()
        );

        update = get_update(862);
        update.signature_slot = update.attested_header.beacon.slot;
        err = lightclient.verify_update(&update).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidTimestamp.to_string()
        );

        update = get_update(862);
        update.finalized_header.beacon.slot = update.attested_header.beacon.slot + 1;
        err = lightclient.verify_update(&update).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidTimestamp.to_string()
        );
    }

    #[test]
    fn test_verify_update_period() {
        let mut lightclient = init_lightclient(None);
        // current period is 862, without a sync committee
        let mut update = get_update(863);

        let mut err = lightclient.verify_update(&update).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidPeriod.to_string()
        );

        // properly sync with period 862, store sync committee
        update = get_update(862);
        lightclient.apply_update(&update).unwrap();

        // update was applied
        assert!(lightclient.state.next_sync_committee.is_some());

        // update period > current period + 1
        update = get_update(864);
        err = lightclient.verify_update(&update).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidPeriod.to_string()
        );
    }

    #[test]
    fn test_verify_update_relevance() {
        let mut lightclient = init_lightclient(None);
        let mut update = get_update(862);
        lightclient.apply_update(&update).unwrap();

        update.attested_header.beacon.slot = lightclient.state.update_slot;
        update.finalized_header.beacon.slot = lightclient.state.update_slot;
        assert!(lightclient.state.next_sync_committee.is_some());
        let mut err = lightclient.verify_update(&update).unwrap_err();
        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::NotRelevant.to_string()
        );

        update = get_update(862);
        update.attested_header.beacon.slot = lightclient.state.update_slot - (256 * 32);
        update.finalized_header.beacon.slot = lightclient.state.update_slot - (256 * 32) - 1; // subtracting 1 for a regression bug
        lightclient.state.next_sync_committee = None;
        err = lightclient.verify_update(&update).unwrap_err();
        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::NotRelevant.to_string()
        );
    }

    #[test]
    fn test_verify_update_finality_proof() {
        let lightclient = init_lightclient(None);
        let mut update = get_update(862);

        update.finality_branch = vec![];
        let mut err = lightclient.verify_update(&update).unwrap_err();
        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidFinalityProof.to_string()
        );

        update = get_update(862);
        update.finalized_header.beacon.state_root = Node::default();
        err = lightclient.verify_update(&update).unwrap_err();
        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidFinalityProof.to_string()
        );
    }

    #[test]
    fn test_verify_update_invalid_committee() {
        let lightclient = init_lightclient(None);

        let mut update = get_update(862);
        update.next_sync_committee.public_keys[0] = BlsPublicKey::default();
        let err = lightclient.verify_update(&update).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidNextSyncCommitteeProof.to_string()
        );
    }

    #[test]
    fn test_verify_update_invalid_sig() {
        let lightclient = init_lightclient(None);

        let mut update = get_update(862);
        update.sync_aggregate.sync_committee_signature = BlsSignature::default();

        let err = lightclient.verify_update(&update).err().unwrap();
        assert_eq!(
            err.to_string(),
            ConsensusError::InvalidSignature.to_string()
        );
    }

    #[test]
    fn test_verify_update() {
        let lightclient = init_lightclient(None);

        let update = get_update(862);
        let res = lightclient.verify_update(&update);
        assert!(res.is_ok());
    }

    #[test]
    fn test_bootstrap_state() {
        let lightclient = init_lightclient(None);
        let bootstrap = get_bootstrap();

        assert_eq!(
            lightclient.state,
            LightClientState {
                update_slot: bootstrap.header.beacon.slot,
                current_sync_committee: bootstrap.current_sync_committee,
                next_sync_committee: None,
            }
        );
    }

    #[test]
    fn test_apply_first_update() {
        let mut lightclient = init_lightclient(None);
        let update = get_update(862);
        let bootstrap = get_bootstrap();

        let res = lightclient.apply_update(&update);
        assert!(res.is_ok());
        assert_eq!(
            lightclient.state.update_slot, update.finalized_header.beacon.slot,
            "update_slot should be set after applying update"
        );
        assert_eq!(
            lightclient.state.current_sync_committee, bootstrap.current_sync_committee,
            "current_sync_committee should be unchanged"
        );
        assert_eq!(
            lightclient.state.next_sync_committee.unwrap(),
            update.next_sync_committee,
            "next_sync_committee should be set after applying update"
        );
    }

    #[test]
    fn test_apply_next_period_update() {
        let mut lightclient = init_lightclient(None);

        assert!(lightclient.apply_update(&get_update(862)).is_ok());
        let state_before_update = lightclient.state.clone();

        let update = get_update(863);
        assert!(lightclient.apply_update(&update).is_ok());

        assert_eq!(
            lightclient.state.update_slot, update.finalized_header.beacon.slot,
            "update_slot should be set after applying update"
        );
        assert_eq!(
            lightclient.state.current_sync_committee,
            state_before_update.next_sync_committee.unwrap(),
            "current_sync_committee was updated with previous next_sync_committee"
        );
        assert_eq!(
            lightclient.state.next_sync_committee.clone().unwrap(),
            update.next_sync_committee,
            "next_sync_committee was updated"
        );
    }

    #[test]
    #[ignore]
    // TODO: need two updates from the same period
    fn test_apply_same_period_update() {
        let mut lightclient = init_lightclient(None);
        let mut update = get_update(862);

        assert!(lightclient.apply_update(&update).is_ok());
        let state_before_update = lightclient.state.clone();
        // apply again
        assert!(lightclient.apply_update(&update).is_ok());

        assert_ne!(
            lightclient.state.update_slot,
            state_before_update.update_slot,
        );
        assert_eq!(
            lightclient.state.update_slot, update.finalized_header.beacon.slot,
            "update_slot should be set after applying update"
        );
        assert_eq!(
            lightclient.state.current_sync_committee, state_before_update.current_sync_committee,
            "current_sync_committee should be unchanged"
        );
        assert_eq!(
            lightclient.state.next_sync_committee, state_before_update.next_sync_committee,
            "next_sync_committee should be unchanged"
        );
    }
}
