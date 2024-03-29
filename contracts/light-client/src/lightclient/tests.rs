#[cfg(test)]
pub mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::lightclient::helpers::test_helpers::{
        filter_message_variants, get_batched_data, get_legacy_verification_data,
        mock_contractcall_message_with_log, mock_workerset_message_with_log,
    };
    use crate::lightclient::helpers::{
        calc_sync_period, compare_content_with_log, extract_logs_from_receipt_proof,
        hex_str_to_bytes, is_proof_valid, parse_log, parse_logs_from_receipt, parse_message_id,
        verify_block_roots_proof, verify_historical_roots_proof, verify_transaction_proof,
        verify_trie_proof, Comparison,
    };
    use crate::{
        lightclient::error::ConsensusError,
        lightclient::helpers::test_helpers::{get_bootstrap, get_config, get_update},
        lightclient::LightClient,
        lightclient::{self},
    };
    use cosmwasm_std::testing::mock_env;
    use cosmwasm_std::Timestamp;
    use ethabi::{decode, ParamType};
    use types::alloy_primitives::Address;
    use types::common::ContentVariant;
    use types::consensus::{Bootstrap, OptimisticUpdate};
    use types::execution::{ContractCallBase, GatewayEvent};
    use types::lightclient::LightClientState;
    use types::proofs::{nonempty, AncestryProof, UpdateVariant};
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

        let mut client = LightClient::new(&config.chain_config, None, &env);
        let res = client.bootstrap(&bootstrap);
        if let Err(e) = res {
            panic!("Error bootstrapping: {}", e);
        }

        client
    }

    #[test]
    fn test_apply_bootstrap() {
        let config = get_config();
        let env = mock_env();
        let mut client = LightClient::new(&config.chain_config, None, &env);

        // test corrupt current committee branch
        let mut bootstrap = get_bootstrap();
        bootstrap.current_sync_committee_branch = vec![];
        assert!(client.bootstrap(&bootstrap).is_err());

        // test normal bootstrap
        let bootstrap = get_bootstrap();
        assert!(client.bootstrap(&bootstrap).is_ok());

        assert_eq!(
            client.state,
            LightClientState {
                update_slot: bootstrap.header.beacon.slot,
                current_sync_committee: bootstrap.current_sync_committee,
                next_sync_committee: None
            }
        );
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
        let verification_data = get_batched_data(false, "finality").1;
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
        invalid_receipt_proof.receipts_root = Node::default();
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
        let data = get_batched_data(false, "finality").1;
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
        let verification_data = get_batched_data(true, "finality").1;
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

        let recent_block = verification_data.update.recent_block();
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
    fn test_parse_logs_from_legacy_receipt() {
        let legacy_receipt = get_legacy_verification_data();

        let logs_result = parse_logs_from_receipt(&legacy_receipt);
        assert!(logs_result.is_ok());

        let parse_result = parse_log(&logs_result.unwrap().0[7]);
        assert!(parse_result.is_ok());

        assert_eq!(
            parse_result.unwrap(),
            GatewayEvent::ContactCall(ContractCallBase {
                source_address: Some(
                    hex::decode("481a2aae41cd34832ddcf5a79404538bb2c02bc8")
                        .unwrap()
                        .as_slice()
                        .try_into()
                        .unwrap()
                ),
                destination_chain: Some(String::from("osmosis-7")),
                destination_address: Some(String::from(
                    "osmo1zl9ztmwe2wcdvv9std8xn06mdaqaqm789rutmazfh3z869zcax4sv0ctqw"
                )),
                payload_hash: Some(
                    vec![
                        229, 110, 107, 115, 37, 22, 199, 64, 219, 239, 95, 60, 169, 125, 156, 99,
                        142, 37, 17, 70, 214, 194, 31, 64, 39, 194, 58, 132, 172, 220, 90, 201
                    ]
                    .try_into()
                    .unwrap()
                )
            })
        );
    }

    #[test]
    fn test_parse_logs_from_receipt() {
        let verification_data = get_batched_data(false, "finality").1;
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
            171, 164, 217, 147, 24, 128, 8, 246, 101, 201, 114, 215, 159, 197, 154, 178, 56, 30,
            206, 148,
        ]
        .try_into()
        .unwrap();
        let expected_topics: Vec<[u8; 32]> = vec![
            vec![
                48, 174, 108, 199, 140, 39, 230, 81, 116, 91, 242, 173, 8, 161, 29, 232, 57, 16,
                172, 30, 52, 122, 82, 247, 172, 137, 140, 15, 190, 249, 77, 174,
            ]
            .try_into()
            .unwrap(),
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 197, 90, 211, 221, 179, 134, 51, 93, 90, 243,
                56, 35, 227, 168, 69, 192, 219, 212, 69, 92,
            ]
            .try_into()
            .unwrap(),
            vec![
                235, 200, 76, 189, 117, 186, 85, 22, 191, 69, 231, 2, 74, 158, 18, 188, 60, 92,
                136, 15, 115, 227, 165, 190, 202, 126, 187, 165, 43, 40, 103, 167,
            ]
            .try_into()
            .unwrap(),
        ];
        let expected_data: Vec<u8> = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 224, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 112, 111, 108, 121, 103, 111, 110, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 116, 104,
            105, 115, 32, 105, 115, 32, 116, 104, 101, 32, 97, 100, 100, 114, 101, 115, 115, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 112, 97, 121, 108, 111, 97, 100, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
        let verification_data = get_batched_data(false, "finality").1;
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
        let verification_data = get_batched_data(false, "finality").1;
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
    fn test_compare_message_with_event() {
        let verification_data = get_batched_data(false, "finality").1;
        let transaction_proofs = verification_data.target_blocks[0].transactions_proofs[0].clone();
        let message = filter_message_variants(&transaction_proofs)[0].clone();
        let receipt_proof = transaction_proofs.receipt_proof;
        let transaction_proof = transaction_proofs.transaction_proof;

        let (_, log_index) = parse_message_id(&message.cc_id.id).unwrap();
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
        let GatewayEvent::ContactCall(event) = parse_log(&log).unwrap() else {
            panic!("Invalid event type");
        };

        assert!(message.compare_with_event(event.clone()).is_ok());

        // test source_address check
        let mut modified_message = message.clone();
        assert_eq!(
            modified_message.source_address.to_string().to_lowercase(),
            "0xc55ad3ddb386335d5af33823e3a845c0dbd4455c"
        );
        assert!(modified_message.compare_with_event(event.clone()).is_ok());
        modified_message.source_address = Address::ZERO.to_string().try_into().unwrap();
        assert!(modified_message.compare_with_event(event.clone()).is_err());

        // test destination_chain check
        let mut modified_message = message.clone();
        assert_eq!(
            modified_message
                .destination_chain
                .to_string()
                .to_lowercase(),
            "polygon"
        );
        assert!(modified_message.compare_with_event(event.clone()).is_ok());
        modified_message.destination_chain = String::from("none").try_into().unwrap();
        assert!(modified_message.compare_with_event(event.clone()).is_err());

        // test destination_address check
        let mut modified_message = message.clone();
        assert_eq!(
            modified_message.destination_address.to_string(),
            "this is the address"
        );
        assert!(modified_message.compare_with_event(event.clone()).is_ok());
        modified_message.destination_address = Address::ZERO.to_string().try_into().unwrap();
        assert!(modified_message.compare_with_event(event.clone()).is_err());

        // test payload_hash check
        let mut modified_message = message.clone();
        assert_eq!(
            hex::encode(modified_message.payload_hash),
            "ebc84cbd75ba5516bf45e7024a9e12bc3c5c880f73e3a5beca7ebba52b2867a7"
        );
        assert!(modified_message.compare_with_event(event.clone()).is_ok());
        modified_message.payload_hash = Default::default();
        assert!(modified_message.compare_with_event(event.clone()).is_err());
    }

    #[test]
    fn test_compare_workerset_message_with_event() {
        let (message, log) = mock_workerset_message_with_log();

        let GatewayEvent::OperatorshipTransferred(event) = parse_log(&log).unwrap() else {
            panic!("Invalid event type")
        };

        assert!(message.compare_with_event(event.clone()).is_ok());
        let mut modified_message = message.clone();
        modified_message.new_operators_data = String::from("");
        assert!(modified_message.compare_with_event(event.clone()).is_err());
    }

    #[test]
    fn test_compare_content_with_log() {
        let (message, contractcall_log) = mock_contractcall_message_with_log();
        let (workerset_message, operatorship_log) = mock_workerset_message_with_log();

        // assert happy path
        assert!(compare_content_with_log(
            ContentVariant::Message(message.clone()),
            &contractcall_log
        )
        .is_ok());
        assert!(compare_content_with_log(
            ContentVariant::WorkerSet(workerset_message.clone()),
            &operatorship_log
        )
        .is_ok());

        // assert failure in either of the messages
        let mut modified_message = message.clone();
        let mut modified_workerset_message = workerset_message.clone();

        modified_message.payload_hash = <[u8; 32]>::default();
        modified_workerset_message.new_operators_data = String::from("");
        assert!(compare_content_with_log(
            ContentVariant::Message(modified_message.clone()),
            &contractcall_log
        )
        .is_err());
        assert!(compare_content_with_log(
            ContentVariant::WorkerSet(modified_workerset_message.clone()),
            &operatorship_log
        )
        .is_err());
    }

    #[test]
    fn test_parse_log_contractcall() {
        let (message, log) = mock_contractcall_message_with_log();

        let parsing_result = parse_log(&log);
        assert!(parsing_result.is_ok());
        let GatewayEvent::ContactCall(event) = parsing_result.unwrap() else {
            panic!("Unexpected log")
        };
        assert_eq!(
            event.source_address.unwrap().to_string().to_lowercase(),
            message.source_address.to_string()
        );
        assert_eq!(
            event.destination_chain.unwrap().to_string().to_lowercase(),
            message.destination_chain.to_string()
        );
        assert_eq!(
            event
                .destination_address
                .unwrap()
                .to_string()
                .to_lowercase(),
            message.destination_address.to_string()
        );
        assert_eq!(event.payload_hash.unwrap(), message.payload_hash);
    }

    #[test]
    fn test_parse_log_operatorship() {
        let (_, log) = mock_workerset_message_with_log();

        let parsing_result = parse_log(&log);
        assert!(parsing_result.is_ok());
        let GatewayEvent::OperatorshipTransferred(event) = parsing_result.unwrap() else {
            panic!("Unexpected log")
        };
        assert_eq!(
            event.new_operators_data.unwrap(),
            hex::encode(
                decode(&[ParamType::Bytes], log.data.as_slice()).unwrap()[0]
                    .clone()
                    .into_bytes()
                    .unwrap()
            )
        );
    }

    #[test]
    fn test_parse_log_failure() {
        let (_, log) = mock_contractcall_message_with_log();

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
    fn test_parse_message_id() {
        let id = nonempty::String::try_from(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:123",
        )
        .unwrap();
        let result = parse_message_id(&id).unwrap();
        assert_eq!(
            result.0,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(result.1, 123);

        let id = nonempty::String::try_from("invalid_format").unwrap();
        assert!(parse_message_id(&id).is_err());

        let id = nonempty::String::try_from("0123:123").unwrap();
        assert!(parse_message_id(&id).is_err());

        let id = nonempty::String::try_from(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:abc",
        )
        .unwrap();
        assert!(parse_message_id(&id).is_err());
    }

    #[test]
    fn test_recent_block() {
        let data = get_batched_data(false, "finality").1;
        let UpdateVariant::Finality(update) = data.update.clone() else {
            panic!("Invalid update type")
        };
        let optimistic = OptimisticUpdate::from(&update);

        assert_eq!(update.finalized_header.beacon, data.update.recent_block());

        assert_eq!(
            update.attested_header.beacon,
            UpdateVariant::Optimistic(optimistic).recent_block()
        );
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
        let update = get_update(862);

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
