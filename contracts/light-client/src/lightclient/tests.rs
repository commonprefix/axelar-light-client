#[cfg(test)]
pub mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::lightclient::helpers::test_helpers::{
        get_verification_data_with_block_roots, get_verification_data_with_historical_roots,
    };
    use crate::lightclient::helpers::{
        extract_logs_from_receipt_proof, is_proof_valid, parse_logs_from_receipt,
        verify_block_roots_proof, verify_historical_roots_proof, verify_message,
        verify_transaction_proof, verify_trie_proof,
    };
    use crate::{
        lightclient::error::ConsensusError,
        lightclient::LightClient,
        lightclient::{self},
        lightclient::{
            helpers::test_helpers::{get_bootstrap, get_config, get_update},
            Verification,
        },
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
        let verification_data = get_verification_data_with_block_roots();
        let proofs = verification_data.1.proofs;
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
        let mut verification_data = get_verification_data_with_block_roots();
        let (block_roots_index, block_root_proof) = match verification_data.1.proofs.ancestry_proof
        {
            AncestryProof::BlockRoots {
                block_roots_index,
                block_root_proof,
            } => (block_roots_index, block_root_proof),
            AncestryProof::HistoricalRoots { .. } => {
                panic!("Unexpected.")
            }
        };
        // TODO: improve this
        let update = match verification_data.1.proofs.update {
            UpdateVariant::Finality(update) => update,
            UpdateVariant::Optimistic(..) => {
                panic!("Unexpected")
            }
        };

        let recent_block = update.finalized_header.beacon;
        let target_block_root = verification_data
            .1
            .proofs
            .target_block
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
        let verification_data = get_verification_data_with_historical_roots();
        let (
            block_root_proof,
            block_summary_root,
            block_summary_root_proof,
            block_summary_root_gindex,
        ) = match verification_data.1.proofs.ancestry_proof {
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

        let update = match verification_data.1.proofs.update {
            UpdateVariant::Finality(update) => update,
            UpdateVariant::Optimistic(..) => {
                panic!("Unexpected")
            }
        };

        let recent_block = update.finalized_header.beacon;
        let target_block = verification_data.1.proofs.target_block;

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
        let verification_data = get_verification_data_with_block_roots();
        let proofs = verification_data.1.proofs;
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
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 45, 76, 236, 211, 98, 206, 77, 244, 1, 23, 21,
                75, 154, 6, 121, 123, 92, 241, 118, 32,
            ]
            .try_into()
            .unwrap(),
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 206, 22, 246, 147, 117, 82, 10, 176, 19, 119,
                206, 123, 136, 245, 186, 140, 72, 248, 214, 102,
            ]
            .try_into()
            .unwrap(),
        ];
        let expected_data: Vec<u8> = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 59,
            154, 202, 0,
        ];

        assert_eq!(first_log.address, expected_address);
        assert_eq!(first_log.topics, expected_topics);
        assert_eq!(first_log.data, expected_data);

        let logs_result = extract_logs_from_receipt_proof(
            &proofs.receipt_proof,
            proofs.transaction_proof.transaction_index,
            &proofs.target_block.clone().hash_tree_root().unwrap(),
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
        let verification_data = get_verification_data_with_block_roots();
        let proofs = verification_data.1.proofs;

        assert!(extract_logs_from_receipt_proof(
            &proofs.receipt_proof,
            proofs.transaction_proof.transaction_index,
            &proofs.target_block.clone().hash_tree_root().unwrap(),
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
            &proofs.target_block.clone().hash_tree_root().unwrap(),
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
        let verification_data = get_verification_data_with_block_roots();
        let transaction_proof = verification_data.1.proofs.transaction_proof;
        let target_block_root = &verification_data
            .1
            .proofs
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
    fn test_verify_message() {
        let verification_data = get_verification_data_with_block_roots();
        let message = verification_data.1.message;
        let receipt_proof = verification_data.1.proofs.receipt_proof;
        let transaction_proof = verification_data.1.proofs.transaction_proof;

        let log_index_str = message.cc_id.id.split(':').nth(1).unwrap();
        let log_index: usize = log_index_str.parse().unwrap();
        let logs = extract_logs_from_receipt_proof(
            &receipt_proof,
            transaction_proof.transaction_index,
            &verification_data
                .1
                .proofs
                .target_block
                .clone()
                .hash_tree_root()
                .unwrap(),
        )
        .unwrap();
        let log = logs.0[log_index].clone();

        assert!(verify_message(&message, &log, &transaction_proof.transaction).is_ok());

        // test source address check
        let mut modified_log = log.clone();
        // TODO: don't hardcode
        assert_eq!(
            modified_log.address,
            hex::decode("4f4495243837681061c4743b74b3eedf548d56a5")
                .unwrap()
                .as_slice()
        );
        assert!(verify_message(&message, &modified_log, &transaction_proof.transaction).is_ok());
        modified_log.address = Address::ZERO.to_vec().try_into().unwrap();
        assert!(verify_message(&message, &modified_log, &transaction_proof.transaction).is_err());

        // test transaction hash check
        let mut modified_message = message.clone();
        assert_eq!(
            modified_message.cc_id.id.split(':').next().unwrap(),
            "0x39c508536dbb1e48ee05d4c17bab7262bd18951725d3004fc0c58dab147f64c3"
        );
        assert!(verify_message(&modified_message, &log, &transaction_proof.transaction).is_ok());
        modified_message.cc_id.id = String::from("foo:bar").try_into().unwrap();
        assert!(verify_message(&modified_message, &log, &transaction_proof.transaction).is_err());
        modified_message.cc_id.id = String::from("0x1234567:bar").try_into().unwrap();
        assert!(verify_message(&modified_message, &log, &transaction_proof.transaction).is_err());

        // test source_address check
        let mut modified_message = message.clone();
        assert_eq!(
            modified_message.source_address.to_string().to_lowercase(),
            "0xce16f69375520ab01377ce7b88f5ba8c48f8d666"
        );
        assert!(verify_message(&modified_message, &log, &transaction_proof.transaction).is_ok());
        modified_message.source_address = Address::ZERO.to_string().try_into().unwrap();
        assert!(verify_message(&modified_message, &log, &transaction_proof.transaction).is_err());

        // test destination_chain check
        let mut modified_message = message.clone();
        assert_eq!(
            modified_message
                .destination_chain
                .to_string()
                .to_lowercase(),
            "fantom"
        );
        assert!(verify_message(&modified_message, &log, &transaction_proof.transaction).is_ok());
        modified_message.destination_chain = String::from("none").try_into().unwrap();
        assert!(verify_message(&modified_message, &log, &transaction_proof.transaction).is_err());

        // test destination_address check
        let mut modified_message = message.clone();
        assert_eq!(
            modified_message.destination_address.to_string(),
            "0xce16F69375520ab01377ce7B88f5BA8C48F8D666"
        );
        assert!(verify_message(&modified_message, &log, &transaction_proof.transaction).is_ok());
        modified_message.destination_address = Address::ZERO.to_string().try_into().unwrap();
        assert!(verify_message(&modified_message, &log, &transaction_proof.transaction).is_err());

        // test payload_hash check
        let mut modified_message = message.clone();
        assert_eq!(
            hex::encode(modified_message.payload_hash),
            "44f95df5069da9568af3523591468aab99df0ef9c8328cb66bdfe0e612d9d037"
        );
        assert!(verify_message(&modified_message, &log, &transaction_proof.transaction).is_ok());
        // TODO: generate [u8; 32] instead of hardcoding
        modified_message.payload_hash = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        assert!(verify_message(&modified_message, &log, &transaction_proof.transaction).is_err());

        // failure on invalid log
        let log = ReceiptLog::default();
        assert!(verify_message(&message, &log, &transaction_proof.transaction).is_err());
    }

    #[test]
    fn test_verify_update_participation() {
        let lightclient = init_lightclient(None);

        let mut update = get_update(862);
        update.sync_aggregate.sync_committee_bits = Bitvector::default();

        let err = update.verify(&lightclient).unwrap_err();

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
        let mut err = update.verify(&lightclient).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidTimestamp.to_string()
        );

        update = get_update(862);
        update.signature_slot = update.attested_header.beacon.slot;
        err = update.verify(&lightclient).unwrap_err();

        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidTimestamp.to_string()
        );

        update = get_update(862);
        update.finalized_header.beacon.slot = update.attested_header.beacon.slot + 1;
        err = update.verify(&lightclient).unwrap_err();

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

        let mut err = update.verify(&lightclient).unwrap_err();

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
        err = update.verify(&lightclient).unwrap_err();

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
        let mut err = update.verify(&lightclient).unwrap_err();
        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::NotRelevant.to_string()
        );

        update = get_update(862);
        update.attested_header.beacon.slot = lightclient.state.update_slot - (256 * 32);
        update.finalized_header.beacon.slot = lightclient.state.update_slot - (256 * 32) - 1; // subtracting 1 for a regression bug
        lightclient.state.next_sync_committee = None;
        err = update.verify(&lightclient).unwrap_err();
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
        let mut err = update.verify(&lightclient).unwrap_err();
        assert_eq!(
            err.to_string(),
            lightclient::ConsensusError::InvalidFinalityProof.to_string()
        );

        update = get_update(862);
        update.finalized_header.beacon.state_root = Node::default();
        err = update.verify(&lightclient).unwrap_err();
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
        let err = update.verify(&lightclient).unwrap_err();

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

        let err = update.verify(&lightclient).err().unwrap();
        assert_eq!(
            err.to_string(),
            ConsensusError::InvalidSignature.to_string()
        );
    }

    #[test]
    fn test_verify_update() {
        let lightclient = init_lightclient(None);

        let update = get_update(862);
        let res = update.verify(&lightclient);
        assert!(res.is_ok());
    }

    #[test]
    fn test_bootstrap_state() {
        let lightclient = init_lightclient(None);
        let bootstrap = get_bootstrap();

        let mut update = get_update(862);
        update.finalized_header.beacon = BeaconBlockHeader::default();

        let err = update.verify(&lightclient);
        assert!(err.is_err());

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
        let res = update.verify(&lightclient);
        assert!(res.is_ok());

        let res = lightclient.apply_update(&update);
        assert!(res.is_ok());
        assert_eq!(
            lightclient.state.update_slot, update.finalized_header.beacon.slot,
            "finalized_header should be set after applying update"
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

        let mut res;
        res = lightclient.apply_update(&get_update(862));
        assert!(res.is_ok());
        let state_before_update = lightclient.state.clone();

        let update = get_update(863);
        res = lightclient.apply_update(&update);
        assert!(res.is_ok());

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
    fn test_apply_same_period_update() {
        let mut lightclient = init_lightclient(None);
        let update = get_update(862);

        let mut res;
        res = lightclient.apply_update(&update);
        assert!(res.is_ok());
        let state_before_update = lightclient.state.clone();

        // TODO: FIXME
        // update.finalized_header.beacon.slot =
        //     U64::from(update.finalized_header.beacon.slot.as_u64() + 1);
        res = lightclient.apply_update(&update);
        assert!(res.is_ok());

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

    #[test]
    fn test_multiple_updates() {
        let mut lightclient = init_lightclient(None);
        let update = get_update(862);
        let res = lightclient.apply_update(&update);
        assert!(res.is_ok());
        assert_eq!(
            lightclient.state.update_slot, update.finalized_header.beacon.slot,
            "finalized_header should be set after applying first update"
        );

        let update = get_update(863);
        let res = lightclient.apply_update(&update);
        assert!(res.is_ok());
        assert_eq!(
            lightclient.state.update_slot, update.finalized_header.beacon.slot,
            "finalized_header should be set after applying second update"
        );
    }
}
