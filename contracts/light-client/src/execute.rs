use crate::ContractError;
use cosmwasm_std::{DepsMut, Env, Response};
use eyre::{eyre, Result};
use hasher::{Hasher, HasherKeccak};
use types::common::{Config, FinalizationVariant, PrimaryKey};
use types::consensus::BeaconBlockHeader;
use types::execution::ReceiptLogs;
use types::proofs::{
    BatchVerificationData, BlockProofsBatch, TransactionProofsBatch, UpdateVariant,
};
use types::ssz_rs::{Merkleized, Node};
use types::sync_committee_rs::consensus_types::Transaction;
use types::sync_committee_rs::constants::MAX_BYTES_PER_TRANSACTION;
use types::{common::ContentVariant, consensus::Update};

use crate::lightclient::helpers::{
    compare_content_with_log, extract_logs_from_receipt_proof, parse_message_id,
    verify_ancestry_proof, verify_transaction_proof, LowerCaseFields,
};
use crate::lightclient::LightClient;
use crate::state::{CONFIG, LIGHT_CLIENT_STATE, VERIFIED_MESSAGES, VERIFIED_WORKER_SETS};

/// Finds the necessary log from a list of logs and then verifies the provided content.
fn verify_content(
    content: ContentVariant,
    transaction: &Transaction<MAX_BYTES_PER_TRANSACTION>,
    logs: &ReceiptLogs,
    gateway_address: &str,
) -> Result<()> {
    let gateway_address = hex::decode(
        gateway_address
            .strip_prefix("0x")
            .ok_or_else(|| eyre!("Invalid gateway address in .env"))?,
    )?;
    let hasher = HasherKeccak::new();
    let transaction_hash = hex::encode(hasher.digest(transaction.as_slice()));
    let (message_tx_hash, log_index) = match &content {
        ContentVariant::Message(message) => parse_message_id(&message.cc_id.id),
        ContentVariant::WorkerSet(message) => parse_message_id(&message.message_id),
    }?;

    if message_tx_hash != transaction_hash {
        return Err(eyre!("Invalid content transaction hash"));
    }

    let log = logs
        .0
        .get(log_index)
        .ok_or_else(|| eyre!("Log index out of bounds"))?;

    if gateway_address != log.address {
        return Err(eyre!("Invalid log address"));
    }

    compare_content_with_log(content, log)
}

/// Verifies that the transaction and the receipt are included in the target block, and then verifies the messages for the given transaction.
fn process_transaction_proofs(
    data: &TransactionProofsBatch,
    target_block_root: &Node,
    gateway_address: &str,
) -> Vec<(ContentVariant, Result<()>)> {
    let result = verify_transaction_proof(&data.transaction_proof, target_block_root)
        .and_then(|_| {
            extract_logs_from_receipt_proof(
                &data.receipt_proof,
                data.transaction_proof.transaction_index,
                target_block_root,
            )
        })
        .map(|logs| {
            data.content
                .iter()
                .map(|content_variant| {
                    (
                        content_variant.to_owned(),
                        verify_content(
                            content_variant.clone(),
                            &data.transaction_proof.transaction,
                            &logs,
                            gateway_address,
                        ),
                    )
                })
                .collect::<Vec<(ContentVariant, Result<()>)>>()
        });

    result.unwrap_or_else(|err| {
        data.content
            .iter()
            .map(|content_variant| (content_variant.to_owned(), Err(eyre!(err.to_string()))))
            .collect()
    })
}

/// Verifies that a target block is an ancestor of the given recent block, and then proceeds with the verification of the transactions inside the target block.
fn process_block_proofs(
    recent_block: &BeaconBlockHeader,
    data: &BlockProofsBatch,
    gateway_address: &str,
) -> Vec<(ContentVariant, Result<()>)> {
    let transactions_proofs = &data.transactions_proofs;

    let mut target_block_root = Node::default();
    let mut ancestry_proof_verification = || -> Result<()> {
        target_block_root = data.target_block.clone().hash_tree_root()?;

        verify_ancestry_proof(&data.ancestry_proof, &data.target_block, recent_block)?;
        Ok(())
    };

    match ancestry_proof_verification() {
        Ok(_) => transactions_proofs
            .iter()
            .flat_map(|proof| {
                process_transaction_proofs(proof, &target_block_root, gateway_address)
            })
            .collect(),
        Err(err) => transactions_proofs
            .iter()
            .flat_map(|proof| {
                proof
                    .content
                    .iter()
                    .map(|content_variant| (content_variant.clone(), Err(eyre!(err.to_string()))))
            })
            .collect(),
    }
}

/// Processes a complete verification request
pub fn process_batch_data(
    deps: DepsMut,
    lightclient: &LightClient,
    data: &BatchVerificationData,
    config: &Config,
) -> Result<Vec<(ContentVariant, Result<()>)>> {
    match &data.update {
        UpdateVariant::Finality(update) => {
            if matches!(config.finalization, FinalizationVariant::Optimistic()) {
                return Err(eyre!(
                    "Optimistic verification enabled but provided Finality update"
                ));
            }
            lightclient.verify_finality_update(update)?
        }
        UpdateVariant::Optimistic(update) => {
            if matches!(config.finalization, FinalizationVariant::Finality()) {
                return Err(eyre!(
                    "Finality verification enabled but provided Optimistic update"
                ));
            }
            lightclient.verify_optimistic_update(update)?
        }
    }
    let recent_block = data.update.recent_block();
    let gateway_address = config.gateway_address.clone();

    let results = data
        .target_blocks
        .iter()
        .flat_map(|block_proofs_batch| {
            process_block_proofs(&recent_block, block_proofs_batch, &gateway_address)
        })
        .collect::<Vec<(ContentVariant, Result<()>)>>();

    for content_variant_result in results.iter() {
        if content_variant_result.1.is_ok() {
            match &content_variant_result.0 {
                ContentVariant::Message(message) => {
                    VERIFIED_MESSAGES.save(deps.storage, message.to_lowercase().hash(), message)?
                }
                ContentVariant::WorkerSet(message) => VERIFIED_WORKER_SETS.save(
                    deps.storage,
                    message.to_lowercase().key(),
                    message,
                )?,
            }
        }
    }

    Ok(results)
}

pub fn light_client_update(
    deps: DepsMut,
    env: &Env,
    update: Update,
) -> Result<Response, ContractError> {
    let state = LIGHT_CLIENT_STATE.load(deps.storage)?;
    let config = CONFIG.load(deps.storage)?;
    let mut lc = LightClient::new(&config.chain_config, Some(state), env);

    let res = lc.apply_update(&update);
    if res.is_err() {
        return Err(ContractError::from(res.err().unwrap()));
    }

    LIGHT_CLIENT_STATE.save(deps.storage, &lc.state)?;

    Ok(Response::new())
}

#[cfg(test)]
pub mod tests {
    use crate::execute::{process_block_proofs, process_transaction_proofs, verify_content};
    use crate::lightclient::helpers::test_helpers::{
        filter_message_variants, filter_workerset_variants, get_batched_data, get_config,
        get_gindex_overflow_data,
    };
    use crate::lightclient::helpers::{
        extract_logs_from_receipt_proof, parse_message_id, LowerCaseFields,
    };
    use crate::lightclient::tests::tests::init_lightclient;
    use crate::state::{CONFIG, VERIFIED_MESSAGES, VERIFIED_WORKER_SETS};
    use cosmwasm_std::testing::mock_dependencies;
    use eyre::Result;
    use types::alloy_primitives::Address;
    use types::common::{ContentVariant, FinalizationVariant, PrimaryKey, WorkerSetMessage};
    use types::consensus::{FinalityUpdate, OptimisticUpdate};
    use types::execution::{ReceiptLog, ReceiptLogs};
    use types::proofs::{
        AncestryProof, BlockProofsBatch, Message, TransactionProofsBatch, UpdateVariant,
    };
    use types::ssz_rs::{Merkleized, Node};

    use super::process_batch_data;

    fn filter_variants_as_mutref(
        proofs_batch: &mut TransactionProofsBatch,
    ) -> (Vec<&mut WorkerSetMessage>, Vec<&mut Message>) {
        let mut workerset_messages: Vec<&mut WorkerSetMessage> = vec![];
        let mut messages: Vec<&mut Message> = vec![];

        for content in proofs_batch.content.iter_mut() {
            match content {
                ContentVariant::WorkerSet(m) => workerset_messages.push(m),
                ContentVariant::Message(m) => messages.push(m),
            }
        }
        (workerset_messages, messages)
    }

    #[test]
    fn test_verify_content_failures() {
        let gateway_address = String::from("0xAba4D993188008F665C972d79fc59AB2381eCe94");
        let verification_data = get_batched_data(false, "finality").1;
        let target_block_proofs = verification_data.target_blocks.get(0).unwrap();
        let proofs = target_block_proofs.transactions_proofs.get(0).unwrap();

        let messages = filter_message_variants(proofs);

        let mut message = messages.get(0).unwrap().clone();
        message.cc_id.id = String::from("broken_id").try_into().unwrap();
        assert_eq!(
            verify_content(
                ContentVariant::Message(message.clone()).clone(),
                &proofs.transaction_proof.transaction,
                &ReceiptLogs::default(),
                &gateway_address
            )
            .unwrap_err()
            .to_string(),
            "Invalid message id format"
        );

        message.cc_id.id = String::from("foo:bar").try_into().unwrap();
        assert_eq!(
            verify_content(
                ContentVariant::Message(message.clone()).clone(),
                &proofs.transaction_proof.transaction,
                &ReceiptLogs::default(),
                &gateway_address,
            )
            .unwrap_err()
            .to_string(),
            "Invalid transaction hash in message id"
        );

        message = messages.get(0).unwrap().clone();
        assert_eq!(
            verify_content(
                ContentVariant::Message(message.clone()).clone(),
                &proofs.transaction_proof.transaction,
                &ReceiptLogs::default(),
                &gateway_address,
            )
            .unwrap_err()
            .to_string(),
            "Log index out of bounds"
        );

        message = messages.get(0).unwrap().clone();
        message.cc_id.id =
            String::from("0xa92d426734f1f7054b89a68b2a71f2f19f8150716bf046c59a3cd819413afd13:0")
                .try_into()
                .unwrap();
        assert_eq!(
            verify_content(
                ContentVariant::Message(message.clone()).clone(),
                &proofs.transaction_proof.transaction,
                &ReceiptLogs::default(),
                &gateway_address,
            )
            .unwrap_err()
            .to_string(),
            "Invalid content transaction hash"
        );

        message = messages.get(0).unwrap().clone();
        message.cc_id.id = String::from(format!(
            "{}:0",
            parse_message_id(&message.cc_id.id).unwrap().0
        ))
        .try_into()
        .unwrap();
        let mut logs = extract_logs_from_receipt_proof(
            &proofs.receipt_proof,
            proofs.transaction_proof.transaction_index,
            &target_block_proofs
                .target_block
                .clone()
                .hash_tree_root()
                .unwrap(),
        )
        .unwrap();
        logs.0[0].address = Address::ZERO.to_vec().try_into().unwrap();
        assert_eq!(
            verify_content(
                ContentVariant::Message(message.clone()).clone(),
                &proofs.transaction_proof.transaction,
                &logs,
                &gateway_address,
            )
            .unwrap_err()
            .to_string(),
            "Invalid log address"
        );
    }

    #[test]
    fn test_verify_message() {
        let gateway_address = String::from("0xAba4D993188008F665C972d79fc59AB2381eCe94");
        let verification_data = get_batched_data(false, "finality").1;
        let target_block_proofs = verification_data.target_blocks.get(0).unwrap();
        let proofs = target_block_proofs.transactions_proofs.get(0).unwrap();

        let messages = filter_message_variants(proofs);

        let message = messages.get(0).unwrap().clone();
        let logs = extract_logs_from_receipt_proof(
            &proofs.receipt_proof,
            proofs.transaction_proof.transaction_index,
            &target_block_proofs
                .target_block
                .clone()
                .hash_tree_root()
                .unwrap(),
        )
        .unwrap();
        // valid comparison
        assert!(verify_content(
            ContentVariant::Message(message.clone()).clone(),
            &proofs.transaction_proof.transaction,
            &logs,
            &gateway_address
        )
        .is_ok());

        let logs = ReceiptLogs(vec![ReceiptLog::default()]);
        // invalid comparison
        assert!(verify_content(
            ContentVariant::Message(message.clone()).clone(),
            &proofs.transaction_proof.transaction,
            &logs,
            &gateway_address,
        )
        .is_err());
    }

    #[test]
    fn test_verify_workerset_message() {
        let gateway_address = String::from("0xAba4D993188008F665C972d79fc59AB2381eCe94");
        let verification_data = get_batched_data(false, "finality").1;
        let target_block_proofs = verification_data.target_blocks.get(0).unwrap();
        let proofs = target_block_proofs.transactions_proofs.get(0).unwrap();

        let messages = filter_workerset_variants(proofs);

        let message = messages.get(0).unwrap().clone();
        let logs = extract_logs_from_receipt_proof(
            &proofs.receipt_proof,
            proofs.transaction_proof.transaction_index,
            &target_block_proofs
                .target_block
                .clone()
                .hash_tree_root()
                .unwrap(),
        )
        .unwrap();
        // valid comparison
        assert!(verify_content(
            ContentVariant::WorkerSet(message.clone()).clone(),
            &proofs.transaction_proof.transaction,
            &logs,
            &gateway_address
        )
        .is_ok());

        let logs = ReceiptLogs(vec![ReceiptLog::default()]);
        // invalid comparison
        assert!(verify_content(
            ContentVariant::WorkerSet(message.clone()).clone(),
            &proofs.transaction_proof.transaction,
            &logs,
            &gateway_address,
        )
        .is_err());
    }

    #[test]
    fn test_process_transaction_proofs() {
        let gateway_address = String::from("0xAba4D993188008F665C972d79fc59AB2381eCe94");
        let data = get_batched_data(false, "finality").1;

        let block_proofs = data
            .target_blocks
            .get(0)
            .expect("No block proofs available");
        let transaction_proofs = block_proofs
            .transactions_proofs
            .get(0)
            .expect("No transaction proofs available")
            .clone();
        let content = transaction_proofs.content.clone();

        let target_block_root = block_proofs.target_block.clone().hash_tree_root().unwrap();

        let res =
            process_transaction_proofs(&transaction_proofs, &target_block_root, &gateway_address);
        assert_valid_contents(&content, &res);

        // test error from content
        let mut corrupted_proofs = transaction_proofs.clone();
        let (workerset_messages, messages) = filter_variants_as_mutref(&mut corrupted_proofs);
        for message in messages {
            message.cc_id.id = "invalid".to_string().try_into().unwrap();
        }
        for message in workerset_messages {
            message.message_id = "invalid".to_string().try_into().unwrap();
        }
        let res =
            process_transaction_proofs(&corrupted_proofs, &target_block_root, &gateway_address);
        assert_invalid_contents(&corrupted_proofs.content, &res);

        // test error in transaction proof
        let mut corrupted_proofs = transaction_proofs.clone();
        corrupted_proofs.transaction_proof.transaction_proof = vec![Node::default(); 32];
        let res =
            process_transaction_proofs(&corrupted_proofs, &target_block_root, &gateway_address);
        assert_invalid_contents(&extract_content_from_block(block_proofs), &res);
    }

    pub fn extract_content_from_block(target_block: &BlockProofsBatch) -> Vec<ContentVariant> {
        target_block
            .transactions_proofs
            .iter()
            .flat_map(|transaction_proofs| transaction_proofs.content.clone())
            .collect()
    }

    fn assert_valid_contents(contents: &[ContentVariant], res: &Vec<(ContentVariant, Result<()>)>) {
        assert!(res.len() > 0);
        assert_eq!(res.len(), contents.len());
        for (index, content_variant) in contents.iter().enumerate() {
            assert!(res[index].1.is_ok());
            assert_eq!(res[index].0, *content_variant);
        }
    }

    fn corrupt_contents(target_block: &mut BlockProofsBatch) {
        for tx in target_block.transactions_proofs.iter_mut() {
            let (mut workerset_messaages, mut messages) = filter_variants_as_mutref(tx);
            for message in messages.iter_mut() {
                message.cc_id.id = "invalid".to_string().try_into().unwrap();
            }

            for message in workerset_messaages.iter_mut() {
                message.message_id = "invalid".to_string().try_into().unwrap();
            }
        }
    }

    fn assert_invalid_contents(
        contents: &[ContentVariant],
        res: &Vec<(ContentVariant, Result<()>)>,
    ) {
        assert!(res.len() > 0);
        assert_eq!(res.len(), contents.len());
        for (index, content_variant) in contents.iter().enumerate() {
            assert!(res[index].1.is_err());
            assert_eq!(res[index].0, *content_variant);
        }
    }

    #[test]
    fn test_process_block_proofs() {
        let gateway_address = String::from("0xAba4D993188008F665C972d79fc59AB2381eCe94");
        let mut data = get_batched_data(false, "finality").1;
        let recent_block = data.update.recent_block();

        for target_block in data.target_blocks.iter_mut() {
            let content = extract_content_from_block(target_block);

            let res = process_block_proofs(&recent_block, target_block, &gateway_address);
            assert_valid_contents(&content, &res);

            corrupt_contents(target_block);
            let contents = extract_content_from_block(target_block);
            let res = process_block_proofs(&recent_block, target_block, &gateway_address);
            assert_invalid_contents(&contents, &res);
        }

        // test error on ancestry proof
        for target_block in data.target_blocks.iter_mut() {
            let contents = extract_content_from_block(&target_block.clone());

            let AncestryProof::BlockRoots {
                block_root_proof,
                block_roots_index: _,
            } = &mut target_block.ancestry_proof
            else {
                panic!("")
            };
            *block_root_proof = vec![Node::default(); 18];
            let res = process_block_proofs(&recent_block, target_block, &gateway_address);
            assert_invalid_contents(&contents, &res);
        }
    }

    #[test]
    fn test_process_batch_data() {
        for historical in [true, false] {
            for finalization in ["finality", "optimistic"] {
                let (bootstrap, mut data) = get_batched_data(historical, finalization);
                let lc = init_lightclient(Some(bootstrap));
                let mut config = get_config();
                config.finalization = match finalization {
                    "finality" => FinalizationVariant::Finality(),
                    "optimistic" => FinalizationVariant::Optimistic(),
                    _ => config.finalization,
                };
                let mut deps = mock_dependencies();
                CONFIG.save(&mut deps.storage, &get_config()).unwrap();

                let res = process_batch_data(deps.as_mut(), &lc, &data, &config);
                let contents = data
                    .target_blocks
                    .iter()
                    .flat_map(|target_block| extract_content_from_block(target_block))
                    .collect::<Vec<ContentVariant>>();

                println!("{}, {}", historical, finalization);
                assert!(res.is_ok());
                assert_valid_contents(&contents, &res.unwrap());
                for content in contents {
                    match content {
                        ContentVariant::Message(m) => {
                            assert!(VERIFIED_MESSAGES
                                .load(&mut deps.storage, m.to_lowercase().hash())
                                .is_ok());
                        }
                        ContentVariant::WorkerSet(m) => {
                            assert!(VERIFIED_WORKER_SETS
                                .load(&mut deps.storage, m.key())
                                .is_ok());
                        }
                    }
                }

                // finalization type of update is different than config
                let mut corrupt_config = config.clone();
                corrupt_config.finalization = match finalization {
                    "finality" => FinalizationVariant::Optimistic(),
                    "optimistic" => FinalizationVariant::Finality(),
                    _ => corrupt_config.finalization,
                };
                assert!(process_batch_data(deps.as_mut(), &lc, &data, &corrupt_config).is_err());

                // Corrupt the update
                let mut corrupt_data = data.clone();
                match finalization {
                    "finality" => {
                        corrupt_data.update = UpdateVariant::Finality(FinalityUpdate::default())
                    }
                    "optimistic" => {
                        corrupt_data.update = UpdateVariant::Optimistic(OptimisticUpdate::default())
                    }
                    _ => panic!("Unknown finalization"),
                };
                assert!(process_batch_data(deps.as_mut(), &lc, &corrupt_data, &config).is_err(),);

                // Corrupt the contents
                for target_block in data.target_blocks.iter_mut() {
                    corrupt_contents(target_block);
                }
                let contents = data
                    .target_blocks
                    .iter()
                    .flat_map(|target_block| extract_content_from_block(target_block))
                    .collect::<Vec<ContentVariant>>();
                let res = process_batch_data(deps.as_mut(), &lc, &data, &config);
                assert!(res.is_ok());
                assert_invalid_contents(&contents, &res.unwrap());
            }
        }
    }

    #[test]
    fn generalized_index_overflow() {
        let data = get_gindex_overflow_data();
        let recent_block = data.update.recent_block();

        let gateway_address = String::from("0x557b0dc16d07cb297412a7da40a48615f7559765");
        let results = data
            .target_blocks
            .iter()
            .flat_map(|block_proofs_batch| {
                process_block_proofs(&recent_block, block_proofs_batch, &gateway_address)
            })
            .collect::<Vec<(ContentVariant, Result<()>)>>();

        for content_result in results {
            assert!(content_result.1.is_ok());
        }
    }
}
