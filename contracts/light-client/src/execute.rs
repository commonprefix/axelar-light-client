use crate::ContractError;
use cosmwasm_std::{DepsMut, Env, Response};
use eyre::{eyre, Result};
use hasher::{Hasher, HasherKeccak};
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
    calc_sync_period, compare_content_with_log, extract_logs_from_receipt_proof, parse_message_id,
    verify_ancestry_proof, verify_transaction_proof,
};
use crate::lightclient::LightClient;
use crate::state::{CONFIG, LIGHT_CLIENT_STATE, SYNC_COMMITTEE, VERIFIED_MESSAGES};

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

pub fn process_batch_data(
    deps: DepsMut,
    lightclient: &LightClient,
    data: &BatchVerificationData,
) -> Result<Vec<(ContentVariant, Result<()>)>> {
    match &data.update {
        UpdateVariant::Finality(update) => lightclient.verify_finality_update(update)?,
        UpdateVariant::Optimistic(update) => lightclient.verify_optimistic_update(update)?,
    }
    let recent_block = data.update.recent_block();
    let gateway_address = CONFIG.load(deps.storage)?.gateway_address;

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
                    VERIFIED_MESSAGES.save(deps.storage, message.hash(), message)?
                }
                ContentVariant::WorkerSet(..) => todo!(),
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

    SYNC_COMMITTEE.save(
        deps.storage,
        &(
            update.next_sync_committee,
            calc_sync_period(update.attested_header.beacon.slot) + 1,
        ),
    )?;
    LIGHT_CLIENT_STATE.save(deps.storage, &lc.state)?;

    Ok(Response::new())
}

#[cfg(test)]
mod tests {
    use crate::execute::{process_block_proofs, process_transaction_proofs, verify_content};
    use crate::lightclient::helpers::test_helpers::{
        filter_message_variants, filter_workeset_message_variants, get_batched_data, get_config,
    };
    use crate::lightclient::helpers::{extract_logs_from_receipt_proof, parse_message_id};
    use crate::lightclient::tests::tests::init_lightclient;
    use crate::state::CONFIG;
    use cosmwasm_std::testing::mock_dependencies;
    use eyre::Result;
    use types::alloy_primitives::Address;
    use types::common::ContentVariant;
    use types::consensus::FinalityUpdate;
    use types::execution::{ReceiptLog, ReceiptLogs};
    use types::proofs::{BlockProofsBatch, Message, TransactionProofsBatch, UpdateVariant};
    use types::ssz_rs::Merkleized;

    use super::process_batch_data;

    fn filter_message_variants_as_mutref(
        proofs_batch: &mut TransactionProofsBatch,
    ) -> Vec<&mut Message> {
        proofs_batch
            .content
            .iter_mut()
            .filter_map(|c| match c {
                ContentVariant::Message(m) => Some(m),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn test_verify_content_failures() {
        let gateway_address = String::from("0x4F4495243837681061C4743b74B3eEdf548D56A5");
        let verification_data = get_batched_data(false).1;
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
        let gateway_address = String::from("0x4F4495243837681061C4743b74B3eEdf548D56A5");
        let verification_data = get_batched_data(false).1;
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
    #[ignore]
    fn test_verify_workerset_message() {
        let gateway_address = String::from("0x4F4495243837681061C4743b74B3eEdf548D56A5");
        let verification_data = get_batched_data(false).1;
        let target_block_proofs = verification_data.target_blocks.get(0).unwrap();
        let proofs = target_block_proofs.transactions_proofs.get(0).unwrap();

        let messages = filter_workeset_message_variants(proofs);

        let mut message = messages.first().unwrap().clone();
        message.message_id = String::from("broken_id").try_into().unwrap();
        assert_eq!(
            verify_content(
                ContentVariant::WorkerSet(message.clone()).clone(),
                &proofs.transaction_proof.transaction,
                &ReceiptLogs::default(),
                &gateway_address,
            )
            .unwrap_err()
            .to_string(),
            "Invalid message id format"
        );

        message.message_id = String::from("foo:bar").try_into().unwrap();
        assert_eq!(
            verify_content(
                ContentVariant::WorkerSet(message.clone()).clone(),
                &proofs.transaction_proof.transaction,
                &ReceiptLogs::default(),
                &gateway_address
            )
            .unwrap_err()
            .to_string(),
            "Invalid transaction hash in message id"
        );

        message = messages.get(0).unwrap().clone();
        assert_eq!(
            verify_content(
                ContentVariant::WorkerSet(message.clone()).clone(),
                &proofs.transaction_proof.transaction,
                &ReceiptLogs::default(),
                &gateway_address
            )
            .unwrap_err()
            .to_string(),
            "Log index out of bounds"
        );

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
            &gateway_address
        )
        .is_err());
    }

    #[test]
    fn test_process_transaction_proofs() {
        let gateway_address = String::from("0x4F4495243837681061C4743b74B3eEdf548D56A5");
        let data = get_batched_data(false).1;

        let block_proofs = data
            .target_blocks
            .get(0)
            .expect("No block proofs available");
        let transaction_proofs = block_proofs
            .transactions_proofs
            .get(0)
            .expect("No transaction proofs available")
            .clone();
        let messages = filter_message_variants(&transaction_proofs);

        let target_block_root = block_proofs.target_block.clone().hash_tree_root().unwrap();

        let res =
            process_transaction_proofs(&transaction_proofs, &target_block_root, &gateway_address);
        assert_valid_messages(&messages, &res);

        let mut corrupted_proofs = transaction_proofs.clone();
        let mut messages = filter_message_variants_as_mutref(&mut corrupted_proofs);
        messages[0].cc_id.id = "invalid".to_string().try_into().unwrap();
        let res =
            process_transaction_proofs(&corrupted_proofs, &target_block_root, &gateway_address);
        assert_invalid_messages(&filter_message_variants(&corrupted_proofs), &res);
    }

    fn extract_messages_from_block(target_block: &BlockProofsBatch) -> Vec<Message> {
        target_block
            .transactions_proofs
            .iter()
            .flat_map(|transaction_proofs| filter_message_variants(transaction_proofs).into_iter())
            .collect()
    }

    fn assert_valid_messages(messages: &[Message], res: &Vec<(ContentVariant, Result<()>)>) {
        assert!(res.len() > 0);
        assert_eq!(res.len(), messages.len());
        for (index, message) in messages.iter().enumerate() {
            assert!(res[index].1.is_ok());
            if let ContentVariant::Message(m) = &res[index].0 {
                assert_eq!(m, message);
            } else {
                assert!(false, "Not a message variant");
            }
        }
    }

    fn corrupt_messages(target_block: &mut BlockProofsBatch) {
        for tx in target_block.transactions_proofs.iter_mut() {
            let mut messages = filter_message_variants_as_mutref(tx);
            for message in messages.iter_mut() {
                message.cc_id.id = "invalid".to_string().try_into().unwrap();
            }
        }
    }

    fn assert_invalid_messages(messages: &[Message], res: &Vec<(ContentVariant, Result<()>)>) {
        assert!(res.len() > 0);
        assert_eq!(res.len(), messages.len());
        for (index, message) in messages.iter().enumerate() {
            assert_eq!(
                res[index].1.as_ref().unwrap_err().to_string(),
                "Invalid message id format"
            );
            if let ContentVariant::Message(m) = &res[index].0 {
                assert_eq!(m, message);
            } else {
                assert!(false, "Not a message variant");
            }
        }
    }

    #[test]
    fn test_process_block_proofs() {
        let gateway_address = String::from("0x4F4495243837681061C4743b74B3eEdf548D56A5");
        let mut data = get_batched_data(false).1;
        let recent_block = data.update.recent_block();

        for target_block in data.target_blocks.iter_mut() {
            let messages = extract_messages_from_block(target_block);

            let res = process_block_proofs(&recent_block, target_block, &gateway_address);
            assert_valid_messages(&messages, &res);

            corrupt_messages(target_block);
            let messages = extract_messages_from_block(target_block);
            let res = process_block_proofs(&recent_block, target_block, &gateway_address);
            assert_invalid_messages(&messages, &res);
        }
    }

    #[test]
    fn test_process_batch_data() {
        let (bootstrap, mut data) = get_batched_data(false);
        let lc = init_lightclient(Some(bootstrap));
        let mut deps = mock_dependencies();
        CONFIG.save(&mut deps.storage, &get_config()).unwrap();

        let res = process_batch_data(deps.as_mut(), &lc, &data);
        let messages = data
            .target_blocks
            .iter()
            .flat_map(|target_block| extract_messages_from_block(target_block))
            .collect::<Vec<Message>>();

        assert!(res.is_ok());
        assert_valid_messages(&messages, &res.unwrap());

        let mut corrupt_data = data.clone();
        corrupt_data.update = UpdateVariant::Finality(FinalityUpdate::default());
        assert!(process_batch_data(deps.as_mut(), &lc, &corrupt_data).is_err());

        for target_block in data.target_blocks.iter_mut() {
            corrupt_messages(target_block);
        }
        let messages = data
            .target_blocks
            .iter()
            .flat_map(|target_block| extract_messages_from_block(target_block))
            .collect::<Vec<Message>>();
        let res = process_batch_data(deps.as_mut(), &lc, &data);
        assert!(res.is_ok());
        assert_invalid_messages(&messages, &res.unwrap());
    }
}
