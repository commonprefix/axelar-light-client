use crate::ContractError;
use cosmwasm_std::{DepsMut, Env, Response};
use eyre::{eyre, Result};
use types::common::ChainConfig;
use types::execution::{ReceiptLog, ReceiptLogs};
use types::proofs::{
    BatchVerificationData, BlockProofsBatch, Message, TransactionProofsBatch, UpdateVariant,
};
use types::ssz_rs::{Merkleized, Node};
use types::sync_committee_rs::consensus_types::Transaction;
use types::sync_committee_rs::constants::MAX_BYTES_PER_TRANSACTION;
use types::{common::Forks, consensus::Update};

use crate::lightclient::helpers::{
    compare_message_with_log, extract_logs_from_receipt_proof, extract_recent_block,
    verify_ancestry_proof, verify_transaction_proof,
};
use crate::lightclient::{LightClient, Verification};
use crate::state::{CONFIG, LIGHT_CLIENT_STATE, SYNC_COMMITTEE, VERIFIED_MESSAGES};

fn verify_message(
    message: &Message,
    transaction: &Transaction<MAX_BYTES_PER_TRANSACTION>,
    logs: &ReceiptLogs,
    compare_fn: &dyn Fn(&Message, &ReceiptLog, &Vec<u8>) -> Result<()>,
) -> Result<()> {
    let log_index_str = message
        .cc_id
        .id
        .split(':')
        .nth(1)
        .ok_or_else(|| eyre!("Missing ':' in message ID"))?;
    let log_index = log_index_str
        .parse::<usize>()
        .map_err(|_| eyre!("Failed to parse log index"))?;
    let log = logs
        .0
        .get(log_index)
        .ok_or_else(|| eyre!("Log index out of bounds"))?;

    compare_fn(message, log, transaction)?;

    Ok(())
}

fn process_transaction_proofs(
    data: &TransactionProofsBatch,
    target_block_root: &Node,
) -> Vec<(Message, Result<()>)> {
    let result = verify_transaction_proof(&data.transaction_proof, target_block_root)
        .and_then(|_| {
            extract_logs_from_receipt_proof(
                &data.receipt_proof,
                data.transaction_proof.transaction_index,
                target_block_root,
            )
        })
        .map(|logs| {
            data.messages
                .iter()
                .map(|message| {
                    (
                        message.to_owned(),
                        verify_message(
                            message,
                            &data.transaction_proof.transaction,
                            &logs,
                            &compare_message_with_log,
                        ),
                    )
                })
                .collect::<Vec<(Message, Result<()>)>>()
        });

    match result {
        Ok(proof_results) => proof_results,
        Err(err) => data
            .messages
            .iter()
            .map(|message| (message.to_owned(), Err(eyre!(err.to_string()))))
            .collect(),
    }
}

fn process_block_proofs(
    update: &UpdateVariant,
    data: &BlockProofsBatch,
) -> Vec<(Message, Result<()>)> {
    let transactions_proofs = &data.transactions_proofs;

    let mut target_block_root = Node::default();
    let mut ancestry_proof_verification = || -> Result<()> {
        let recent_block = extract_recent_block(&update);
        target_block_root = data.target_block.clone().hash_tree_root()?;

        verify_ancestry_proof(&data.ancestry_proof, &data.target_block, &recent_block)?;
        Ok(())
    };

    match ancestry_proof_verification() {
        Ok(_) => transactions_proofs
            .iter()
            .flat_map(|proof| process_transaction_proofs(proof, &target_block_root))
            .collect(),
        Err(err) => transactions_proofs
            .iter()
            .flat_map(|proof| {
                proof
                    .messages
                    .iter()
                    .map(|message| (message.clone(), Err(eyre!(err.to_string()))))
            })
            .collect(),
    }
}

pub fn process_batch_data(
    deps: DepsMut,
    lightclient: &LightClient,
    data: &BatchVerificationData,
) -> Result<Vec<(Message, Result<()>)>> {
    let update: &dyn Verification = match &data.update {
        UpdateVariant::Finality(update) => update,
        UpdateVariant::Optimistic(update) => update,
    };

    update.verify(&lightclient)?;

    let results = data
        .target_blocks
        .iter()
        .flat_map(|block_proofs_batch| process_block_proofs(&data.update, block_proofs_batch))
        .collect::<Vec<(Message, Result<()>)>>();

    for message_result in results.iter() {
        if message_result.1.is_ok() {
            VERIFIED_MESSAGES.save(deps.storage, message_result.0.hash_id(), &message_result.0)?
        }
    }

    return Ok(results);
}

pub fn light_client_update(
    deps: DepsMut,
    env: &Env,
    period: u64,
    update: Update,
) -> Result<Response, ContractError> {
    let state = LIGHT_CLIENT_STATE.load(deps.storage)?;
    let config = CONFIG.load(deps.storage)?;
    let mut lc = LightClient::new(&config, Some(state), env);

    let res = lc.apply_update(&update);
    if res.is_err() {
        return Err(ContractError::from(res.err().unwrap()));
    }

    SYNC_COMMITTEE.save(deps.storage, &(update.next_sync_committee, period + 1))?;
    LIGHT_CLIENT_STATE.save(deps.storage, &lc.state)?;

    Ok(Response::new())
}

pub fn update_forks(deps: DepsMut, forks: Forks) -> Result<Response> {
    CONFIG.update(deps.storage, |mut config| -> Result<ChainConfig> {
        config.forks = forks;
        Ok(config)
    })?;
    Ok(Response::new())
}

#[cfg(test)]
mod tests {
    use crate::execute::{self, process_block_proofs, process_transaction_proofs, verify_message};
    use crate::lightclient::helpers::extract_logs_from_receipt_proof;
    use crate::lightclient::helpers::test_helpers::get_batched_data;
    use crate::lightclient::tests::tests::init_lightclient;
    use cosmwasm_std::testing::mock_dependencies;
    use eyre::{eyre, Result};
    use types::consensus::FinalityUpdate;
    use types::execution::ReceiptLogs;
    use types::proofs::{BlockProofsBatch, Message, UpdateVariant};
    use types::ssz_rs::Merkleized;

    use super::process_batch_data;

    #[test]
    fn test_verify_message() {
        let verification_data = get_batched_data().1;
        let target_block_proofs = verification_data.target_blocks.get(0).unwrap();
        let proofs = target_block_proofs.transactions_proofs.get(0).unwrap();

        let mock_compare_ok = |_: &_, _: &_, _: &_| Ok(());
        let mock_compare_err = |_: &_, _: &_, _: &_| Err(eyre!("always fail"));

        let mut message = proofs.messages.get(0).unwrap().clone();
        message.cc_id.id = String::from("broken_id").try_into().unwrap();
        assert_eq!(
            verify_message(
                &message,
                &proofs.transaction_proof.transaction,
                &ReceiptLogs::default(),
                &mock_compare_ok
            )
            .unwrap_err()
            .to_string(),
            "Missing ':' in message ID"
        );

        message.cc_id.id = String::from("foo:bar").try_into().unwrap();
        assert_eq!(
            verify_message(
                &message,
                &proofs.transaction_proof.transaction,
                &ReceiptLogs::default(),
                &mock_compare_ok
            )
            .unwrap_err()
            .to_string(),
            "Failed to parse log index"
        );

        message = proofs.messages.get(0).unwrap().clone();
        assert_eq!(
            verify_message(
                &message,
                &proofs.transaction_proof.transaction,
                &ReceiptLogs::default(),
                &mock_compare_ok
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
        // returns the result of the compare function (OK)
        assert!(verify_message(
            &message,
            &proofs.transaction_proof.transaction,
            &logs,
            &mock_compare_ok
        )
        .is_ok());

        // returns the result of the compare function (Err)
        assert!(verify_message(
            &message,
            &proofs.transaction_proof.transaction,
            &logs,
            &mock_compare_err
        )
        .is_err());
    }

    #[test]
    fn test_process_transaction_proofs() {
        let data = get_batched_data().1;

        let block_proofs = data
            .target_blocks
            .get(0)
            .expect("No block proofs available");
        let transaction_proofs = block_proofs
            .transactions_proofs
            .get(0)
            .expect("No transaction proofs available")
            .clone();
        let messages = transaction_proofs.messages.clone();

        let target_block_root = block_proofs.target_block.clone().hash_tree_root().unwrap();

        let res = process_transaction_proofs(&transaction_proofs, &target_block_root);
        assert_valid_messages(&messages, &res);

        let mut corrupted_proofs = transaction_proofs.clone();
        corrupted_proofs.messages[0].cc_id.id = "invalid".to_string().try_into().unwrap();
        let messages = corrupted_proofs.messages.clone();
        let res = process_transaction_proofs(&corrupted_proofs, &target_block_root);
        assert_invalid_messages(&messages, &res);
    }

    fn extract_messages_from_block(target_block: &BlockProofsBatch) -> Vec<Message> {
        target_block
            .transactions_proofs
            .iter()
            .flat_map(|transaction_proofs| transaction_proofs.messages.iter())
            .cloned() // Clone here if necessary
            .collect()
    }

    fn assert_valid_messages(messages: &[Message], res: &Vec<(Message, Result<()>)>) {
        assert!(res.len() > 0);
        assert_eq!(res.len(), messages.len());
        for (index, message) in messages.iter().enumerate() {
            assert_eq!(res[index].0, *message);
            assert!(res[index].1.is_ok());
        }
    }

    fn corrupt_messages(target_block: &mut BlockProofsBatch) {
        for tx in target_block.transactions_proofs.iter_mut() {
            for message in tx.messages.iter_mut() {
                message.cc_id.id = "invalid".to_string().try_into().unwrap();
            }
        }
    }

    fn assert_invalid_messages(messages: &[Message], res: &Vec<(Message, Result<()>)>) {
        assert!(res.len() > 0);
        assert_eq!(res.len(), messages.len());
        for (index, message) in messages.iter().enumerate() {
            assert_eq!(res[index].0, *message);
            assert_eq!(
                res[index].1.as_ref().unwrap_err().to_string(),
                "Missing ':' in message ID"
            );
        }
    }

    #[test]
    fn test_process_block_proofs() {
        let mut data = get_batched_data().1;

        for target_block in data.target_blocks.iter_mut() {
            let messages = extract_messages_from_block(target_block);

            let res = process_block_proofs(&data.update, target_block);
            assert_valid_messages(&messages, &res);

            corrupt_messages(target_block);
            let messages = extract_messages_from_block(target_block);
            let res = process_block_proofs(&data.update, target_block);
            assert_invalid_messages(&messages, &res);
        }
    }

    #[test]
    fn test_process_batch_data() {
        let (bootstrap, mut data) = get_batched_data();
        let lc = init_lightclient(Some(bootstrap));
        let mut deps = mock_dependencies();

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
