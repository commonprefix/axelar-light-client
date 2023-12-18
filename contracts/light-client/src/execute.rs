use crate::ContractError;
use cosmwasm_std::{DepsMut, Env, Response};
use eyre::{eyre, Result};
use types::common::ChainConfig;
use types::execution::ReceiptLogs;
use types::lightclient::MessageVerification;
use types::proofs::{BatchMessageProof, BlockLevelVerificationData, Message};
use types::ssz_rs::{Merkleized, Node};
use types::sync_committee_rs::consensus_types::Transaction;
use types::sync_committee_rs::constants::MAX_BYTES_PER_TRANSACTION;
use types::{common::Forks, consensus::Update};

use crate::lightclient::helpers::{
    compare_message_with_log, extract_logs_from_receipt_proof, verify_ancestry_proof,
    verify_transaction_proof,
};
use crate::lightclient::LightClient;
use crate::state::{CONFIG, LIGHT_CLIENT_STATE, SYNC_COMMITTEE};

pub fn verify_message(
    message: &Message,
    transaction: &Transaction<MAX_BYTES_PER_TRANSACTION>,
    logs: &ReceiptLogs,
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

    compare_message_with_log(message, log, &transaction)?;

    Ok(())
}

pub fn verify_block_level_proofs(
    data: &BlockLevelVerificationData,
    target_block_root: &Node,
) -> Vec<(Message, Result<()>)> {
    let result = verify_transaction_proof(&data.transaction_proof, &target_block_root)
        .and_then(|_| {
            extract_logs_from_receipt_proof(
                &data.receipt_proof,
                data.transaction_proof.transaction_index,
                &target_block_root,
            )
        })
        .and_then(|logs| {
            Ok(data
                .messages
                .iter()
                .map(|message| {
                    (
                        message.to_owned(),
                        verify_message(message, &data.transaction_proof.transaction, &logs),
                    )
                })
                .collect::<Vec<(Message, Result<()>)>>())
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

pub fn process_batch_verification_data(
    lightclient: &LightClient,
    data: &BatchMessageProof,
) -> Vec<(Message, Result<()>)> {
    let proofs = &data.proofs;

    let mut target_block_root = Node::default();
    let mut ancestry_proof_verification = || -> Result<()> {
        let recent_block = lightclient.extract_recent_block(&data.update)?;
        target_block_root = data.target_block.clone().hash_tree_root()?;

        verify_ancestry_proof(&data.ancestry_proof, &data.target_block, &recent_block)?;
        Ok(())
    };

    match ancestry_proof_verification() {
        Ok(_) => proofs
            .iter()
            .flat_map(|proof| verify_block_level_proofs(proof, &target_block_root))
            .collect(),
        Err(err) => proofs
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

pub fn process_verification_data(
    lightclient: &LightClient,
    data: &MessageVerification,
) -> Result<()> {
    let message = &data.message;
    let proofs = &data.proofs;

    let recent_block = lightclient.extract_recent_block(&proofs.update)?;
    let target_block_root = proofs.target_block.clone().hash_tree_root()?;

    verify_ancestry_proof(&proofs.ancestry_proof, &proofs.target_block, &recent_block)?;
    verify_transaction_proof(&proofs.transaction_proof, &target_block_root)?;

    let logs = extract_logs_from_receipt_proof(
        &proofs.receipt_proof,
        proofs.transaction_proof.transaction_index,
        &target_block_root,
    )?;

    let log_index_str = message.cc_id.id.split(':').nth(1).unwrap();
    let log_index: usize = log_index_str.parse()?;
    compare_message_with_log(
        message,
        logs.0.get(log_index).unwrap(),
        &proofs.transaction_proof.transaction,
    )?;
    Ok(())
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
    use crate::execute;
    use crate::lightclient::helpers::test_helpers::{
        get_verification_data_with_block_roots, get_verification_data_with_historical_roots,
    };
    use crate::lightclient::tests::tests::init_lightclient;

    #[test]
    fn test_verification_with_historical_roots() {
        let data = get_verification_data_with_historical_roots();
        let lightclient = init_lightclient(Some(data.0));
        let res = execute::process_verification_data(&lightclient, &data.1);
        println!("{res:?}");
        assert!(res.is_ok());
    }

    #[test]
    fn test_verification_with_block_roots() {
        let data = get_verification_data_with_block_roots();
        let lightclient = init_lightclient(Some(data.0));
        let res = execute::process_verification_data(&lightclient, &data.1);
        println!("{res:?}");
        assert!(res.is_ok());
    }
}
