use crate::ContractError;
use cosmwasm_std::{DepsMut, Env, Response};
use eyre::Result;
use types::common::ChainConfig;
use types::lightclient::MessageVerification;
use types::proofs::{BatchMessageProof, Message};
use types::ssz_rs::Merkleized;
use types::{common::Forks, consensus::Update};

use crate::lightclient::helpers::{
    extract_logs_from_receipt_proof, verify_ancestry_proof, verify_message,
    verify_transaction_proof,
};
use crate::lightclient::LightClient;
use crate::state::{CONFIG, LIGHT_CLIENT_STATE, SYNC_COMMITTEE};

pub fn process_batch_verification_data(
    lightclient: &LightClient,
    data: &BatchMessageProof,
) -> Result<Vec<Message>> {
    let mut verified: Vec<Message> = vec![];
    let proofs = &data.proofs;

    let recent_block = lightclient.extract_recent_block(&data.update)?;
    let target_block_root = data.target_block.clone().hash_tree_root()?;

    verify_ancestry_proof(&data.ancestry_proof, &data.target_block, &recent_block)?;

    for proof in proofs.into_iter() {
        // TODO: wrap everything in something like a try catch
        let transaction_proof_res =
            verify_transaction_proof(&proof.transaction_proof, &target_block_root);

        if transaction_proof_res.is_err() {
            // process the next transaction proof
            continue;
        }

        // TODO: improve syntax
        let receipt_verification_res = extract_logs_from_receipt_proof(
            &proof.receipt_proof,
            proof.transaction_proof.transaction_index,
            &target_block_root,
        );

        if receipt_verification_res.is_err() {
            continue;
        }

        // TODO: handle all unwraps gracefully
        let logs = receipt_verification_res.unwrap();
        for message in (&proof.messages).into_iter() {
            let log_index_str = message.cc_id.id.split(':').nth(1).unwrap();
            let log_index: usize = log_index_str.parse()?;
            let log = logs.0.get(log_index).unwrap();

            let verification_result =
                verify_message(&message, log, &proof.transaction_proof.transaction);

            if verification_result.is_err() {
                continue;
            }

            verified.push(message.clone()); // TODO: try not cloning
        }
    }

    Ok(verified)
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
    verify_message(
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
