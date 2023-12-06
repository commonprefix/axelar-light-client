pub mod execute {
    use crate::ContractError;
    use cosmwasm_std::{DepsMut, Env, Response, StdResult};
    use eyre::Result;
    use ssz_rs::{
        get_generalized_index, verify_merkle_proof, GeneralizedIndex, Merkleized, Node,
        SszVariableOrIndex, Vector,
    };
    use sync_committee_rs::constants::SLOTS_PER_HISTORICAL_ROOT;
    use types::lightclient::MessageVerification;
    use types::proofs::{AncestryProof, UpdateVariant};
    use types::{common::Forks, consensus::Update, execution::ReceiptLogs};

    use crate::lightclient::helpers::{verify_message, verify_trie_proof};
    use crate::lightclient::{LightClient, Verification};
    use crate::state::{CONFIG, LIGHT_CLIENT_STATE, SYNC_COMMITTEE};

    use super::*;

    pub fn process_verification_data(
        lightclient: &LightClient,
        data: &MessageVerification,
    ) -> Result<()> {
        let message = &data.message;
        let proofs = &data.proofs;

        // Get recent block
        let recent_block = match proofs.update.clone() {
            UpdateVariant::Finality(update) => {
                update.verify(lightclient)?;
                update.finalized_header.beacon
            }
            UpdateVariant::Optimistic(update) => {
                update.verify(lightclient)?;
                update.attested_header.beacon
            }
        };

        let target_block_root = proofs.target_block.clone().hash_tree_root()?;

        // Verify ancestry proof
        match proofs.ancestry_proof.clone() {
            AncestryProof::BlockRoots {
                block_roots_index,
                block_root_proof,
            } => {
                let valid_block_root_proof = verify_merkle_proof(
                    &target_block_root,
                    block_root_proof.as_slice(),
                    &GeneralizedIndex(block_roots_index as usize),
                    &recent_block.state_root,
                );

                if !valid_block_root_proof {
                    return Err(ContractError::InvalidBlockRootsProof.into());
                }
            }
            AncestryProof::HistoricalRoots {
                block_root_proof,
                block_summary_root_proof,
                block_summary_root,
                block_summary_root_gindex,
            } => {
                let block_root_index =
                    proofs.target_block.slot as usize % SLOTS_PER_HISTORICAL_ROOT;
                let block_root_gindex = get_generalized_index(
                    &Vector::<Node, SLOTS_PER_HISTORICAL_ROOT>::default(),
                    &[SszVariableOrIndex::Index(block_root_index)],
                );

                let valid_block_root_proof = verify_merkle_proof(
                    &target_block_root,
                    block_root_proof.as_slice(),
                    &GeneralizedIndex(block_root_gindex),
                    &block_summary_root,
                );

                if !valid_block_root_proof {
                    return Err(ContractError::InvalidBlockRootsProof.into());
                }

                let valid_block_summary_root_proof = verify_merkle_proof(
                    &block_summary_root,
                    block_summary_root_proof.as_slice(),
                    &GeneralizedIndex(block_summary_root_gindex as usize),
                    &recent_block.state_root,
                );

                if !valid_block_summary_root_proof {
                    return Err(ContractError::InvalidBlockSummaryRootProof.into());
                }
            }
        }

        // Verify receipt proof
        let receipt_option = verify_trie_proof(
            proofs.receipt_proof.receipts_root,
            proofs.transaction_proof.transaction_index,
            proofs.receipt_proof.receipt_proof.clone(),
        );

        let receipt = match receipt_option {
            Some(s) => s,
            None => return Err(ContractError::InvalidReceiptProof.into()),
        };

        let valid_receipts_root = verify_merkle_proof(
            &proofs.receipt_proof.receipts_root,
            &proofs.receipt_proof.receipts_root_proof,
            &GeneralizedIndex(3219), // TODO
            &target_block_root,
        );

        if !valid_receipts_root {
            return Err(ContractError::InvalidReceiptsBranchProof.into());
        }

        // Verify transaction proof
        let valid_transaction = verify_merkle_proof(
            &proofs
                .transaction_proof
                .transaction
                .clone()
                .hash_tree_root()?,
            proofs.transaction_proof.transaction_proof.as_slice(),
            &GeneralizedIndex(proofs.transaction_proof.transaction_gindex as usize),
            &target_block_root,
        );

        if !valid_transaction {
            return Err(ContractError::InvalidTransactionProof.into());
        }

        let logs: ReceiptLogs = alloy_rlp::Decodable::decode(&mut &receipt[..]).unwrap();
        for log in logs.0.iter() {
            if verify_message(message, log, &proofs.transaction_proof.transaction) {
                return Ok(());
            }
        }
        Err(ContractError::InvalidMessage.into())
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

    pub fn update_forks(deps: DepsMut, forks: Forks) -> Result<Response, ContractError> {
        CONFIG.update(deps.storage, |mut config| -> StdResult<_> {
            config.forks = forks;
            Ok(config)
        })?;
        Ok(Response::new())
    }
}

#[cfg(test)]
mod tests {
    use crate::execute::execute;
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
