#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Reply, Response, StdResult,
};
use types::lightclient::{EventVerificationData, Message};

use crate::error::ContractError;
use crate::lightclient::helpers::calc_sync_period;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::{lightclient::LightClient, state::*};
use eyre::Result;

use cw2::{self, set_contract_version};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let mut lc = LightClient::new(&msg.config, None, &env);
    lc.bootstrap(msg.bootstrap.clone()).unwrap();

    LIGHT_CLIENT_STATE.save(deps.storage, &lc.state)?;
    CONFIG.save(deps.storage, &msg.config)?;

    let period = calc_sync_period(msg.bootstrap.header.beacon.slot);
    SYNC_COMMITTEES.save(deps.storage, period, &msg.bootstrap.current_sync_committee)?;

    // TODO: Use commit hash or something else
    cw2::set_contract_version(deps.storage, "lightclient", "1")?;

    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    use ExecuteMsg::*;

    match msg {
        LightClientUpdate { period, update } => {
            execute::light_client_update(deps, &env, period, update)
        }
        // TODO: only admin should do that
        UpdateForks { forks } => execute::update_forks(deps, forks),
        VerifyBlock { verification_data } => execute::verify_block(&deps, &env, verification_data),
        verification_request @ VerifyProof { .. } => execute::verify_proof(verification_request),
        VerifyTopicInclusion { receipt, topic } => execute::verify_topic_inclusion(receipt, topic),
        EventVerificationData { payload } => {
            let state = LIGHT_CLIENT_STATE.load(deps.storage)?;
            let config = CONFIG.load(deps.storage)?;
            let lc = LightClient::new(&config, Some(state), &env);
            if execute::process_verification_data(&lc, &payload).is_err() {
                return Err(ContractError::InvalidVerificationData);
            }
            VERIFIED_MESSAGES.save(deps.storage, payload.message.hash_id(), &payload.message)?;
            Ok(Response::new())
        }
        VerifyMessages {
            messages: _messages,
        } => Ok(Response::new()),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(_deps: DepsMut, _env: Env, msg: Reply) -> Result<Response, ContractError> {
    Ok(Response::new().add_attribute(msg.id.to_string(), "somevalue"))
}

mod execute {
    use cosmwasm_std::{to_json_binary, StdResult, WasmMsg};
    use ssz_rs::{verify_merkle_proof, GeneralizedIndex, Merkleized};
    use types::proofs::AncestryProof;
    use types::{
        common::Forks,
        consensus::Update,
        execution::ReceiptLogs,
        lightclient::{BlockVerificationData, UpdateVariant},
    };

    use crate::lightclient::helpers::{verify_message, verify_trie_proof};
    use crate::lightclient::Verification;

    use super::*;

    pub fn process_verification_data(
        lightclient: &LightClient,
        data: &EventVerificationData,
    ) -> Result<()> {
        // Get recent block
        let recent_block = match data.update.clone() {
            UpdateVariant::Finality(update) => {
                update.verify(lightclient)?;
                update.finalized_header.beacon
            }
            UpdateVariant::Optimistic(update) => {
                update.verify(lightclient)?;
                update.attested_header.beacon
            }
        };

        let target_block_root = data.target_block.clone().hash_tree_root()?;

        // Verify ancestry proof
        match data.ancestry_proof.clone() {
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
                block_roots_proof: _,
                historical_batch_proof: _,
                historical_roots_proof: _,
                historical_roots_index: _,
                historical_roots_branch: _,
            } => {
                todo!()
            }
        }

        // Verify receipt proof
        let receipt_option = verify_trie_proof(
            data.receipt_proof.receipts_root,
            data.receipt_proof.transaction_index,
            data.receipt_proof.receipt_proof.clone(),
        );

        let receipt = match receipt_option {
            Some(s) => s,
            None => return Err(ContractError::InvalidReceiptProof.into()),
        };

        let valid_receipts_root = verify_merkle_proof(
            &data.receipt_proof.receipts_root,
            &data.receipt_proof.receipts_branch,
            &GeneralizedIndex(3219), // TODO
            &target_block_root,
        );

        if !valid_receipts_root {
            return Err(ContractError::InvalidReceiptsBranchProof.into());
        }

        // Verify transaction proof
        let valid_transaction = verify_merkle_proof(
            &data.receipt_proof.transaction.clone().hash_tree_root()?,
            data.receipt_proof.transaction_branch.as_slice(),
            &GeneralizedIndex(data.receipt_proof.transaction_gindex as usize),
            &target_block_root,
        );

        if !valid_transaction {
            return Err(ContractError::InvalidTransactionProof.into());
        }

        let logs: ReceiptLogs = alloy_rlp::Decodable::decode(&mut &receipt[..]).unwrap();
        for log in logs.0.iter() {
            if verify_message(&data.message, log, &data.receipt_proof.transaction) {
                return Ok(());
            }
        }
        Err(ContractError::InvalidMessage.into())
    }

    pub fn verify_proof(msg: ExecuteMsg) -> Result<Response, ContractError> {
        let message = WasmMsg::Execute {
            contract_addr: String::from(
                "axelar1awkf64kxnu07z0rljnryfajh5yl78c6cn2jzhwlgcw699ux6rfpsksuasf",
            ),
            msg: to_json_binary(&msg)?,
            funds: vec![],
        };
        Ok(Response::new().add_message(message))
    }

    pub fn verify_topic_inclusion(
        receipt: Vec<u8>,
        topic: Vec<u8>,
    ) -> Result<Response, ContractError> {
        let logs: ReceiptLogs = alloy_rlp::Decodable::decode(&mut &receipt[..]).unwrap();

        let is_included = logs.contains_topic(&topic[..]);
        Ok(Response::new().add_attribute("result", is_included.to_string()))
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

        SYNC_COMMITTEES.save(deps.storage, period + 1, &update.next_sync_committee)?;
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

    pub fn verify_block(
        deps: &DepsMut,
        env: &Env,
        ver_data: BlockVerificationData,
    ) -> Result<Response, ContractError> {
        let state = LIGHT_CLIENT_STATE.load(deps.storage)?;
        let config = CONFIG.load(deps.storage)?;
        let lc = LightClient::new(&config, Some(state), env);

        let sync_committee =
            SYNC_COMMITTEES.load(deps.storage, calc_sync_period(ver_data.sig_slot));
        if sync_committee.is_err() {
            return Err(ContractError::NoSyncCommittee {
                period: calc_sync_period(ver_data.sig_slot),
            });
        }

        let res = lc.verify_block(
            &sync_committee.unwrap(),
            &ver_data.target_block,
            &ver_data.intermediate_chain,
            &ver_data.sync_aggregate,
            ver_data.sig_slot,
        );

        if res {
            Ok(Response::new().add_attribute("result", "ok"))
        } else {
            Ok(Response::new().add_attribute("result", "err"))
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    use QueryMsg::*;

    match msg {
        Greet {} => to_json_binary(&query::greet()?),
        LightClientState {} => to_json_binary(&LIGHT_CLIENT_STATE.load(deps.storage)?),
        Config {} => to_json_binary(&CONFIG.load(deps.storage)?),
        SyncCommittee { period } => {
            let sync_committee = &SYNC_COMMITTEES.load(deps.storage, period)?;
            to_json_binary(&sync_committee)
        }
        Version {} => to_json_binary(&VERSION.load(deps.storage)?),
        IsVerified { messages } => to_json_binary(
            &messages
                .into_iter()
                .map(|message| {
                    let result = VERIFIED_MESSAGES.load(deps.storage, message.hash_id());
                    (message, result.is_ok())
                })
                .collect::<Vec<(Message, bool)>>(),
        ),
    }
}

mod query {
    use super::*;

    pub fn greet() -> StdResult<String> {
        Ok("Hello, world!".to_string())
    }
}

#[entry_point]
pub fn migrate(deps: DepsMut, _env: Env, _msg: Empty) -> Result<Response, ContractError> {
    let contract_info = cw2::get_contract_version(deps.storage).unwrap();
    set_contract_version(
        deps.storage,
        contract_info.contract,
        (contract_info.version.parse::<u64>().unwrap() + 1).to_string(),
    )?;
    Ok(Response::default())
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{
        contract::{execute, instantiate, query},
        lightclient::helpers::test_helpers::*,
        lightclient::LightClient,
        lightclient::{helpers::hex_str_to_bytes, tests::tests::init_lightclient},
        msg::ExecuteMsg,
    };
    use cosmwasm_std::{testing::mock_env, Addr, Timestamp};
    use cw_multi_test::{App, ContractWrapper, Executor};
    use serde::Serialize;
    use sync_committee_rs::constants::BlsSignature;
    use types::{
        common::{ChainConfig, Fork, Forks},
        lightclient::LightClientState,
    };

    use crate::msg::{InstantiateMsg, QueryMsg};

    fn deploy() -> (App, Addr) {
        let mut app = App::default();

        let code = ContractWrapper::new(execute, instantiate, query);
        let code_id = app.store_code(Box::new(code));

        app.update_block(|block| {
            block.time = Timestamp::from_seconds(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            );
        });

        let addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("owner"),
                &InstantiateMsg {
                    bootstrap: get_bootstrap(),
                    config: get_config(),
                },
                &[],
                "Contract",
                None,
            )
            .unwrap();

        (app, addr)
    }

    #[test]
    fn test_data() {
        let lightclient = init_lightclient();
        let data = get_event_verification_data();
        let res = execute::process_verification_data(&lightclient, &data);
        println!("{res:?}");
        assert!(res.is_ok());
    }

    #[test]
    fn test_verify() {
        assert!(false);
    }

    #[test]
    fn test_topic_inclusion() {
        let (mut app, addr) = deploy();
        let mut request = get_topic_inclusion_query();
        let mut resp = app
            .execute_contract(
                Addr::unchecked("owner"),
                addr.to_owned(),
                &ExecuteMsg::VerifyTopicInclusion {
                    receipt: request.receipt.clone(),
                    topic: request.topic.clone(),
                },
                &[],
            )
            .unwrap();

        let wasm = resp.events.iter().find(|ev| ev.ty == "wasm").unwrap();
        assert_eq!(
            wasm.attributes
                .iter()
                .find(|attr| attr.key == "result")
                .unwrap()
                .value,
            "true"
        );

        request.topic[0] = request.topic[0] + 1; // modify a random byte
        resp = app
            .execute_contract(
                Addr::unchecked("owner"),
                addr.to_owned(),
                &ExecuteMsg::VerifyTopicInclusion {
                    receipt: request.receipt.clone(),
                    topic: request.topic.clone(),
                },
                &[],
            )
            .unwrap();

        let wasm = resp.events.iter().find(|ev| ev.ty == "wasm").unwrap();
        assert_eq!(
            wasm.attributes
                .iter()
                .find(|attr| attr.key == "result")
                .unwrap()
                .value,
            "false"
        );
    }

    #[test]
    fn test_initialize() {
        let (app, addr) = deploy();
        let env = mock_env();
        let bootstrap = get_bootstrap();

        let resp: LightClientState = app
            .wrap()
            .query_wasm_smart(addr, &QueryMsg::LightClientState {})
            .unwrap();

        let mut lc = LightClient::new(&get_config(), None, &env);
        lc.bootstrap(bootstrap).unwrap();
        assert_eq!(resp, lc.state)
    }

    #[test]
    fn test_light_client_update() {
        let (mut app, addr) = deploy();

        let update = get_update(862);
        let resp = app.execute_contract(
            Addr::unchecked("owner"),
            addr.to_owned(),
            &ExecuteMsg::LightClientUpdate {
                period: 862,
                update: update.clone(),
            },
            &[],
        );

        assert!(resp.is_ok());

        let update = get_update(863);
        let resp = app.execute_contract(
            Addr::unchecked("owner"),
            addr.to_owned(),
            &ExecuteMsg::LightClientUpdate {
                period: 863,
                update: update.clone(),
            },
            &[],
        );

        assert!(resp.is_ok());
    }

    #[test]
    fn test_invalid_update() {
        let (mut app, addr) = deploy();
        let mut update = get_update(862);
        update.sync_aggregate.sync_committee_signature = BlsSignature::default();

        //Call update
        let resp = app.execute_contract(
            Addr::unchecked("owner"),
            addr.to_owned(),
            &ExecuteMsg::LightClientUpdate {
                period: 862,
                update: update.clone(),
            },
            &[],
        );

        assert!(resp.is_err());
    }

    #[test]
    fn test_forks_query() {
        let (app, addr) = deploy();
        let resp: ChainConfig = app
            .wrap()
            .query_wasm_smart(addr, &QueryMsg::Config {})
            .unwrap();

        assert_eq!(resp.forks, get_forks());
    }

    #[test]
    fn test_forks_update() {
        let (mut app, addr) = deploy();
        let new_forks = Forks {
            genesis: Fork {
                epoch: 0,
                fork_version: hex_str_to_bytes("0x03000000").unwrap().try_into().unwrap(),
            },
            altair: Fork {
                epoch: 1,
                fork_version: hex_str_to_bytes("0x02000000").unwrap().try_into().unwrap(),
            },
            bellatrix: Fork {
                epoch: 2,
                fork_version: hex_str_to_bytes("0x01000000").unwrap().try_into().unwrap(),
            },
            capella: Fork {
                epoch: 3,
                fork_version: hex_str_to_bytes("0x00000000").unwrap().try_into().unwrap(),
            },
        };

        app.execute_contract(
            Addr::unchecked("owner"),
            addr.clone(),
            &ExecuteMsg::UpdateForks {
                forks: new_forks.clone(),
            },
            &[],
        )
        .unwrap();

        let resp: ChainConfig = app
            .wrap()
            .query_wasm_smart(addr, &QueryMsg::Config {})
            .unwrap();

        assert_eq!(resp.forks, new_forks);
    }
}
