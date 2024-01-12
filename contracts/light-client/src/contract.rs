#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
};
use cw_ownable::{assert_owner, get_ownership, update_ownership};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::{lightclient::LightClient, state::*};
use eyre::Result;

use crate::execute::{self, process_batch_data};
use crate::types::VerificationResult;
use types::common::{ContentVariant, PrimaryKey};
use types::connection_router::Message;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    cw_ownable::initialize_owner(deps.storage, deps.api, Some(info.sender.as_str()))?;

    let mut lc = LightClient::new(&msg.config.chain_config, None, &env);
    lc.bootstrap(&msg.bootstrap).unwrap();

    LIGHT_CLIENT_STATE.save(deps.storage, &lc.state)?;
    CONFIG.save(deps.storage, &msg.config)?;

    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    use ExecuteMsg::*;

    match msg {
        LightClientUpdate(update) => execute::light_client_update(deps, &env, update),
        UpdateConfig(config) => {
            assert_owner(deps.storage, &info.sender)
                .map_err(|e| ContractError::Std(StdError::GenericErr { msg: e.to_string() }))?;
            CONFIG.save(deps.storage, &config)?;
            Ok(Response::new())
        }
        BatchVerificationData(payload) => {
            let state = LIGHT_CLIENT_STATE.load(deps.storage)?;
            let config = CONFIG.load(deps.storage)?;
            let lc = LightClient::new(&config.chain_config, Some(state), &env);

            let results = process_batch_data(deps, &lc, &payload, &config)
                .map_err(|e| ContractError::Std(StdError::GenericErr { msg: e.to_string() }))?;

            Ok(Response::new().set_data(to_json_binary(
                &results
                    .iter()
                    .map(|result| {
                        let key = match &result.0 {
                            ContentVariant::Message(message) => message.key(),
                            ContentVariant::WorkerSet(message) => message.key(),
                        };
                        let status = result
                            .1
                            .as_ref()
                            .map(|_| String::from("OK"))
                            .unwrap_or_else(|e| e.to_string());

                        (key, status)
                    })
                    .collect::<VerificationResult>(),
            )?))
        }
        UpdateOwnership(action) => {
            update_ownership(deps, &env.block, &info.sender, action)
                .map_err(|e| ContractError::Std(StdError::GenericErr { msg: e.to_string() }))?;
            Ok(Response::new())
        }
        VerifyMessages { messages: _ } => Ok(Response::new()),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    use QueryMsg::*;

    match msg {
        LightClientState {} => to_json_binary(&LIGHT_CLIENT_STATE.load(deps.storage)?),
        Config {} => to_json_binary(&CONFIG.load(deps.storage)?),
        IsVerified { messages } => to_json_binary(
            &messages
                .into_iter()
                .map(|message| {
                    let result = VERIFIED_MESSAGES.load(deps.storage, message.hash());
                    (message, result.is_ok())
                })
                .collect::<Vec<(Message, bool)>>(),
        ),
        IsWorkerSetVerified { message } => {
            let result = VERIFIED_WORKER_SETS.load(deps.storage, message.key());
            to_json_binary(&result.is_ok())
        }
        Ownership {} => to_json_binary(&get_ownership(deps.storage)?),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::execute::tests::extract_content_from_block;
    use crate::{
        contract::{execute, instantiate, query},
        lightclient::helpers::test_helpers::*,
        lightclient::LightClient,
        msg::ExecuteMsg,
    };
    use cosmwasm_std::{from_json, testing::mock_env, Addr, Timestamp};
    use cw_multi_test::{App, ContractWrapper, Executor};
    use cw_ownable::{Action, Ownership};
    use types::common::{Config, ContentVariant};
    use types::connection_router::Message;
    use types::consensus::{Bootstrap, FinalityUpdate};
    use types::lightclient::LightClientState;
    use types::proofs::UpdateVariant;
    use types::ssz_rs::Node;
    use types::sync_committee_rs::constants::BlsSignature;

    use crate::msg::{InstantiateMsg, QueryMsg};
    use crate::types::VerificationResult;

    fn deploy(bootstrap: Option<Bootstrap>) -> (App, Addr) {
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
                Addr::unchecked("deployer"),
                &InstantiateMsg {
                    bootstrap: bootstrap.unwrap_or(get_bootstrap()),
                    config: get_config(),
                },
                &[],
                "Contract",
                None,
            )
            .unwrap();

        (app, addr)
    }

    fn get_lc_state(app: &App, addr: &Addr) -> LightClientState {
        app.wrap()
            .query_wasm_smart(addr, &QueryMsg::LightClientState {})
            .unwrap()
    }

    #[test]
    fn test_initialize() {
        let (app, addr) = deploy(None);
        let env = mock_env();
        let bootstrap = get_bootstrap();

        let state = get_lc_state(&app, &addr);

        let mut lc = LightClient::new(&get_config().chain_config, None, &env);
        lc.bootstrap(&bootstrap).unwrap();
        assert_eq!(state, lc.state);
    }

    #[test]
    fn test_light_client_update() {
        let (mut app, addr) = deploy(None);

        let state_before = get_lc_state(&app, &addr);
        let update = get_update(862);
        let resp = app.execute_contract(
            Addr::unchecked("owner"),
            addr.to_owned(),
            &ExecuteMsg::LightClientUpdate(update.clone()),
            &[],
        );
        let state_after_862 = get_lc_state(&app, &addr);

        assert!(resp.is_ok());
        assert_eq!(
            state_after_862,
            LightClientState {
                update_slot: update.finalized_header.beacon.slot,
                next_sync_committee: Some(update.next_sync_committee), // update is from the same period as the bootstrap
                current_sync_committee: state_before.current_sync_committee
            }
        );

        let update = get_update(863);
        let resp = app.execute_contract(
            Addr::unchecked("owner"),
            addr.to_owned(),
            &ExecuteMsg::LightClientUpdate(update.clone()),
            &[],
        );
        let state_after_863 = get_lc_state(&app, &addr);

        assert!(resp.is_ok());
        assert_eq!(
            state_after_863,
            LightClientState {
                update_slot: update.finalized_header.beacon.slot,
                next_sync_committee: Some(update.next_sync_committee),
                current_sync_committee: state_after_862.next_sync_committee.unwrap()
            }
        );
    }

    #[test]
    fn test_invalid_update() {
        let (mut app, addr) = deploy(None);
        let mut update = get_update(862);
        update.sync_aggregate.sync_committee_signature = BlsSignature::default();

        //Call update
        let resp = app.execute_contract(
            Addr::unchecked("owner"),
            addr.to_owned(),
            &ExecuteMsg::LightClientUpdate(update.clone()),
            &[],
        );

        assert!(resp.is_err());
    }

    #[test]
    fn test_batch_verification_success() {
        let (bootstrap, verification_data) = get_batched_data(false, "finality");
        let (mut app, addr) = deploy(Some(bootstrap));
        let contents = verification_data
            .target_blocks
            .iter()
            .flat_map(|target_block| extract_content_from_block(target_block))
            .collect::<Vec<ContentVariant>>();

        let resp = app.execute_contract(
            Addr::unchecked("owner"),
            addr.to_owned(),
            &ExecuteMsg::BatchVerificationData(verification_data),
            &[],
        );
        assert!(resp.is_ok());
        let result: VerificationResult = from_json(&resp.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            result,
            vec![
                (String::from("message:ethereum:0xc57b29866a593b73d15981c961c8e61380d4e471f08f5b58d441fc828e0f8166:6"), String::from("OK")),
                (String::from("workersetmessage:0xcaabfb4729c106140393eaceca29a0d90e5e64297bb9adbec9c3c7d49c9fab61:0"), String::from("OK"))
            ]
        );
        for content in contents {
            match content {
                ContentVariant::Message(m) => {
                    let res: Vec<(Message, bool)> = app
                        .wrap()
                        .query_wasm_smart(
                            &addr,
                            &QueryMsg::IsVerified {
                                messages: vec![m.clone()],
                            },
                        )
                        .unwrap();
                    assert_eq!(res, vec![(m, true)]);
                }
                ContentVariant::WorkerSet(m) => {
                    let res: bool = app
                        .wrap()
                        .query_wasm_smart(&addr, &QueryMsg::IsWorkerSetVerified { message: m })
                        .unwrap();
                    assert!(res);
                }
            };
        }
    }

    #[test]
    fn test_batch_verification_high_level_failure() {
        let (bootstrap, mut verification_data) = get_batched_data(false, "finality");
        let (mut app, addr) = deploy(Some(bootstrap));
        let contents = verification_data
            .target_blocks
            .iter_mut()
            .flat_map(|target_block| extract_content_from_block(target_block))
            .collect::<Vec<ContentVariant>>();

        // break the update
        let mut corrupt_data = verification_data.clone();
        corrupt_data.update = UpdateVariant::Finality(FinalityUpdate::default());

        // execute
        let resp = app.execute_contract(
            Addr::unchecked("owner"),
            addr.to_owned(),
            &ExecuteMsg::BatchVerificationData(corrupt_data),
            &[],
        );

        // assert
        assert!(resp.is_err());
        for content in contents {
            match content {
                ContentVariant::Message(m) => {
                    let res: Vec<(Message, bool)> = app
                        .wrap()
                        .query_wasm_smart(
                            &addr,
                            &QueryMsg::IsVerified {
                                messages: vec![m.clone()],
                            },
                        )
                        .unwrap();
                    assert_eq!(res, vec![(m.clone(), false)]);
                }
                ContentVariant::WorkerSet(m) => {
                    let res: bool = app
                        .wrap()
                        .query_wasm_smart(
                            &addr,
                            &QueryMsg::IsWorkerSetVerified { message: m.clone() },
                        )
                        .unwrap();
                    assert_eq!(res, false);
                }
            };
        }
    }

    #[test]
    fn test_batch_verification_content_failure() {
        let (bootstrap, mut verification_data) = get_batched_data(false, "finality");
        let (mut app, addr) = deploy(Some(bootstrap));
        let contents = verification_data
            .target_blocks
            .iter_mut()
            .flat_map(|target_block| extract_content_from_block(target_block))
            .collect::<Vec<ContentVariant>>();

        // break the transaction proof of the first content
        verification_data.target_blocks[0].transactions_proofs[0]
            .transaction_proof
            .transaction_proof = vec![Node::default(); 32];

        // execute
        let resp = app.execute_contract(
            Addr::unchecked("owner"),
            addr.to_owned(),
            &ExecuteMsg::BatchVerificationData(verification_data),
            &[],
        );

        // assert
        assert!(resp.is_ok());
        let result: VerificationResult = from_json(&resp.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            result,
            vec![
                (String::from("message:ethereum:0xc57b29866a593b73d15981c961c8e61380d4e471f08f5b58d441fc828e0f8166:6"), String::from("Invalid transaction proof")),
                (String::from("workersetmessage:0xcaabfb4729c106140393eaceca29a0d90e5e64297bb9adbec9c3c7d49c9fab61:0"), String::from("OK"))
            ]
        );
        for (_index, content) in contents.iter().enumerate() {
            match content {
                // this is the first content, with the broken transaction proof
                ContentVariant::Message(m) => {
                    let res: Vec<(Message, bool)> = app
                        .wrap()
                        .query_wasm_smart(
                            &addr,
                            &QueryMsg::IsVerified {
                                messages: vec![m.clone()],
                            },
                        )
                        .unwrap();
                    assert_eq!(res, vec![(m.clone(), false)]);
                }
                // the second content should be validated
                ContentVariant::WorkerSet(m) => {
                    let res: bool = app
                        .wrap()
                        .query_wasm_smart(
                            &addr,
                            &QueryMsg::IsWorkerSetVerified { message: m.clone() },
                        )
                        .unwrap();
                    assert!(res);
                }
            };
        }
    }

    #[test]
    fn test_config_query() {
        let (app, addr) = deploy(None);

        let config: Config = app
            .wrap()
            .query_wasm_smart(addr, &QueryMsg::Config {})
            .unwrap();
        assert_eq!(config, get_config());
    }

    #[test]
    fn test_ownership() {
        let (mut app, addr) = deploy(None);

        let res: Ownership<Addr> = app
            .wrap()
            .query_wasm_smart(&addr, &QueryMsg::Ownership {})
            .unwrap();
        assert_eq!(res.owner.unwrap(), "deployer");

        // old owner proposes new owner
        let resp = app.execute_contract(
            Addr::unchecked("deployer"),
            addr.to_owned(),
            &ExecuteMsg::UpdateOwnership(Action::TransferOwnership {
                new_owner: String::from("new_owner"),
                expiry: None,
            }),
            &[],
        );
        assert!(resp.is_ok());

        // new owner accepts
        let resp = app.execute_contract(
            Addr::unchecked("new_owner"),
            addr.to_owned(),
            &ExecuteMsg::UpdateOwnership(Action::AcceptOwnership {}),
            &[],
        );
        assert!(resp.is_ok());

        let res: Ownership<Addr> = app
            .wrap()
            .query_wasm_smart(&addr, &QueryMsg::Ownership {})
            .unwrap();
        assert_eq!(res.owner.unwrap(), "new_owner");
    }

    #[test]
    fn test_update_config() {
        let (mut app, addr) = deploy(None);
        let default_config = get_config();
        let mut new_config = get_config();

        let config_query: Config = app
            .wrap()
            .query_wasm_smart(&addr, &QueryMsg::Config {})
            .unwrap();
        assert_eq!(config_query, default_config);

        // random use should not be able to update config
        new_config.gateway_address = String::from("new_gateway");
        assert!(app
            .execute_contract(
                Addr::unchecked("some_user"),
                addr.to_owned(),
                &ExecuteMsg::UpdateConfig(new_config.clone()),
                &[],
            )
            .is_err());

        // verify that config was not updated
        let config_query: Config = app
            .wrap()
            .query_wasm_smart(&addr, &QueryMsg::Config {})
            .unwrap();
        assert_eq!(config_query, default_config);

        // owner should be able to update config
        assert!(app
            .execute_contract(
                Addr::unchecked("deployer"),
                addr.to_owned(),
                &ExecuteMsg::UpdateConfig(new_config.clone()),
                &[],
            )
            .is_ok());

        // verify that config was updated
        let config_query: Config = app
            .wrap()
            .query_wasm_smart(&addr, &QueryMsg::Config {})
            .unwrap();
        assert_eq!(config_query, new_config.clone());
    }
}
