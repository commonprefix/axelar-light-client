#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
};

use crate::error::ContractError;
use crate::lightclient::helpers::calc_sync_period;
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
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let mut lc = LightClient::new(&msg.config.chain_config, None, &env);
    lc.bootstrap(&msg.bootstrap).unwrap();

    LIGHT_CLIENT_STATE.save(deps.storage, &lc.state)?;
    CONFIG.save(deps.storage, &msg.config)?;

    let period = calc_sync_period(msg.bootstrap.header.beacon.slot);
    SYNC_COMMITTEE.save(
        deps.storage,
        &(msg.bootstrap.current_sync_committee, period),
    )?;

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
        LightClientUpdate { update } => execute::light_client_update(deps, &env, update),
        BatchVerificationData { payload } => {
            let state = LIGHT_CLIENT_STATE.load(deps.storage)?;
            let config = CONFIG.load(deps.storage)?;
            let lc = LightClient::new(&config.chain_config, Some(state), &env);

            let results = process_batch_data(deps, &lc, &payload);
            if let Err(err) = results {
                return Err(ContractError::Std(StdError::GenericErr {
                    msg: err.to_string(),
                }));
            }

            Ok(Response::new().set_data(to_json_binary(
                &results
                    .unwrap()
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
        VerifyMessages {
            messages: _messages,
        } => Ok(Response::new()),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    use QueryMsg::*;

    match msg {
        LightClientState {} => to_json_binary(&LIGHT_CLIENT_STATE.load(deps.storage)?),
        Config {} => to_json_binary(&CONFIG.load(deps.storage)?),
        SyncCommittee {} => {
            let sync_committee = &SYNC_COMMITTEE.load(deps.storage)?;
            to_json_binary(&sync_committee)
        }
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
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{
        contract::{execute, instantiate, query},
        lightclient::helpers::test_helpers::*,
        lightclient::LightClient,
        msg::ExecuteMsg,
    };
    use cosmwasm_std::{testing::mock_env, Addr, Timestamp};
    use cw_multi_test::{App, ContractWrapper, Executor};
    use types::lightclient::LightClientState;
    use types::sync_committee_rs::constants::BlsSignature;

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
    fn test_initialize() {
        let (app, addr) = deploy();
        let env = mock_env();
        let bootstrap = get_bootstrap();

        let resp: LightClientState = app
            .wrap()
            .query_wasm_smart(addr, &QueryMsg::LightClientState {})
            .unwrap();

        let mut lc = LightClient::new(&get_config().chain_config, None, &env);
        lc.bootstrap(&bootstrap).unwrap();
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
                update: update.clone(),
            },
            &[],
        );

        assert!(resp.is_err());
    }
}
