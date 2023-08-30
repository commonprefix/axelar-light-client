#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::{state::*, verifier};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let state = verifier::bootstrap(msg.bootstrap.clone())?;
    LIGHT_CLIENT_STATE.save(deps.storage, &state)?;

    CONFIG.save(deps.storage, &msg.config)?;
    BOOTSTRAP.save(deps.storage, &msg.bootstrap)?;

    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    use ExecuteMsg::*;

    match msg {
        Update { period, update } => execute::update(deps, period, update),
    }
}

mod execute {
    use crate::types::Update;

    use super::*;

    pub fn update(deps: DepsMut, period: u64, update: Update) -> Result<Response, ContractError> {
        let resp = UPDATES.may_load(deps.storage, period)?;
        if resp.is_some() {
            return Err(ContractError::UpdateAlreadyExists {});
        }

        UPDATES.save(deps.storage, period, &update)?;
        Ok(Response::new())
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    use QueryMsg::*;

    match msg {
        Greet {} => to_binary(&query::greet()?),
        Bootstrap {} => to_binary(&BOOTSTRAP.load(deps.storage)?),
        Update { period } => to_binary(&query::update(deps, period)?),
        LightClientState {} => to_binary(&LIGHT_CLIENT_STATE.load(deps.storage)?),
    }
}

mod query {
    use super::*;
    use crate::types::Update;

    pub fn greet() -> StdResult<String> {
        Ok("Hello, world!".to_string())
    }

    pub fn update(deps: Deps, period: u64) -> StdResult<Update> {
        UPDATES.load(deps.storage, period)
    }

    // pub fn genesis_committee(deps: Deps) {
    //     return GENESIS_COMMITTEE.load(deps.storage)
    // }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use crate::{
        contract::{execute, instantiate, query},
        msg::ExecuteMsg,
        types::{ChainConfig, LightClientState, Update},
        verifier,
    };
    use cosmwasm_std::{Addr, StdError};
    use cw_multi_test::{App, ContractWrapper, Executor};

    use crate::{
        msg::{InstantiateMsg, QueryMsg},
        types::Bootstrap,
    };

    fn get_bootstrap() -> Bootstrap {
        let file = File::open("testdata/bootstrap.json").unwrap();
        let bootstrap: Bootstrap = serde_json::from_reader(file).unwrap();

        return bootstrap;
    }

    // Currently have in testdata: 767.json
    fn get_update(period: u64) -> Update {
        let path = format!("testdata/{}.json", period);
        let file = File::open(path).unwrap();
        let update: Update = serde_json::from_reader(file).unwrap();

        return update;
    }

    fn get_config() -> ChainConfig {
        return ChainConfig {
            chain_id: 1,
            genesis_time: 1606824023,
        };
    }

    #[test]
    fn test_initialize() {
        let mut app = App::default();

        let code = ContractWrapper::new(execute, instantiate, query);
        let code_id = app.store_code(Box::new(code));

        let bootstrap = get_bootstrap();

        let addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("owner"),
                &InstantiateMsg {
                    bootstrap: bootstrap.clone(),
                    config: get_config(),
                },
                &[],
                "Contract",
                None,
            )
            .unwrap();

        let resp: Bootstrap = app
            .wrap()
            .query_wasm_smart(addr.clone(), &QueryMsg::Bootstrap {})
            .unwrap();

        assert_eq!(resp, bootstrap);

        let resp: LightClientState = app
            .wrap()
            .query_wasm_smart(addr.clone(), &QueryMsg::LightClientState {})
            .unwrap();

        let state = verifier::bootstrap(bootstrap).unwrap();
        assert_eq!(resp, state)
    }

    #[test]
    fn test_update() {
        // Open and parse JSON

        let mut app = App::default();

        let code = ContractWrapper::new(execute, instantiate, query);
        let code_id = app.store_code(Box::new(code));

        let bootstrap = get_bootstrap();

        let addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("owner"),
                &InstantiateMsg {
                    bootstrap: bootstrap,
                    config: get_config(),
                },
                &[],
                "Contract",
                None,
            )
            .unwrap();

        let update = get_update(767);

        //Call update
        let resp = app.execute_contract(
            Addr::unchecked("owner"),
            addr.to_owned(),
            &ExecuteMsg::Update {
                period: 767,
                update: update.clone(),
            },
            &[],
        );

        assert!(resp.is_ok());

        let resp: Update = app
            .wrap()
            .query_wasm_smart(addr.to_owned(), &QueryMsg::Update { period: 767 })
            .unwrap();

        assert_eq!(resp, update);

        // Call update with wrong period
        let resp = app.execute_contract(
            Addr::unchecked("owner"),
            addr.to_owned(),
            &ExecuteMsg::Update {
                period: 767,
                update: update.clone(),
            },
            &[],
        );

        assert!(resp.is_err());

        // Query update with wrong period
        let resp: Result<Update, StdError> = app
            .wrap()
            .query_wasm_smart(addr.to_owned(), &QueryMsg::Update { period: 768 });

        assert!(resp.is_err());
    }
}
