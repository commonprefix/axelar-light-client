#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::{lightclient::LightClient, state::*};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let mut lc = LightClient::new(&msg.config, None);
    // Load state from bootstrap
    lc.bootstrap(msg.bootstrap.clone()).unwrap();

    BOOTSTRAP.save(deps.storage, &msg.bootstrap)?;
    LIGHT_CLIENT_STATE.save(deps.storage, &lc.state)?;
    CONFIG.save(deps.storage, &msg.config)?;

    println!(
        "Last slot after bootstrap {:?}",
        lc.state.finalized_header.slot
    );

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
    use crate::lightclient::types::Update;

    use super::*;

    pub fn update(deps: DepsMut, period: u64, update: Update) -> Result<Response, ContractError> {
        // TODO: Fix this cloned state everywhere
        let state = LIGHT_CLIENT_STATE.load(deps.storage)?;
        let config = CONFIG.load(deps.storage)?;
        let mut lc = LightClient::new(&config, Some(state));

        let res = lc.verify_update(&update);
        if res.is_err() {
            return Err(ContractError::from(res.err().unwrap()));
        }

        let res = lc.apply_update(&update);
        if res.is_err() {
            return Err(ContractError::from(res.err().unwrap()));
        }

        LIGHT_CLIENT_STATE.save(deps.storage, &lc.state)?;
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
    use crate::lightclient::types::Update;

    pub fn greet() -> StdResult<String> {
        Ok("Hello, world!".to_string())
    }

    pub fn update(deps: Deps, period: u64) -> StdResult<Update> {
        UPDATES.load(deps.storage, period)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use crate::{
        contract::{execute, instantiate, query},
        helpers::hex_str_to_bytes,
        lightclient::types::{Bootstrap, ChainConfig, LightClientState, Update},
        lightclient::LightClient,
        msg::ExecuteMsg,
    };
    use cosmwasm_std::Addr;
    use cw_multi_test::{App, ContractWrapper, Executor};

    use crate::msg::{InstantiateMsg, QueryMsg};

    fn get_bootstrap() -> Bootstrap {
        let file = File::open("testdata/bootstrap.json").unwrap();
        let bootstrap: Bootstrap = serde_json::from_reader(file).unwrap();

        return bootstrap;
    }

    // Currently have in testdata: 767, 862, 863
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
            genesis_root: hex_str_to_bytes(
                "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
            )
            .unwrap(),
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

        let mut lc = LightClient::new(&get_config(), None);
        lc.bootstrap(bootstrap).unwrap();
        assert_eq!(resp, lc.state)
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

        let update = get_update(862);

        //Call update
        let resp = app.execute_contract(
            Addr::unchecked("owner"),
            addr.to_owned(),
            &ExecuteMsg::Update {
                period: 862,
                update: update.clone(),
            },
            &[],
        );

        assert!(resp.is_ok());

        let update = get_update(863);

        //Call update
        let resp = app.execute_contract(
            Addr::unchecked("owner"),
            addr.to_owned(),
            &ExecuteMsg::Update {
                period: 863,
                update: update.clone(),
            },
            &[],
        );

        assert!(resp.is_ok());
    }
}
