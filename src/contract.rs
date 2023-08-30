#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};

use crate::error::ContractError;
use crate::helpers::calc_sync_period;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::*;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let genesis_period = calc_sync_period(msg.bootstrap.slot.as_u64());

    GENESIS_PERIOD.save(deps.storage, &genesis_period)?;
    GENESIS_TIME.save(deps.storage, &msg.bootstrap.genesis_time)?;
    GENESIS_COMMITTEE.save(deps.storage, &msg.bootstrap.committee)?;

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
        let resp = UPDATES.may_load(deps.storage, 767)?;
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
        GenesisTime {} => to_binary(&query::genesis_time(deps)?),
        GenesisPeriod {} => to_binary(&query::genesis_period(deps)?),
        GenesisCommittee {} => to_binary(&GENESIS_COMMITTEE.load(deps.storage)?),
        Update { period } => to_binary(&query::update(deps, period)?),
    }
}

mod query {
    use super::*;
    use crate::types::{primitives::U64, Update};

    pub fn greet() -> StdResult<String> {
        Ok("Hello, world!".to_string())
    }

    pub fn genesis_time(deps: Deps) -> StdResult<U64> {
        GENESIS_TIME.load(deps.storage)
    }

    pub fn genesis_period(deps: Deps) -> StdResult<u64> {
        GENESIS_PERIOD.load(deps.storage)
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
        types::{primitives::U64, SyncCommittee, Update},
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

    #[test]
    fn test_initialize() {
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
                    bootstrap: bootstrap.clone(),
                },
                &[],
                "Contract",
                None,
            )
            .unwrap();

        let resp: u64 = app
            .wrap()
            .query_wasm_smart(&addr, &QueryMsg::GenesisPeriod {})
            .unwrap();
        assert_eq!(resp, 766);

        let resp: U64 = app
            .wrap()
            .query_wasm_smart(&addr, &QueryMsg::GenesisTime {})
            .unwrap();
        assert_eq!(resp, bootstrap.genesis_time);

        let resp: SyncCommittee = app
            .wrap()
            .query_wasm_smart(&addr, &QueryMsg::GenesisCommittee {})
            .unwrap();
        assert_eq!(resp.pubkeys.len(), 512);
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
