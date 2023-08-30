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
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    use QueryMsg::*;

    match msg {
        Greet {} => to_binary(&query::greet()?),
        GenesisTime {} => to_binary(&query::genesis_time(deps)?),
        GenesisPeriod {} => to_binary(&query::genesis_period(deps)?),
        GenesisCommittee {} => to_binary(&GENESIS_COMMITTEE.load(deps.storage)?),
    }
}

mod query {
    use super::*;
    use crate::types::primitives::U64;

    pub fn greet() -> StdResult<String> {
        Ok("Hello, world!".to_string())
    }

    pub fn genesis_time(deps: Deps) -> StdResult<U64> {
        GENESIS_TIME.load(deps.storage)
    }

    pub fn genesis_period(deps: Deps) -> StdResult<u64> {
        GENESIS_PERIOD.load(deps.storage)
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
        types::primitives::U64,
    };
    use cosmwasm_std::Addr;
    use cw_multi_test::{App, ContractWrapper, Executor};

    use crate::{
        msg::{InstantiateMsg, QueryMsg},
        types::Bootstrap,
    };

    #[test]
    fn greet_query() {
        // Open and parse JSON
        fn get_mock_bootstrap() -> Bootstrap {
            let file = File::open("testdata/bootstrap.json").unwrap();
            let bootstrap: Bootstrap = serde_json::from_reader(file).unwrap();

            return bootstrap;
        }

        let mut app = App::default();

        let code = ContractWrapper::new(execute, instantiate, query);
        let code_id = app.store_code(Box::new(code));

        let bootstrap = get_mock_bootstrap();

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
        assert_eq!(resp, 466);

        let resp: U64 = app
            .wrap()
            .query_wasm_smart(&addr, &QueryMsg::GenesisTime {})
            .unwrap();
        assert_eq!(resp, bootstrap.genesis_time);

        let resp: Vec<String> = app
            .wrap()
            .query_wasm_smart(&addr, &QueryMsg::GenesisCommittee {})
            .unwrap();
        assert_eq!(resp.len(), 512);
    }
}
