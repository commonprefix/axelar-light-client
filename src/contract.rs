#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::bootstrap;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    bootstrap.save(deps.storage, &msg.bootstrap)?;
    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    unimplemented!()
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    use QueryMsg::*;

    match msg {
        Greet {} => to_binary(&query::greet()?),
        Bootstrap {} => to_binary(&query::get_bootstrap(_deps)?),
    }
}

mod query {
    use crate::types::Bootstrap;

    use super::*;

    pub fn greet() -> StdResult<String> {
        Ok("Hello, world!".to_string())
    }

    pub fn get_bootstrap(deps: Deps) -> StdResult<Bootstrap> {
        bootstrap.load(deps.storage)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use crate::{
        contract::{execute, instantiate, query},
        types::{BeaconHeader, Header},
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
            println!("{:?}", bootstrap);

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

        let resp: Bootstrap = app
            .wrap()
            .query_wasm_smart(addr, &QueryMsg::Bootstrap {})
            .unwrap();

        assert_eq!(resp, bootstrap);
    }
}
