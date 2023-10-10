#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};

use crate::error::ContractError;
use crate::lightclient::helpers::calc_sync_period;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::{lightclient::LightClient, state::*};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let mut lc = LightClient::new(&msg.config, &msg.forks, None, &env);
    lc.bootstrap(msg.bootstrap.clone()).unwrap();

    BOOTSTRAP.save(deps.storage, &msg.bootstrap)?;
    LIGHT_CLIENT_STATE.save(deps.storage, &lc.state)?;
    CONFIG.save(deps.storage, &msg.config)?;
    FORKS.save(deps.storage, &msg.forks)?;

    let period = calc_sync_period(msg.bootstrap.header.beacon.slot.into());
    SYNC_COMMITTEES.save(deps.storage, period, &msg.bootstrap.current_sync_committee)?;

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
        UpdateForks { forks } => execute::update_forks(deps, forks),
    }
}

mod execute {
    use crate::lightclient::types::{Forks, Update};

    use super::*;

    pub fn light_client_update(
        deps: DepsMut,
        env: &Env,
        period: u64,
        update: Update,
    ) -> Result<Response, ContractError> {
        let state = LIGHT_CLIENT_STATE.load(deps.storage)?;
        let config = CONFIG.load(deps.storage)?;
        let forks = FORKS.load(deps.storage)?;
        let mut lc = LightClient::new(&config, &forks, Some(state), &env);

        let res = lc.verify_update(&update);
        if res.is_err() {
            return Err(ContractError::from(res.err().unwrap()));
        }

        let res = lc.apply_update(&update);
        if res.is_err() {
            return Err(ContractError::from(res.err().unwrap()));
        }

        UPDATES.save(deps.storage, period, &update)?;
        SYNC_COMMITTEES.save(deps.storage, period + 1, &update.next_sync_committee)?;
        LIGHT_CLIENT_STATE.save(deps.storage, &lc.state)?;

        Ok(Response::new())
    }

    pub fn update_forks(deps: DepsMut, forks: Forks) -> Result<Response, ContractError> {
        FORKS.save(deps.storage, &forks)?;
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
        Forks {} => to_binary(&FORKS.load(deps.storage)?),
        SyncCommittee { period } => {
            let sync_committee = &SYNC_COMMITTEES.load(deps.storage, period)?;
            to_binary(&sync_committee)
        }
    }
}

mod query {
    use super::*;

    pub fn greet() -> StdResult<String> {
        Ok("Hello, world!".to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{
        contract::{execute, instantiate, query},
        lightclient::LightClient,
        lightclient::{
            helpers::hex_str_to_bytes,
            types::{Bootstrap, Fork, LightClientState, SignatureBytes},
            types::{Fork, LightClientState, SignatureBytes},
        },
        lightclient::{helpers::test_helpers::*, types::Forks},
        msg::ExecuteMsg,
    };
    use cosmwasm_std::{testing::mock_env, Addr, Timestamp};
    use cw_multi_test::{App, ContractWrapper, Executor};

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
                    forks: get_forks(),
                },
                &[],
                "Contract",
                None,
            )
            .unwrap();

        return (app, addr);
    }

    #[test]
    fn test_initialize() {
        let (app, addr) = deploy();
        let env = mock_env();
        let bootstrap = get_bootstrap();

        let resp: LightClientState = app
            .wrap()
            .query_wasm_smart(&addr, &QueryMsg::LightClientState {})
            .unwrap();

        let mut lc = LightClient::new(&get_config(), &get_forks(), None, &env);
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
        update.sync_aggregate.sync_committee_signature = SignatureBytes::default();

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
        let resp: Forks = app
            .wrap()
            .query_wasm_smart(addr, &QueryMsg::Forks {})
            .unwrap();

        assert_eq!(resp, get_forks());
    }

    #[test]
    fn test_forks_update() {
        let (mut app, addr) = deploy();
        let new_forks = Forks {
            genesis: Fork {
                epoch: 0,
                fork_version: hex_str_to_bytes("0x03000000").unwrap(),
            },
            altair: Fork {
                epoch: 1,
                fork_version: hex_str_to_bytes("0x02000000").unwrap(),
            },
            bellatrix: Fork {
                epoch: 2,
                fork_version: hex_str_to_bytes("0x01000000").unwrap(),
            },
            capella: Fork {
                epoch: 3,
                fork_version: hex_str_to_bytes("0x00000000").unwrap(),
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

        let resp: Forks = app
            .wrap()
            .query_wasm_smart(addr, &QueryMsg::Forks {})
            .unwrap();

        assert_eq!(resp, new_forks);
    }
}
