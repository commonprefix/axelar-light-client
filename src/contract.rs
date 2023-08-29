use std::collections::btree_set::Union;

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
    unimplemented!();
    // bootstrap.save(deps.storage, &msg.bootstrap)?;
    // Ok(Response::new())
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
    unimplemented!();
    // use QueryMsg::*;

    // match msg {
    //     Greet {} => to_binary(&query::greet()?),
    //     Bootstrap {} => to_binary(&query::get_bootstrap(_deps)?),
    // }
}
// mod query {
//     use crate::types::Bootstrap;

//     use super::*;

//     pub fn greet() -> StdResult<String> {
//         Ok("Hello, world!".to_string())
//     }

//     pub fn get_bootstrap(deps: Deps) -> StdResult<Bootstrap> {
//         bootstrap.load(deps.storage)
//     }
// }

#[cfg(test)]
mod tests {
    use std::fs::File;

    use crate::contract::{execute, instantiate, query};
    use cosmwasm_std::Addr;
    use cw_multi_test::{App, ContractWrapper, Executor};
    use ssz_rs::Vector;

    use crate::{
        msg::{InstantiateMsg, QueryMsg},
        types::{BLSPubKey, Bootstrap, Header, SyncCommittee},
    };

    #[test]
    fn greet_query() {
        // Open and parse JSON
        let file = File::open("testdata/bootstrap.json").unwrap();
        let bootstrap: Bootstrap = serde_json::from_reader(file).unwrap();
        println!("{:?}", bootstrap);

        // fn create_mock_bls_key() -> BLSPubKey {
        //     Vector::<u8, 48>::default()
        // }

        // fn create_mock_pub_keys() -> Vector<BLSPubKey, 512> {
        //     let mut pub_keys = vec![];
        //     for _ in 0..512 {
        //         pub_keys.push(create_mock_bls_key());
        //     }
        //     Vector::<BLSPubKey, 512>::try_from(pub_keys).unwrap()
        // }

        // let mut app = App::default();

        // let code = ContractWrapper::new(execute, instantiate, query);
        // let code_id = app.store_code(Box::new(code));

        // let bootstrap = Bootstrap {
        //     header: Header {
        //         slot: 0,
        //         proposer_index: 0,
        //         parent_root: [0; 32],
        //         state_root: [0; 32],
        //         body_root: [0; 32],
        //     },
        //     current_sync_committee: SyncCommittee {
        //         pubkeys: create_mock_pub_keys(),
        //         aggregate_pubkey: create_mock_bls_key(),
        //     },
        //     current_sync_committee_branch: vec![],
        // };

        // let addr = app
        //     .instantiate_contract(
        //         code_id,
        //         Addr::unchecked("owner"),
        //         &InstantiateMsg {
        //             bootstrap: bootstrap.clone(),
        //         },
        //         &[],
        //         "Contract",
        //         None,
        //     )
        //     .unwrap();

        // let resp: Bootstrap = app
        //     .wrap()
        //     .query_wasm_smart(addr, &QueryMsg::Bootstrap {})
        //     .unwrap();

        // assert_eq!(resp, bootstrap);
    }
}
