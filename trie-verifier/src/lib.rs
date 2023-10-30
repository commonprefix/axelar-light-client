use cosmwasm_std::{
    entry_point, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response, StdResult,
};
use error::ContractError;
use msg::ExecuteMsg;

pub mod error;
pub mod helpers;
pub mod msg;
pub mod types;

#[entry_point]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: Empty,
) -> StdResult<Response> {
    Ok(Response::new())
}

#[entry_point]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    use ExecuteMsg::*;

    match msg {
        VerifyProof { root, proof, key } => execute::verify_proof(root, proof, key),
        Test {} => execute::test(),
    }
}
#[entry_point]
pub fn query(_deps: Deps, _env: Env, _msg: Empty) -> StdResult<Binary> {
    unimplemented!()
}

mod execute {
    use super::*;

    pub fn verify_proof(
        root: Vec<u8>,
        proof: Vec<Vec<u8>>,
        mut key: Vec<u8>,
    ) -> Result<Response, ContractError> {
        let data = helpers::verify_proof(&root, &mut key, proof);
        Ok(Response::new().set_data(data))
    }

    pub fn test() -> Result<Response, ContractError> {
        Ok(Response::new()
            .set_data(vec![1, 2, 3])
            .add_attribute("foo", "bar"))
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::Addr;
    use cw_multi_test::{App, ContractWrapper, Executor};

    use super::*;
    use crate::helpers::test_helpers::get_receipt_verification_request;

    #[test]
    fn test_proof_verification() {
        let mut app = App::default();

        let code = ContractWrapper::new(execute, instantiate, query);
        let code_id = app.store_code(Box::new(code));

        let addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("owner"),
                &Empty {},
                &[],
                "Contract",
                None,
            )
            .unwrap();

        let request = get_receipt_verification_request();
        let resp = app
            .execute_contract(
                Addr::unchecked("owner"),
                addr,
                &ExecuteMsg::VerifyProof {
                    proof: request.proof.clone(),
                    key: request.key,
                    root: request.root,
                },
                &[],
            )
            .unwrap();

        assert!(resp.data.is_some());
        assert_eq!(resp.data.unwrap().to_vec(), &request.proof[1][7..]);
    }
}
