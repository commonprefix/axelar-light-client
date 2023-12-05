use ethers::types::H256;
use thiserror::Error;

#[derive(Debug, Clone, Copy)]
pub enum BlockTag {
    // Latest,
    // Finalized,
    // Number(u64),
}

impl std::fmt::Display for BlockTag {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[derive(Debug, Error)]
#[error("block not available: {block}")]
pub struct BlockNotFoundError {
    block: BlockTag,
}

#[derive(Debug, Error)]
#[error("slot not found: {slot:?}")]
pub struct SlotNotFoundError {
    slot: H256,
}

#[derive(Debug, Error)]
#[error("rpc error on method: {method}, message: {error}")]
pub struct RpcError<E: ToString> {
    method: String,
    error: E,
}

impl<E: ToString> RpcError<E> {
    pub fn new(method: &str, err: E) -> Self {
        Self {
            method: method.to_string(),
            error: err,
        }
    }
}
