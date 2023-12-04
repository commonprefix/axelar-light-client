use serde::{Deserialize, Serialize};
use ssz_rs::{Node, SszVariableOrIndex};

#[derive(Deserialize, Debug, Serialize, Default)]
pub struct ProofResponse {
    pub gindex: u64,
    pub witnesses: Vec<Node>,
    pub leaf: Node,
}

#[derive(Debug)]
pub enum GindexOrPath {
    Gindex(usize),
    Path(Vec<SszVariableOrIndex>),
}
