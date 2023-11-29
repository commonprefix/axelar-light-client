use serde::Deserialize;
use ssz_rs::{Node, SszVariableOrIndex};

#[derive(Deserialize, Debug)]
pub struct ProofResponse {
    pub gindex: u64,
    pub witnesses: Vec<Node>,
    pub leaf: Node,
}

pub enum GindexOrPath {
    Gindex(usize),
    Path(Vec<SszVariableOrIndex>),
}
