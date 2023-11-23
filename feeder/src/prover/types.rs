use serde::Deserialize;
use ssz_rs::Node;

#[derive(Deserialize, Debug)]
pub struct ProofResponse {
    pub gindex: u64,
    pub witnesses: Vec<Node>,
    pub leaf: Node,
}
