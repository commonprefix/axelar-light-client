use std::fs::File;

use crate::prover::{
    state_prover::StateProverAPI,
    types::{GindexOrPath, ProofResponse},
};
use async_trait::async_trait;
use eyre::Result;
use ssz_rs::SszVariableOrIndex;

pub struct MockStateProver;

#[allow(dead_code)]
impl MockStateProver {
    pub fn new() -> Self {
        MockStateProver {}
    }
}

#[async_trait]
impl StateProverAPI for MockStateProver {
    async fn get_state_proof(
        &self,
        state_id: &str,
        gindex_or_path: &GindexOrPath,
    ) -> Result<ProofResponse> {
        let filename = match gindex_or_path {
            GindexOrPath::Gindex(gindex) => format!("state_proof_{}_g{}.json", state_id, gindex),
            GindexOrPath::Path(path) => {
                let path = parse_path(path);
                format!("state_proof_{}_{}.json", state_id, path)
            }
        };

        let filename = format!("./src/prover/testdata/state_prover/{}", filename);
        let file = File::open(filename).unwrap();

        let res: ProofResponse = serde_json::from_reader(file).unwrap();

        Ok(res)
    }

    async fn get_block_proof(
        &self,
        block_id: &str,
        gindex_or_path: GindexOrPath,
    ) -> Result<ProofResponse> {
        let filename = match gindex_or_path {
            GindexOrPath::Gindex(gindex) => format!("block_proof_{}_g{}.json", block_id, gindex),
            GindexOrPath::Path(path) => {
                let path = parse_path(&path);
                format!("block_proof_{}_{}.json", block_id, path)
            }
        };

        let filename = format!("./src/prover/testdata/state_prover/{}", filename);
        let file = File::open(filename).unwrap();

        let res: ProofResponse = serde_json::from_reader(file).unwrap();

        Ok(res)
    }
}

fn parse_path(path: &Vec<SszVariableOrIndex>) -> String {
    let mut path_str = String::new();
    for p in path {
        match p {
            SszVariableOrIndex::Name(name) => path_str.push_str(&format!(",{}", name)),
            SszVariableOrIndex::Index(index) => path_str.push_str(&format!(",{}", index)),
        }
    }
    path_str[1..].to_string() // remove first comma
}
