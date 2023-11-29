use crate::{
    error::RpcError,
    eth::{
        consensus::ConsensusRPC,
        constants::{CONSENSUS_RPC, STATE_PROVER_RPC},
        utils::get,
    },
    prover::{
        types::{GindexOrPath, ProofResponse},
        utils::parse_path,
    },
};
use consensus_types::{
    consensus::{self, BeaconStateType},
    proofs::AncestryProof,
};
use cosmos_sdk_proto::tendermint::v0_34::version::Consensus;
use eyre::{anyhow, Result};
use futures::{future, TryFutureExt};
use ssz_rs::{get_generalized_index, Merkleized, Node, SszVariableOrIndex, Vector};
use sync_committee_rs::constants::{
    Root, ALTAIR_FORK_EPOCH, CAPELLA_FORK_EPOCH, SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT,
};

const CAPELLA_FORK_SLOT: u64 = CAPELLA_FORK_EPOCH * SLOTS_PER_EPOCH;

/**
 * Generates a merkle proof from the transaction to the beacon block root.
*/
pub async fn generate_transaction_branch(
    block_id: &String,
    tx_index: u64,
) -> Result<ProofResponse> {
    let path = vec![
        SszVariableOrIndex::Name("body"),
        SszVariableOrIndex::Name("execution_payload"),
        SszVariableOrIndex::Name("transactions"),
        SszVariableOrIndex::Index(tx_index as usize),
    ];

    let proof = get_block_proof(block_id, GindexOrPath::Path(path)).await?;
    Ok(proof)
}

/**
 * Generates a merkle proof from the receipts_root to the beacon block root.
*/
pub async fn generate_receipts_root_branch(block_id: &String) -> Result<ProofResponse> {
    let path = vec![
        SszVariableOrIndex::Name("body"),
        SszVariableOrIndex::Name("execution_payload"),
        SszVariableOrIndex::Name("receipts_root"),
    ];

    let proof = get_block_proof(block_id, GindexOrPath::Path(path)).await?;
    Ok(proof)
}

/**
 * Generates an ancestry proof from the recent block state to the target block
 * using either the block_roots or the historical_roots beacon state property.
*/
pub async fn prove_ancestry(
    target_block_slot: usize,
    recent_block_slot: usize,
    recent_block_state_id: &String,
) -> Result<AncestryProof> {
    let is_in_block_roots_range = target_block_slot < recent_block_slot
        && recent_block_slot <= target_block_slot + SLOTS_PER_HISTORICAL_ROOT;

    let proof = if is_in_block_roots_range {
        prove_ancestry_with_block_roots(&target_block_slot, recent_block_state_id).await?
    } else {
        unimplemented!()
    };

    Ok(proof)
}

/**
 * Generates an ancestry proof from the recent block state to the target block
 * using the block_roots beacon state property using the lodestar prover. The
 * target block must in the range
 * [recent_block_slot - SLOTS_PER_HISTORICAL_ROOT, recent_block_slot].
 */
pub async fn prove_ancestry_with_block_roots(
    target_block_slot: &usize,
    recent_block_state_id: &String,
) -> Result<AncestryProof> {
    let index = target_block_slot % SLOTS_PER_HISTORICAL_ROOT;
    let g_index_from_state_root = get_generalized_index(
        &BeaconStateType::default(),
        &[
            SszVariableOrIndex::Name("block_roots"),
            SszVariableOrIndex::Index(index),
        ],
    );

    let res = get_state_proof(
        recent_block_state_id,
        &GindexOrPath::Gindex(g_index_from_state_root),
    )
    .await?;

    let ancestry_proof = AncestryProof::BlockRoots {
        block_roots_index: g_index_from_state_root as u64,
        block_root_proof: res.witnesses,
    };

    Ok(ancestry_proof)
}

async fn prove_historical_summaries_branch(
    target_block_slot: &u64,
    recent_block_state_id: &String,
) -> Result<ProofResponse> {
    let historical_summaries_index =
        (target_block_slot - CAPELLA_FORK_SLOT) / SLOTS_PER_HISTORICAL_ROOT as u64;

    let path = vec![
        SszVariableOrIndex::Name("historical_summaries"),
        SszVariableOrIndex::Index(historical_summaries_index as usize),
        SszVariableOrIndex::Name("block_summary_root"),
    ];

    let res = get_state_proof(recent_block_state_id, &GindexOrPath::Path(path)).await?;
    return Ok(res);
}

async fn construct_historical_block_roots_tree(start_slot: u64) -> Result<Vector<Root, 8192>> {
    let consensus = ConsensusRPC::new(CONSENSUS_RPC);
    const BATCH_SIZE: usize = 1000;

    let mut all_block_roots_vec = vec![];

    for batch_start in (0..SLOTS_PER_HISTORICAL_ROOT).step_by(BATCH_SIZE as usize) {
        let batch_end = std::cmp::min(batch_start + BATCH_SIZE, SLOTS_PER_HISTORICAL_ROOT);
        let mut futures = Vec::new();

        for i in batch_start..batch_end {
            let future = consensus.get_block_root(start_slot + i as u64);
            futures.push(future);
        }
        println!("Pushed futures for batch {}", batch_start / BATCH_SIZE);

        // Wait for all futures in the batch to resolve
        let resolved = future::join_all(futures).await;
        println!("Resolved batch {}", batch_start / BATCH_SIZE);

        // Process resolved futures and add to the main vector
        for res in resolved {
            match res {
                Ok(block_root) => all_block_roots_vec.push(block_root),
                Err(_) => all_block_roots_vec.push(all_block_roots_vec.last().unwrap().clone()),
            }
        }
    }

    let mut block_roots =
        Vector::<Root, SLOTS_PER_HISTORICAL_ROOT>::try_from(all_block_roots_vec).unwrap();

    Ok(block_roots)
}

async fn prove_block_root_to_block_summary_root(
    target_block_slot: &u64,
    block_roots: Option<Vector<Node, SLOTS_PER_HISTORICAL_ROOT>>,
) -> Result<Vec<Node>> {
    let block_root_index = *target_block_slot as usize % SLOTS_PER_HISTORICAL_ROOT;
    let start_slot = target_block_slot - block_root_index as u64;

    let mut block_roots = match block_roots {
        Some(block_roots) => block_roots,
        None => construct_historical_block_roots_tree(start_slot)
            .await
            .unwrap(),
    };
    println!(
        "Constructed block roots tree {:?}",
        block_roots.hash_tree_root().unwrap()
    );

    let gindex = get_generalized_index(
        &Vector::<Node, SLOTS_PER_HISTORICAL_ROOT>::default(),
        &[SszVariableOrIndex::Index(block_root_index)],
    );
    let proof = ssz_rs::generate_proof(&mut block_roots, &[gindex])?;

    Ok(proof)
}

/**
 * Generates an ancestry proof from the recent block state to the target block
 * using the historical_roots beacon state property. The target block should be
 * in a slot less than recent_block_slot - SLOTS_PER_HISTORICAL_ROOT.
 */
pub async fn prove_ancestry_with_historical_summaries(
    target_block_slot: &u64,
    recent_block_state_id: &String,
    block_roots: Option<Vector<Node, SLOTS_PER_HISTORICAL_ROOT>>,
) -> Result<AncestryProof> {
    if *target_block_slot < CAPELLA_FORK_SLOT {
        return Err(anyhow!(
            "Target block epoch is less than CAPELLA_FORK_EPOCH"
        ));
    }
    let historical_summaries_branch =
        prove_historical_summaries_branch(target_block_slot, recent_block_state_id).await?;

    println!(
        "historical_summaries_branch {:?}",
        historical_summaries_branch
    );

    let block_root_to_block_summary_root =
        prove_block_root_to_block_summary_root(target_block_slot, block_roots).await?;

    println!(
        "block_root_to_block_summary_root {:?}",
        block_root_to_block_summary_root
    );

    let res = AncestryProof::HistoricalRoots {
        block_root_proof: block_root_to_block_summary_root,
        historical_summaries_branch: historical_summaries_branch.witnesses,
        block_summary_root: historical_summaries_branch.leaf,
        block_summary_root_gindex: historical_summaries_branch.gindex as usize,
    };

    Ok(res)
    // let historicalSummariesBranch = get_state_proof(state_id, )
}

async fn get_state_proof(
    state_id: &String,
    gindex_or_path: &GindexOrPath,
) -> Result<ProofResponse> {
    let req = match gindex_or_path {
        GindexOrPath::Gindex(gindex) => format!(
            "{}/state_proof/?state_id={}&gindex={}",
            STATE_PROVER_RPC, state_id, gindex
        ),
        GindexOrPath::Path(path) => {
            let path = parse_path(path);
            format!(
                "{}/state_proof/?state_id={}&path={}",
                STATE_PROVER_RPC, state_id, path
            )
        }
    };
    println!("req {:?}", req);

    let res: ProofResponse = get(&req)
        .await
        .map_err(|e| RpcError::new("get_state_proof", e))?;

    Ok(res)
}

async fn get_block_proof(block_id: &String, gindex_or_path: GindexOrPath) -> Result<ProofResponse> {
    let req = match gindex_or_path {
        GindexOrPath::Gindex(gindex) => format!(
            "{}/block_proof/?block_id={}&gindex={}",
            STATE_PROVER_RPC, block_id, gindex
        ),
        GindexOrPath::Path(path) => {
            let path = parse_path(&path);
            format!(
                "{}/block_proof/?block_id={}&path={}",
                STATE_PROVER_RPC, block_id, path
            )
        }
    };

    let res: ProofResponse = get(&req)
        .await
        .map_err(|e| RpcError::new("get_block_proof", e))?;

    Ok(res)
}

#[cfg(test)]
mod tests {
    use crate::eth::consensus::ConsensusRPC;
    use crate::eth::constants::CONSENSUS_RPC;
    use crate::prover::consensus::{
        generate_receipts_root_branch, generate_transaction_branch,
        prove_ancestry_with_block_roots, prove_ancestry_with_historical_summaries,
    };
    use consensus_types::consensus::BeaconBlockAlias;
    use consensus_types::proofs::AncestryProof;
    use cosmrs::bip32::secp256k1::elliptic_curve::rand_core::block;
    use ssz_rs::{
        get_generalized_index, GeneralizedIndex, Merkleized, Node, SszVariableOrIndex, Vector,
    };
    use std::fs::File;
    use sync_committee_rs::constants::SLOTS_PER_HISTORICAL_ROOT;
    use tokio::test as tokio_test;

    pub fn get_beacon_block() -> BeaconBlockAlias {
        let file = File::open("./src/prover/testdata/beacon_block.json").unwrap();
        serde_json::from_reader(file).unwrap()
    }

    pub fn get_block_roots() -> Vector<Node, 8192> {
        let file = File::open("./src/prover/testdata/block_roots.json").unwrap();
        serde_json::from_reader(file).unwrap()
    }

    /**
     * TESTS BELOW REQUIRE NETWORK REQUESTS
     */
    #[tokio_test]
    async fn test_transactions_branch() {
        let mut block = get_beacon_block();
        let block_root = block.hash_tree_root().unwrap();

        let tx_index = 15;
        let transaction = &mut block.body.execution_payload.transactions[tx_index];
        let node = transaction.hash_tree_root().unwrap();

        let proof = generate_transaction_branch(&block_root.to_string(), tx_index as u64)
            .await
            .unwrap();

        let is_proof_valid = ssz_rs::verify_merkle_proof(
            &node,
            proof.witnesses.as_slice(),
            &GeneralizedIndex(proof.gindex as usize),
            &block_root,
        );

        assert!(is_proof_valid)
    }

    #[tokio_test]
    async fn test_receipts_root_branch() {
        let mut block = get_beacon_block();
        let block_root = block.hash_tree_root().unwrap();

        let proof = generate_receipts_root_branch(&block_root.to_string())
            .await
            .unwrap();

        let is_proof_valid = ssz_rs::verify_merkle_proof(
            &block
                .body
                .execution_payload
                .receipts_root
                .hash_tree_root()
                .unwrap(),
            proof.witnesses.as_slice(),
            &GeneralizedIndex(proof.gindex as usize),
            &block_root,
        );

        assert!(is_proof_valid)
    }

    #[tokio_test]
    async fn test_block_roots_proof() {
        let consensus = ConsensusRPC::new(CONSENSUS_RPC);
        let latest_block = consensus.get_latest_beacon_block_header().await.unwrap();
        let mut old_block = consensus
            .get_beacon_block_header(latest_block.slot - 1000)
            .await
            .unwrap();

        let proof = prove_ancestry_with_block_roots(
            &(old_block.slot as usize),
            &latest_block.state_root.to_string(),
        )
        .await
        .unwrap();

        match proof {
            AncestryProof::BlockRoots {
                block_roots_index,
                block_root_proof,
            } => {
                let is_valid_proof = ssz_rs::verify_merkle_proof(
                    &old_block.hash_tree_root().unwrap(),
                    block_root_proof.as_slice(),
                    &GeneralizedIndex(block_roots_index as usize),
                    &latest_block.state_root,
                );
                assert!(is_valid_proof)
            }
            _ => panic!("Expected block roots proof"),
        }
    }

    #[tokio_test]
    async fn test_historical_proof() {
        let consensus = ConsensusRPC::new(CONSENSUS_RPC);
        let latest_block = consensus.get_latest_beacon_block_header().await.unwrap();
        let mut old_block = consensus
            .get_beacon_block_header(7870916 - 8196)
            .await
            .unwrap();
        let block_roots = get_block_roots();

        let proof = prove_ancestry_with_historical_summaries(
            &(old_block.slot),
            &latest_block.state_root.to_string(),
            Some(block_roots),
        )
        .await
        .unwrap();

        match proof {
            AncestryProof::HistoricalRoots {
                historical_summaries_branch,
                block_root_proof,
                block_summary_root_gindex,
                block_summary_root,
            } => {
                // Proof from state root to the specific block_summary_root of the historical_summaries
                let is_valid_proof = ssz_rs::verify_merkle_proof(
                    &block_summary_root,
                    &historical_summaries_branch,
                    &GeneralizedIndex(block_summary_root_gindex),
                    &latest_block.state_root,
                );

                // Proof from block_summary_root to the target block

                let block_root_index = old_block.slot as usize % SLOTS_PER_HISTORICAL_ROOT;
                let gindex = get_generalized_index(
                    &Vector::<Node, SLOTS_PER_HISTORICAL_ROOT>::default(),
                    &[SszVariableOrIndex::Index(block_root_index)],
                );

                let is_valid_proof = ssz_rs::verify_merkle_proof(
                    &old_block.hash_tree_root().unwrap(),
                    &block_root_proof,
                    &GeneralizedIndex(gindex),
                    &block_summary_root,
                );
                assert!(is_valid_proof)
            }
            _ => panic!("Expected block roots proof"),
        }
    }
}
