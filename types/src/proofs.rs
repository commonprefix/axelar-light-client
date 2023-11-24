use ssz_rs::Node;

/// The block header ancestry proof, this is an enum because the header may either exist in
/// `state.block_roots` or `state.historical_roots`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AncestryProof {
    /// This variant defines the proof data for a beacon chain header in the `state.block_roots`
    BlockRoots {
        // Generalized index from the block_root that we care to the block_root to the state root.
        // No need to provide that, since it can be calculated on-chain.
        block_roots_index: u64,
        block_root_proof: Vec<Node>,
    },
    /// This variant defines the neccessary proofs for a beacon chain header in the
    /// `state.historical_roots`.
    HistoricalRoots {
        /// Proof for the header in `historical_batch.block_roots`
        block_roots_proof: Vec<Node>,
        /// The proof for the `historical_batch.block_roots`, needed to reconstruct
        /// `hash_tree_root(historical_batch)`
        historical_batch_proof: Vec<Node>,
        /// The proof for the `hash_tree_root(historical_batch)` in `state.historical_roots`
        historical_roots_proof: Vec<Node>,
        /// The generalized index for the historical_batch in `state.historical_roots`.
        historical_roots_index: u64,
        /// The proof for the reconstructed `hash_tree_root(state.historical_roots)` in
        /// [`BeaconState`]
        historical_roots_branch: Vec<Node>,
    },
}
