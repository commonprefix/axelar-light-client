# Prover

The prover package encapsulates the main prover of the light client project.
This module is responsible for accepting a set of contents, batching in the 2
layers of batching described below and generating the necessary proofs in the
verifier-compatible struct.

## Proofs

For a single message, the proofs that are generated are the following:

* `AncestryProof`: The proof from the recent block of the update provider up to
  the block that includes the content (target block). The ancestry proof is
  either a BlockRootsProof derived from the block_roots beacon state property or
  a HistoricalRootsProof derived from the historical_roots beacon state property
  depending on how recent the target block is. The ancestry proof is generated
  using the state_prover API.
* `TransactionProof`: The proof from the target beacon block to the specific
  transaction that includes the content. This proof is generated using the
  StateProver API.
* `ReceiptsProof`: This proof is a struct that includes one Merkle proof from
  the beacon block root to the receipts_root proof (generated from the
  StateProverA API) and one Merkle Patricia trie proof from the receipts_root of
  the target block up to the specific receipt.

## Batching

- **Block-level Batching:** Some events could have been emitted from
transactions that were included in the same block. For those events, we can use
the same ancestry proof since they belong to the same block, so we are batching
them together under the same target block.

- **Transaction-level Batching:** There could also be events that were emitted
from the same transaction. Those events, except for the ancestry proof, could
also use the same transaction-inclusion proofs. So we also batch events under
the same transaction.

## Endpoints

Specifically, the prover module exposes 2 basic endpoints:

- `batch_contents(contents: [EnrichedContent]) -> BatchContentGroups`: It
accepts a set of contents and generates a batched version of those messages both
per block and per transaction. Specifically, the
returned `BatchContentGroups` struct is a map from the block number to a map from a tx_hash to messages.

```
pub type BatchContentGroups = IndexMap<u64, IndexMap<H256, Vec<EnrichedContent>>>
```

- `batch_generate_proofs(batch_content_groups: BatchContentGroups, update: LightClientUpdate) -> BatchVerificationData`: 
This is the main function that generates the proofs. This function iterates over
the hashmap generated from the `batch_contents` and generates the
`ancestry_proof` for every single target block and the `transaction_proof` as
well as the `receipts_proof` for every single transaction. If a proof could not
be generated then the nested contents are omitted from the returning data
structure.