
# Types

This package contains all of the common types that are exchanged between the multiple components of the prover/verifier. 

For the types that weren't implemented from scratch, re-exports from the following repos were used:

* [sync-committee-rs](https://github.com/commonprefix/sync-committee-rs): Used to export the basic beacon API types, along with important network constants (like SLOTS_PER_EPOCH). This is a fork of the Polytope Labs repo. 
* [axelar_wasm_std](https://github.com/axelarnetwork/axelar-amplifier). Used to export Axelar specific types.

The types package is exporting the following sub-modules:
* `common`: Types that are used in both the prover and the verifier. Also includes
  types about the content types ie `ContentVariant`. 
* `consensus`: Types regarding the Beacon API. Also includes the LightClientUpdate types.
* `execution`: Types regarding the Execution layer. Also includes the event typed signatures.
* `lightclient`: Includes specific types for the verifier.
* `primitives`: Includes the ssz primitives like `Bytelist`, `ByteVector`.
* `proofs`: This includes all of the proof related types. Every type regarding the batching and the proof generation can be found here.