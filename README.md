# Ethereum Light Client

An Ethereum prover/verifier implementation of a light client that employs the
Sync Committee protocol of Ethereum to bridge events from Ethereum to Axelar.

This repo is a collection of modules that work together to implement a light client.
- **Light Client**: The core source of the verifier.
- **Contracts** The module that packages the light client verifier in an on-chain CosmWasm contract.
- **Feeder**: Off-chain component that will feed the light client with Update
messages to keep up with the latest sync-committee.
- **Types**: Common types used across the different modules.
- **Relayer**: The core off-chain component, responsible for consuming the
events from the queue, generating the the necessary proofs, and providing them
to the verifier along with the event.
- **Eth** An auxiliary package for querying the Ethereum beacon and execution APIs.

More details about the packages are in their corresponding READMEs.

## Setting up the relayer
The relayer module consumes events from a rabbitMQ instance that is implemented
in Axelar and submits them to the on-chain verifier that exists in the
`light-client` package. In order to setup the relayer the following steps are
required.
- Setup an instance of the [state prover](https://github.com/commonprefix/state-prover)
- Obtain an Ethereum Beacon and Execution API URLs, the gateway address and the
Wasm URL.
- Deploy the light client verifier by following the instructions in the
`contracts` package.
- Go to the `relayer` package and follow the instructions mentioned there for
running both the feeder and the relayer.

More on the light client architecture: [Light Client Architecture]

## Acknowledgments
This project uses open-source code from the following projects. We are deeply
grateful for all the work they've put into developing this software, their
commitment to open-source software, and for licensing the work using a
permissive license which allowed us to incorporate their work:
- [Helios](https://github.com/a16z/helios/) for a major part of the light client
verification/processing.
- [Polytope's sync_committee_primitives](https://github.com/polytope-labs/sync-committee-rs) for the Goerli and mainnet constants as well as some primitive beacon types.
- [ethers.rs](https://github.com/gakonst/ethers-rs) and
[alloy.rs](https://github.com/alloy-rs/core) for communicating with Ethereum and
for encoding/decoding execution messages.
- [ssz_rs](https://github.com/polytope-labs/ssz-rs) for SSZ serialization/deserialization.