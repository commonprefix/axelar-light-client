# Ethereum Light Client

An Ethereum prover/verifier implementation of a light client that employs the
Sync Committee protocol of Ethereum to bridge events from Ethereum to Axelar.

More on the [Light Client Architecture](https://commonprefix.notion.site/Light-Client-Architecture-Draft-8fe5486c958e479ab41cdfc36a3d59ed?pvs=4)

This repo is a collection of modules that work together to implement a light client.
- **[Relayer/Feeder](https://github.com/commonprefix/axelar-light-client/tree/main/relayer)**: The core off-chain component, responsible for consuming
the events from the queue, generating the the necessary proofs, and providing
them to the verifier along with the event. It also includes an off-chain
component that will feed the light client with Update messages to keep up with
the latest sync-committee.
- **[Light Client](https://github.com/commonprefix/axelar-light-client/tree/main/contracts/light-client)**: The core source of the verifier.
- **[Types](https://github.com/commonprefix/axelar-light-client/tree/main/types)**: Common types used across the different modules.
- **[Eth](https://github.com/commonprefix/axelar-light-client/tree/main/eth)** An auxiliary package for querying the Ethereum beacon and execution APIs.

More details about the packages are in their corresponding READMEs.

## Setting up the relayer
The relayer module consumes events from a rabbitMQ instance that is implemented
in Axelar and submits them to the on-chain verifier that exists in the
`light-client` package. To set up the relayer the following steps are
required.
- Set up an instance of the [state prover](https://github.com/commonprefix/state-prover).
- Obtain an Ethereum Beacon and Execution API URLs, the gateway address and the
Wasm URL.
- Deploy the light client verifier by following the instructions in the
`contracts` package.
- Go to the `relayer` package and follow the instructions mentioned there for
running both the feeder and the relayer.

## Documentation
Along with the README files, code documentation is also available using the `cargo doc --open` command.

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
