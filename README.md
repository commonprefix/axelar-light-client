# Light Client

An Ethereum on-chain light client built in CosmWasm.

This repo is a collection of modules that work together to implement a light client:
- **Trie Verifier**: It is a CosmWasm module that receives an MPT root, a proof, and a leaf and verifies that the leaf is indeed a part of that root using the provided proof.
- **Light Client**: The core source of the light client.
- **Feeder**: Off-chain component that will feed the light client with Update messages from the Beacon API, as well as the necessary verification data to verify a message.
- **Types**: Common types used across the different modules.

The light client is heavily inspired by a16z's Helios Consensus light client, with a couple of simplifications, changes, and adjustments to become a valid smart contract. Also, the light client uses a fork of the milagro_bls library, which has been simplified to be CosmWasm compatible (see https://github.com/pkakelas/milagro_bls).

The light client currently supports only Ethereum Mainnet due to hardcoded fork versions.

More on the light client architecture: [Light Client Architecture](https://www.notion.so/commonprefix/Light-Client-Architecture-Draft-8fe5486c958e479ab41cdfc36a3d59ed)

## Execution Endpoints (WIP)
### `LightClientUpdate { period: u64, update: LightClientUpdate }`
It receives a LightClientUpdate message from the Ethereum Beacon API. After verifying that the update is correct, it applies the changes to the state, essentially updating the current and next sync committees if needed.

### `UpdateForks { forks: Forks }`
Receives and stores configuration about the chain's forks.

### `VerifyBlock { verification_data: BlockVerificationData }`
Receives a target block, a chain of blocks, a sync committee aggregated signature, and a signature slot, and verifies that the sync committee of the light client has signed the chain of blocks back to the target block.

### `VerifyTopicInclusion { receipt: Bytes[], topic: Bytes[] }`
It RLP-decodes the receipt from the input and verifies that the topic is included in the receipt's events.

## Test

```sh
cargo test
```

## Build

```sh
cargo wasm
cosmwasm-check ./target/wasm32-unknown-unknown/release/light_client.wasm

docker run --rm -v "$(pwd)":/code \
  --mount type=volume,source="$(basename "$(pwd)")_cache",target=/code/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  cosmwasm/rust-optimizer:0.12.11
```
