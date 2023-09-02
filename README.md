# Light Client

An ethereum on-chain light client build in CosmWasm. This repo contains both the light client as a standalone module, as well as the smart contract entry points to access and use the light client.

As an MVP the contract initializes with a bootstrap message from a consensus API and a config object (see src/lightclient/types.rs). Subsequently an update message can be provided from a consensus API and if it's valid, the light client updates it's state, which can be fetched using the LightClientState query message.

The light client is heavily inspired from a16z's Helios Consensus light client, with a couple of simplifications, changes and adjustments to become a valid smart contract. Also, the light clients uses a fork of the milagro_bls library, which has been simplified to be CosmWasm compatible (see https://github.com/pkakelas/milagro_bls).

Also, currently the light client supports only ethereum mainnet due to hardcoded fork versions.

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
