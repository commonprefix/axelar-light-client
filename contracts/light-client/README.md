# LightClient

Implementation of an Ethereum LightClient as a CosmWasm contract.

The main responsibility of this contract is to store the current sync committee and use it to verify Merkle proofs.
The LightClient learns about the sync committee by parsing [LightClientUpdate](https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientupdate) messages, provided from an off-chain component, in our case the [Feeder](https://github.com/commonprefix/axelar-light-client/tree/main/relayer).

From another entrypoint, it receives messages along with their respective proofs, to verify their authenticity. More information about this process can be found in the [Architecture Document](https://www.notion.so/commonprefix/Light-Client-Architecture-8fe5486c958e479ab41cdfc36a3d59ed?pvs=4#545d0c2e0b2247d79a88e3b5a7ebdc11): 

The LightClient is initialized with an instantiate message, which contains a [LightClientBootstrap](https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientbootstrap) message, along with a few options specific to the source chain (Mainnet, Sepolia, Goerli, etc.).

### Build

It is suggested to use an optimizer to build the smart contract. The LightClient has been tested with both the [CosmWasm rust-optimizer](https://github.com/CosmWasm/rust-optimizer) and [cw-optimizoor](https://github.com/mandrean/cw-optimizoor), but cw-optimizoor was much faster with similar results. In the root of the project, run: `cargo cw-optimizoor`.

**Note**: For the current Axelar Devnet, build the contract using Rust version 1.69.0

### Deploy

This process is similar to uploading any other contract on a Cosmos chain. We will use [axelard](https://github.com/axelarnetwork/axelar-core) for the deployment:
```
axelard tx wasm store <path to .wasm artifact> --from <wallet> -y --node http://devnet.rpc.axelar.dev:26657 --chain-id devnet-wasm
```

You might also have to provide extra options for gas calculations, adjust the command accordingly.

### Instantiate

Sample instantiation messages are provided for mainnet, Goerli and Sepolia deployments in `contracts/light-client/testdata/instantiate-{mainnet,goerli,sepolia}.json`. You can modify those accordingly for each new deployment.
While you can use those messages as-is, some fields that might need to be changed for each deployment are the **gateway_address**, which refers to the Axelar Gateway on the Ethereum side, and the **finalization** type, choosing between **Optimistic** and **Finality**. Refer [here](https://www.notion.so/commonprefix/Light-Client-Architecture-8fe5486c958e479ab41cdfc36a3d59ed?pvs=4#98d96718b2c34168841019297896a935) for more information on the finalization types.

The configuration of the LightClient can also be updated after the instantiation, using the **UpdateConfig** entrypoint.

### Governance

The default owner of the contract is the address that instantiated the contract. To change the owner, the current owner can use the **UpdateOwnership** entrypoint and propose a new owner. The proposed new owner then has to use the same entrypoint to accept the ownership transfer.

## Entrypoints

The entrypoints of the contract are separated between query (or view) entrypoints and execution entrypoints. The query entrypoints are free and just request some information from the contract's state, while the execution entrypoints can also modify that state and also incur some cost.

### Execution Entrypoints

#### LightClientUpdate(update: Update) -> void

It receives a LightClientUpdate message, as defined by Ethereum's Consensus Specification, verifies it with the current sync committee stored in the contract state, and then applies it to modify the current state. This entrypoint essentially update the current and next sync committees stored in the contract's state.

#### UpdateConfig(config: Config) -> void

It updates the contract's config which contains information about the chain's genesis and forks, the Axelar Gateway address and the finalization type.

#### BatchVerificationData(payload: BatchVerificationData) -> VerificationResult

This entrypoint receives all the messages to be verified, along with their proofs, and returns the verification result for each message. If a message is successfully verified, it is stored in the contract's state for later lookups.

#### UpdateOwnership(action: Action) -> void

Propose, accept and reject ownership transfers.

#### VerifyMessages( { messages: _ } ) -> void

This entrypoint is no-op and is here only to conform with the Axelar Amplifier's API interfaces.

### Query Entrypoints

#### LightClientState() -> LightClientState

It returns the state for the LightClient, which contains the last LightClientUpdate's slot, the current and the next sync committee.

#### Config() -> Config

Returns the current config.

#### IsVerified( { messages: Message[] } ) -> (Message, bool)[]

Given a vector of Messages, it returns the verification status for each.

#### IsWorkerSetVerified( { message: WorkerSetMessage } -> bool

Given a WorkerSetMessage, which describes an update of the Worker Set, it returns whether that message has been verified or not.

#### Ownership() -> Address

Returns the address of the current contract owner.
