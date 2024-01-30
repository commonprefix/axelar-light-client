# Relayer

This is the main module of the relayer, responsible for consuming the events
from the queue, generating the necessary proofs, and providing them to the
verifier along with the event.  The relayer consists of multiple modules
responsible for consuming and parsing events from the queue, proof generation,
chain integrations, and communicating with a CosmWasm-compatible chain. The
relayer module needs to have access to both the Axelar and the Ethereum chain.
Also, this is a trustless component, and there can be multiple instances of the
relayer (i.e. anyone can generate proofs and submit them to the verifier).

## Modes

The relayer currently works in 2 modes:

### Relay

The Relayer operates by periodically polling the Sentinel queue, and searching
for new events. If there are new **ContractCall** or **OperatorshipTransferred**
events that it has not processed, it will start processing them.

It retrieves the latest **LightClientUpdate** message. Depending on the chosen
verification method, it either fetches a **FinalityUpdate** or an 
**OptimisticUpdate** message. Based on the Update message, it filters events in
the queue and only processes those whose block is an ancestor of the block in
the Update message.

Subsequently, the Relayer fetches the Execution Block and the Beacon Block from
the Execution and Consensus RPCs, respectively. It then parses the event from
the queue and constructs a Content structure.  After the generation of the
contents, the relayer uses the prover to generate the proofs and submits them
to the verifier for verification.

In case the verification succeeded it acks the contents otherwise:
- If the content cannot be parsed, it gets removed from the queue.
- If the auxiliary data cannot be fetched from eth the event is being re-queued
- If the proofs are not generated correctly the event gets re-queued
- If the rabbitMQ is down, the relayer shuts down.

### Feed

The Feeder operates by periodically fetching the state of the verifier and the
latest LightClientUpdate message from the verifier. In each round, if the
verifier is not synced with the latest period, the feeder applies the new
updates to the feeder up to the point where the verifier is up-to-date.

## Setup
- `cargo build`
- `cp .env.template .env`
- Configure the `.env` with the properties as described in the `.env.template`
- Run `RUST_LOG=debug cargo run --bin relay` for the relayer
- Run `RUST_LOG=debug cargo run --bin feed` for the feeder