#!/bin/bash

wallet="wallet"
node="http://devnet.rpc.axelar.dev:26657"
chain_id="devnet-wasm"
axelard="../axelar-core/bin/axelard"
wasm="./artifacts/light_client.wasm"

store_res=$($axelard tx wasm store $wasm --from $wallet -y  --gas=auto --gas-adjustment=1.5 --gas-prices 0.1uwasm --output json -b block --node $node --chain-id $chain_id)
code_id=$(echo "$store_res" | jq -r '.logs[] | select(.events[].type == "store_code") .events[] | select(.type == "store_code") .attributes[] | select(.key == "code_id") .value')

echo "Stored cosmwasm to $chain_id with code_id $code_id"
echo "Instantiating light client contract..."

instantiate_json=$(cat ./testdata/instantiate.json)
instantiate_res=$($axelard tx wasm instantiate $code_id "$instantiate_json" --from $wallet --label "test-light-client" --no-admin --node $node --chain-id $chain_id  --gas-prices 0.0001uwasm --gas 10000000)
contract_address=$(echo "$instantiate_res" | jq -r '.logs[] | select(.events[]?.type == "instantiate") .events[]? | select(.type == "instantiate") .attributes[] | select(.key == "_contract_address") .value')

echo "Instantiated light client contract with address: $contract_address"
