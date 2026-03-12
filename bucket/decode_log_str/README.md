# decode_log_str

Decodes Ethereum event logs from raw `topics` and `data` fields using a provided ABI. Same as `decode_log` but `arguments` is serialized as a JSON **string**, enabling `_like` / `_ilike` filtering in DefraDB.

## Input

Raw Ethereum log document:

```json
{
  "address": "0x...",
  "topics": ["0xddf252ad...", "0x000...from", "0x000...to"],
  "data": "0x000...value",
  "blockNumber": 18500000,
  "transaction": { "hash": "0x...", "from": "0x...", "to": "0x..." }
}
```

## Output

```json
{
  "hash": "0x...",
  "from": "0x...",
  "to": "0x...",
  "blockNumber": 18500000,
  "logAddress": "0x...",
  "event": "Transfer",
  "signature": "Transfer(address,address,uint256)",
  "arguments": "[{\"name\":\"from\",\"type\":\"address\",\"value\":\"0x...\"},{\"name\":\"to\",\"type\":\"address\",\"value\":\"0x...\"},{\"name\":\"value\",\"type\":\"uint256\",\"value\":\"2000000000\"}]"
}
```

`arguments` is a **JSON string**. Filter by address in DefraDB:

```graphql
{ MyEvent(filter: { arguments: { _like: "%0xYourAddress%" } }) { hash event arguments } }
```

## Parameters

| Field | Type   | Description                         |
|-------|--------|-------------------------------------|
| `abi` | String | JSON array of ABI event definitions |

## Build

```bash
cargo build --target wasm32-unknown-unknown --release
```
