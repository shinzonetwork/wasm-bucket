# decode_function_call

Decodes Ethereum function calls from transaction `input` data using a provided ABI.

## Input

Raw Ethereum transaction document:

```json
{
  "hash": "0x...",
  "from": "0x...",
  "to": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  "input": "0xa9059cbb000...to...value",
  "blockNumber": 18500000
}
```

## Output

```json
{
  "hash": "0x...",
  "from": "0x...",
  "to": "0x...",
  "blockNumber": 18500000,
  "function": "transfer",
  "signature": "transfer(address,uint256)",
  "arguments": [
    { "name": "to",    "type": "address", "value": "0x..." },
    { "name": "value", "type": "uint256", "value": "2000000000" }
  ]
}
```

`arguments` is a **JSON array**. Use `decode_function_call_str` if you need string-based filtering.

Documents whose `input` does not match any ABI function are passed through unchanged.

## Parameters

| Field          | Type   | Description                                              |
|----------------|--------|----------------------------------------------------------|
| `function_abi` | String | JSON array of ABI function definitions                   |
| `event_abi`    | String | JSON array of ABI event definitions (pass `"[]"` if unused) |

## Build

```bash
cargo build --target wasm32-unknown-unknown --release
```
