# wasm-bucket

A catalog of WebAssembly lens modules published by Shinzo Network. Each folder under `bucket/` is an independent Rust crate that compiles to a `.wasm` binary conforming to the [lens-vm](https://github.com/lens-vm/spec) ABI. Developers reference these binaries by URL when building views with `viewkit`; the view-creator CLI downloads the bytes at build time and packages them into the view bundle that gets registered on ShinzoHub.

This repo is not an executable, a library, or a service. It is a content-addressed store of compiled lenses plus their source code.

## Terminology (read first if new to this)

- **Lens**: a pure function from an input JSON document to an output JSON document, compiled to WebAssembly. Deterministic: same input + same parameters produces the same output on every host.
- **Lens module**: a single `.wasm` binary that implements one lens.
- **Bucket**: this repository. It is a catalog of lens modules. The name is storage-metaphor, not a technical term from the lens-vm spec.
- **LensVM**: the host-side runtime that loads and executes a lens module. Written in Go (`source-gh/lens/host-go/`), uses Wasmtime under the hood.
- **Lens SDK for Rust**: the Rust crate (`source-gh/lens/sdk-rust/`) that these lenses import to conform to the lens-vm ABI. If a lens were written in AssemblyScript or another wasm-producing language, it would use a different SDK but export the same functions.
- **View**: a developer-defined data transform deployed on ShinzoHub. A view has a source query (what primitive documents to pull), an SDL (what shape the output is), and an optional pipeline of one or more lenses applied to each source document.
- **View bundle (VWL)**: the compiled binary wire format of a view. Includes the query, SDL, lens arguments, and the raw wasm bytes of each lens, zstd-compressed. Encoded and decoded by `viewbundle-go`.

In short: this bucket holds lens modules. A developer assembles one or more lens modules into a view bundle via viewkit and deploys that bundle to ShinzoHub. Hosts fetch the bundle from on-chain storage and run the lenses inside it.

## How a lens fits into Shinzo

Raw blockchain data (blocks, transactions, logs) lives in each indexer's DefraDB as primitive documents. Hosts subscribe to those primitives over P2P. When a view is registered on ShinzoHub, each host downloads the view's bundle, extracts the embedded wasm bytes for each lens, loads them into its local LensVM runtime, and pipes every matching primitive document through the lens pipeline. The output is written to the host's DefraDB under the view's declared SDL type, where applications can query it via GraphQL or subscribe via P2P.

```
indexer DefraDB  --P2P-->  host receives primitive document
                                     |
                                     v
                         host LensVM instantiates the
                          wasm extracted from the bundle
                                     |
                                     v
                         lens transform(input) -> output
                                     |
                                     v
                     host DefraDB stores the result
                                     |
                     queryable via GraphQL or P2P subscription
```

## Repository layout

```
wasm-bucket/
├── bucket/
│   ├── filter/
│   │   ├── Cargo.toml
│   │   ├── filter.rs
│   │   └── filter.wasm               (committed build artifact, ~182 KB)
│   ├── decode_log/
│   │   ├── Cargo.toml
│   │   ├── decode_log.rs
│   │   └── decode_log.wasm           (committed build artifact, ~294 KB)
│   ├── decode_log_str/               (same pattern, arguments as JSON string)
│   ├── decode_function_call/
│   └── decode_function_call_str/
├── LICENSE                            (MIT, Copyright 2025 Shinzo Network)
├── README.md
└── .gitignore                         (target/, Cargo.lock, reviews/)
```

Each lens is self-contained: one `Cargo.toml`, one `.rs` source file, one compiled `.wasm`. The `.wasm` is committed to the repository so developers can reference it via a raw-file URL without running a build locally.

## The lens-vm ABI

Every module in this repo exports the same three C-ABI functions. The contract is defined by the [lens-vm spec](https://github.com/lens-vm/spec#abi---wasm-module-functions) and implemented by `lens_sdk` (see `source-gh/lens/sdk-rust/src/lib.rs`).

```rust
#[no_mangle] pub extern "C" fn alloc(size: usize) -> *mut u8
#[no_mangle] pub extern "C" fn set_param(ptr: *mut u8) -> *mut u8
#[no_mangle] pub extern "C" fn transform() -> *mut u8
```

The module also imports `next()` from the host:

```rust
#[link(wasm_import_module = "lens")]
extern "C" { fn next() -> *mut u8; }
```

Data crosses the host/guest boundary as length-prefixed byte arrays tagged with a type ID. The constants are defined in `lens_sdk`:

| Constant | Value | Meaning |
|---|---|---|
| `ERROR_TYPE_ID` | -1 | Payload is a UTF-8 error message |
| `NIL_TYPE_ID` | 0 | No value (skip this document, try again) |
| `JSON_TYPE_ID` | 1 | Payload is a JSON document |
| `EOS_TYPE_ID` | 127 | End of stream; source yields no more values |

A typical `transform()` implementation:

1. Call `next()` to get a pointer to the next input document.
2. Deserialize the payload with `lens_sdk::try_from_mem::<T>(ptr)`.
3. If the input matches what this lens cares about, decode and rebuild the output document. Otherwise, pass it through unchanged.
4. Serialize the result and return it with `lens_sdk::to_mem(JSON_TYPE_ID, &bytes)`.
5. Return a nil pointer for skipped documents, or an EOS pointer when the source is exhausted.

Parameters set via `set_param` are deserialized with serde and stored in a `static RwLock<Option<Parameters>>` so subsequent `transform()` calls can read them.

## The current lenses

| Lens | Purpose | Output shape | Tests |
|---|---|---|---|
| `filter` | Pass through documents whose top-level string field equals a target value; drop the rest | Input unchanged (on match) or nil (on drop) | 9 passing |
| `decode_log` | ABI-decode Ethereum event logs | JSON document with `arguments` array | 17 passing |
| `decode_log_str` | Same as above, arguments serialized as JSON string | JSON document with `arguments` as string | shares decoder with `decode_log` |
| `decode_function_call` | ABI-decode Ethereum transaction `input` data | JSON document with `arguments` array | 8 passing |
| `decode_function_call_str` | Decodes function call + nested events, both with string `arguments` | JSON document with stringified arguments | shares decoder with `decode_function_call` |

All five crates are on `edition = "2024"` and `lens_sdk = "^0.8.1"` (the latest published version on crates.io as of August 2025). The four `decode_*` crates additionally share decoder helpers (`parse_uint_bits`, `parse_int_bits`, `parse_bytes_n`, `decode_uint`, `decode_int`, `decode_bytes_n`); `filter` has no decoder dependency and therefore ships a smaller wasm (~180 KB vs ~300 KB).

The `_str` variants exist because DefraDB's `_like` / `_ilike` GraphQL filters operate on scalar strings, not on nested array fields. Serializing `arguments` as an opaque JSON string lets you filter view documents by substring matching on the encoded arguments (for example, finding every Transfer that mentions a particular address) without the host having to split each argument into its own collection.

### filter

**Parameters:**

| Field | Type | Description |
|---|---|---|
| `src` | String | Name of the top-level field to read from each input document |
| `value` | String | Expected value, compared case-insensitively (ASCII) |

**Input:** any JSON object with a top-level string field named by `src`.

**Output:**

- On match: the input document unchanged (re-serialized from the same in-memory shape; no field ordering guarantee beyond what the JSON serializer produces).
- On mismatch (including missing field, non-string field, null): `NIL_TYPE_ID`. Downstream lenses see nothing for this iteration, and the host skips it the same way it handles an empty source yield.

**Typical usage** in a view's lens chain (from `shinzo-app`'s codegen output):

```json
{
  "lenses": [
    {
      "label": "filter_by_address",
      "source": "wasm-bucket/filter/filter.wasm",
      "args": {"src": "address", "value": "0x000000000004444c5dc75cB358380D2e3dE08A90"}
    },
    {
      "label": "decode_log_str",
      "source": "wasm-bucket/decode_log_str/decode_log_str.wasm",
      "args": {"abi": "[...]"}
    }
  ]
}
```

Without the filter, `decode_log_str` would receive every `Log` document on the chain and decode every signature that happens to match one of the events in the provided ABI — which means every ERC20 `Transfer` emitted by any contract (they all share `topics[0] = 0xddf252ad...`) would land in the view's output collection regardless of which contract emitted it.

**What this lens does NOT do:**

- No regex / glob / prefix matching. Exact (case-insensitive) equality only.
- No inequality, membership (`in`), or multi-value compare. Each would be a separate lens crate, not a parameter on this one.
- No nested field access (`transaction.from`). Top-level only.

These are deliberate scope decisions; keeping the contract narrow makes the lens trivially correct. Add a new crate when one of these is actually needed.

**Why case-insensitive compare.** Ethereum addresses are commonly pasted into `config.yaml` in EIP-55 checksummed form (mixed case), while indexers normalize to lowercase when storing `Log` documents. Case-insensitive match bridges the two without forcing config authors to hand-lowercase their addresses. Fields that ARE case-sensitive (IPFS CIDs, signed message hashes) should not be filtered by this lens today; add a case-sensitive variant if that use case materializes.

### decode_log and decode_log_str

**Parameters:**

| Field | Type | Description |
|---|---|---|
| `abi` | String | JSON array of ABI event definitions |

**Input:** a Log primitive document. Relevant fields: `address`, `topics` (array of hex strings), `data` (hex string), `blockNumber`, and a nested `transaction` object with `hash`, `from`, `to`.

**Output** (decode_log, array form):

```json
{
  "hash": "0x...",
  "from": "0x...",
  "to": "0x...",
  "blockNumber": 18500000,
  "logAddress": "0x...",
  "event": "Transfer",
  "signature": "Transfer(address,address,uint256)",
  "arguments": [
    {"name": "from",  "type": "address", "value": "0x..."},
    {"name": "to",    "type": "address", "value": "0x..."},
    {"name": "value", "type": "uint256", "value": "2000000000"}
  ]
}
```

The `_str` variant emits `"arguments": "[{\"name\":\"from\",...}]"` (same content, JSON-encoded as a string).

**Type coverage** (as of commit `fc12113`, April 14, 2026):

- `uintN` for N in 8..256 step 8, decoded via `num-bigint::BigUint`, emitted as decimal string
- `intN` for N in 8..256 step 8, two's-complement decode; negative values emit with a leading `-`
- `address`, right-aligned in the 32-byte word, lowercased hex
- `bool`, 0 or nonzero
- `bytesN` for N in 1..32, left-aligned, emitted as `0x...` hex
- `string`, `bytes`, arrays, tuples: not supported. The 32-byte slot is returned as raw hex. Downstream consumers like `shinzo-app` reject these types at codegen time.
- Anonymous events: not supported. `topic_idx` starts at 1 assuming `topics[0]` is the signature hash.

Events whose `topics[0]` does not match any event in the provided ABI emit `{"event": "Unknown", "signature": "", "arguments": []}`, so the document still flows through the pipeline.

### decode_function_call and decode_function_call_str

**Parameters:**

| Field | Type | Description |
|---|---|---|
| `function_abi` | String | JSON array of ABI function definitions |
| `event_abi` | String | JSON array of ABI event definitions, `"[]"` if unused |

**Input:** a Transaction primitive document with `hash`, `from`, `to`, `input`, `blockNumber`. The `input` field is the call data hex string; the first 4 bytes are the function selector.

**Output** (array form):

```json
{
  "hash": "0x...",
  "from": "0x...",
  "to": "0x...",
  "blockNumber": 18500000,
  "function": "transfer",
  "signature": "transfer(address,uint256)",
  "arguments": [
    {"name": "to",    "type": "address", "value": "0x..."},
    {"name": "value", "type": "uint256", "value": "2000000000"}
  ]
}
```

Transactions whose selector does not match any function in the ABI are passed through unchanged (no `function`, `signature`, or `arguments` fields are added). This differs from `decode_log`, which tags unmatched logs with `"event": "Unknown"`.

Argument decoding reads 32 bytes per input parameter. Same static-type-only limitations as `decode_log`.

## End-to-end flow: how a lens from this bucket ends up running on a host

This is the important part to understand, and it surprises people on first read. The raw-file URL you see in `viewkit view add lens` commands is **not** fetched by the host at runtime. Follow the bytes:

1. **At `viewkit view add lens` time**, `core/service/view.go:108-128` downloads the wasm bytes from the URL (or reads from a local `--path`), validates them with `util.IsValidWasm`, and stores them in the developer's local view assets directory. The URL's job ends here. The bytes are now local.
2. **At `viewkit view deploy` time**, `core/service/deploy.go:111-131` reads those stored bytes, base64-encodes them, and passes them to `viewbundle.BundleView(...)` along with the query, SDL, and argument JSON for each lens.
3. **`viewbundle.BundleView`** packs the query, SDL, arguments, and compressed wasm bytes into the VWL wire format (see `shinzo-gh/viewbundle-go/codec.go`). Result: one byte blob.
4. **Viewkit sends an EVM transaction** to the ViewRegistry precompile at `0x0210` on ShinzoHub with the wire bytes as call data.
5. **The precompile** decodes the bundle header, validates it, calls `RegisterObject` on SourceHub via ICA, deploys an SVS-1 per-view contract, stores the wire bytes, and emits a `Registered(key, creator)` event.
6. **Each host** watches for `Registered` events, pulls the wire bytes from ShinzoHub state, calls `viewbundle.UnbundleView(wireBytes)` to extract the query, SDL, and each lens's wasm + arguments.
7. **The host** hands each lens's wasm bytes to its local LensVM engine, which instantiates the module under Wasmtime, calls `set_param` once with the argument JSON, and keeps the instance ready.
8. **As primitive documents flow in** via P2P gossip, any document matching the view's source query gets piped through `transform()`. The lens writes output bytes which the host stores as a new document in the view's collection.

So the raw-file URL pattern below is a developer-side convenience, not a runtime dependency. Once the bundle is on-chain, the host does not need this repo or the raw-file URL to run the lens.

A separate code path in `source-gh/lens/host-go/engine/engine.go:74-99` does allow loading a lens module by `http://`, `https://`, or `file://` URL at runtime. That is a general LensVM capability. Shinzo's view pipeline does not exercise it: `viewbundle` embeds the bytes directly.

## How a developer uses a lens from this bucket

Workflow via `viewkit` (the CLI in `shinzo-view-creator`):

```bash
# Create a view scaffold
viewkit view create my-usdc-view \
  --query 'Ethereum__Mainnet__Log { address topics data transactionHash blockNumber }'

# Declare the output shape. @materialized(if: true) pre-computes the data on write.
viewkit view add sdl \
  'type USDCTransfer @materialized(if: true) { hash: String event: String arguments: String }' \
  --name my-usdc-view

# Add a lens pipeline step. --url downloads the wasm at this step and stores it locally.
viewkit view add lens \
  --label "decode_transfers" \
  --url "https://raw.githubusercontent.com/shinzonetwork/wasm-bucket/main/bucket/decode_log_str/decode_log_str.wasm" \
  --args '{"abi":"[{\"type\":\"event\",\"name\":\"Transfer\",\"inputs\":[{\"name\":\"from\",\"type\":\"address\",\"indexed\":true},{\"name\":\"to\",\"type\":\"address\",\"indexed\":true},{\"name\":\"value\",\"type\":\"uint256\",\"indexed\":false}]}]"}' \
  --name my-usdc-view

# Bundle and deploy. The wasm bytes end up embedded in the VWL bundle on ShinzoHub.
viewkit view deploy my-usdc-view --target devnet --rpc http://rpc.devnet.shinzo.network:8545
```

Alternative to `--url`: `viewkit view add lens --path ./local/path/to/lens.wasm ...`. Both paths (URL and local file) result in the same bytes being stored locally.

The SDL uses `arguments: String` here because `decode_log_str` serializes `arguments` as a JSON string, which allows `_like` filtering in GraphQL queries against the deployed view.

## Building a lens

Rust toolchain with the `wasm32-unknown-unknown` target. From inside a lens folder:

```bash
rustup target add wasm32-unknown-unknown   # once per machine
cargo build --target wasm32-unknown-unknown --release
cp target/wasm32-unknown-unknown/release/<crate_name>.wasm <crate_name>.wasm
```

The final `.wasm` goes at the top level of the lens folder so the raw-file URL resolves to it. Output sizes for the current lenses: ~250-300 KB each. Rust is the current default for production lenses; AssemblyScript is supported by LensVM and produces smaller binaries (~70-100 KB). See `source-gh/lens/tests/modules/as_wasm32_simple/` for an AssemblyScript example.

## Adding a new lens

1. Create `bucket/<new_lens_name>/` with a `Cargo.toml`, a `<new_lens_name>.rs`, and a `README.md` documenting the input, output, and parameter shape.
2. Implement `alloc`, `set_param`, `transform` using `lens_sdk`. Follow the structure of `bucket/decode_log/decode_log.rs`.
3. Build the `.wasm` with the command above.
4. Commit the source, `Cargo.toml`, `README.md`, and `.wasm`.
5. The raw-file URL becomes the stable reference developers use in `viewkit view add lens --url`.

`Cargo.lock` and `target/` are gitignored so each lens has a stable dependency set at source level but does not carry build artifacts beyond the `.wasm` itself.

## References

- Lens-vm ABI spec: https://github.com/lens-vm/spec
- LensVM Go host runtime: `source-gh/lens/host-go/` (module `github.com/sourcenetwork/lens/host-go`, Go 1.24.6, Wasmtime v35)
- `lens_sdk` Rust crate: `source-gh/lens/sdk-rust/src/lib.rs`
- ViewKit CLI (downloads these wasm files, bundles them): `shinzo-gh/shinzo-view-creator`
- VWL wire format (packs wasm bytes into the bundle): `shinzo-gh/viewbundle-go`
- Host that fetches bundles and runs lenses: `shinzo-gh/shinzo-host-client`

## License

MIT. See `LICENSE`.
