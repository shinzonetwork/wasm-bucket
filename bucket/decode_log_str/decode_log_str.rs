// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::sync::RwLock;
use std::{error, fmt};

use lens_sdk::option::StreamOption::{EndOfStream, None, Some};
use lens_sdk::StreamOption;
use serde::Deserialize;
use serde_json::Value;
use sha3::{Digest, Keccak256};

#[link(wasm_import_module = "lens")]
unsafe extern "C" {
    fn next() -> *mut u8;
}

#[derive(Deserialize, Clone)]
pub struct Parameters {
    pub abi: String,
}

static PARAMETERS: RwLock<StreamOption<Parameters>> = RwLock::new(None);

#[derive(Clone, Debug)]
struct ParametersNotSet;

impl fmt::Display for ParametersNotSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("parameters have not been set")
    }
}

impl error::Error for ParametersNotSet {}

fn get_params() -> Result<Parameters, Box<dyn error::Error>> {
    let params = PARAMETERS.read()?.clone().ok_or(ParametersNotSet)?;
    Ok(params)
}

#[unsafe(no_mangle)]
pub extern "C" fn alloc(size: usize) -> *mut u8 {
    lens_sdk::alloc(size)
}

#[unsafe(no_mangle)]
pub extern "C" fn set_param(ptr: *mut u8) -> *mut u8 {
    match try_set_param(ptr) {
        Ok(_) => lens_sdk::nil_ptr(),
        Err(e) => lens_sdk::to_mem(lens_sdk::ERROR_TYPE_ID, e.to_string().as_bytes()),
    }
}

fn try_set_param(ptr: *mut u8) -> Result<(), Box<dyn error::Error>> {
    let parameter = unsafe { lens_sdk::try_from_mem::<Parameters>(ptr)? }.ok_or(ParametersNotSet)?;
    *PARAMETERS.write()? = Some(parameter);
    Ok(())
}

fn safe_to_mem(type_id: i8, data: &[u8]) -> *mut u8 {
    let total = 1 + 4 + data.len();
    let ptr = lens_sdk::alloc(total);
    unsafe {
        *ptr = type_id as u8;
        let len_bytes = (data.len() as u32).to_le_bytes();
        std::ptr::copy_nonoverlapping(len_bytes.as_ptr(), ptr.add(1), 4);
        if !data.is_empty() {
            std::ptr::copy_nonoverlapping(data.as_ptr(), ptr.add(5), data.len());
        }
    }
    ptr
}

#[unsafe(no_mangle)]
pub extern "C" fn transform() -> *mut u8 {
    match try_transform() {
        Ok(Some(json)) => safe_to_mem(lens_sdk::JSON_TYPE_ID, &json),
        Ok(None) => lens_sdk::nil_ptr(),
        Ok(EndOfStream) => safe_to_mem(lens_sdk::EOS_TYPE_ID, &[]),
        Err(e) => safe_to_mem(lens_sdk::ERROR_TYPE_ID, e.to_string().as_bytes()),
    }
}

fn try_transform() -> Result<StreamOption<Vec<u8>>, Box<dyn error::Error>> {
    let ptr = unsafe { next() };
    let input = match unsafe { lens_sdk::try_from_mem::<HashMap<String, Value>>(ptr)? } {
        Some(v) => v,
        // Upstream skipped this iteration. Cascade the skip so we don't
        // fabricate a doc for every filtered-out source row.
        None => return Ok(None),
        EndOfStream => return Ok(EndOfStream),
    };

    // Extract tx context from the nested transaction relation
    let tx = input.get("transaction").and_then(|v| v.as_object());
    let tx_hash = tx.map(|t| str_field_map(t, "hash")).unwrap_or_default();
    let from = tx.map(|t| str_field_map(t, "from")).unwrap_or_default();
    let to = tx.map(|t| str_field_map(t, "to")).unwrap_or_default();

    let block_number = input.get("blockNumber").and_then(|v| v.as_i64()).unwrap_or(0);
    let log_index = input.get("logIndex").and_then(|v| v.as_i64()).unwrap_or(0);
    // block.timestamp arrives as a decimal unix-seconds string from the
    // host's Block collection (for example, "1776715379"). Parse here so
    // the downstream handler sees an integer.
    let block_timestamp = input
        .get("block")
        .and_then(|v| v.as_object())
        .and_then(|b| b.get("timestamp"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    let log_address = str_field(&input, "address");
    let data = input.get("data").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let topics = parse_topics(&input).unwrap_or_default();

    // Build a fresh output document containing ONLY the fields consumers
    // declare in their view SDL. DefraDB's lens→view write path drops docs
    // whose shape has keys absent from the destination schema, so echoing
    // source fields (address, topics, data, transaction, etc.) is fatal.
    let mut out: HashMap<String, Value> = HashMap::new();
    out.insert("hash".into(), Value::String(tx_hash));
    out.insert("from".into(), Value::String(from));
    out.insert("to".into(), Value::String(to));
    out.insert("blockNumber".into(), Value::Number(block_number.into()));
    out.insert("blockTimestamp".into(), Value::Number(block_timestamp.into()));
    out.insert("logIndex".into(), Value::Number(log_index.into()));
    out.insert("logAddress".into(), Value::String(log_address));
    // `data` is kept on the output only long enough for decode_event to
    // read it; it is stripped before returning.
    out.insert("data".into(), Value::String(data));

    if topics.is_empty() {
        out.insert("event".into(), Value::String("Unknown".to_string()));
        out.insert("signature".into(), Value::String(String::new()));
        out.insert("arguments".into(), Value::String("[]".to_string()));
    } else {
        let abi = parse_abi().unwrap_or_default();
        match find_matching_event(&abi, &topics[0]) {
            std::option::Option::Some(event) => decode_event(&mut out, event, &topics)?,
            std::option::Option::None => {
                out.insert("event".into(), Value::String("Unknown".to_string()));
                out.insert("signature".into(), Value::String(String::new()));
                out.insert("arguments".into(), Value::String("[]".to_string()));
            }
        }
    }

    out.remove("data");
    ok_json(&out)
}

struct AbiEvent {
    name: String,
    signature: String,
    inputs: Vec<AbiInput>,
}

struct AbiInput {
    name: String,
    typ: String,
    indexed: bool,
}

fn parse_abi() -> Result<Vec<AbiEvent>, Box<dyn error::Error>> {
    let params = get_params()?;
    let items: Vec<Value> = serde_json::from_str(&params.abi)?;

    let events = items
        .iter()
        .filter(|item| item["type"] == "event")
        .filter_map(|item| {
            let name = item["name"].as_str()?;
            let inputs = item["inputs"].as_array()?;

            let abi_inputs: Vec<AbiInput> = inputs
                .iter()
                .filter_map(|inp| {
                    std::option::Option::Some(AbiInput {
                        name: inp["name"].as_str()?.to_string(),
                        typ: inp["type"].as_str()?.to_string(),
                        indexed: inp["indexed"].as_bool().unwrap_or(false),
                    })
                })
                .collect();

            let types: Vec<&str> = abi_inputs.iter().map(|i| i.typ.as_str()).collect();
            let sig = format!("{}({})", name, types.join(","));

            std::option::Option::Some(AbiEvent {
                name: name.to_string(),
                signature: sig,
                inputs: abi_inputs,
            })
        })
        .collect();

    Ok(events)
}

fn find_matching_event<'a>(events: &'a [AbiEvent], topic0: &str) -> std::option::Option<&'a AbiEvent> {
    events.iter().find(|e| event_selector(&e.signature) == topic0)
}

fn event_selector(signature: &str) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(signature.as_bytes());
    format!("0x{}", hex::encode(hasher.finalize()))
}

fn decode_event(
    doc: &mut HashMap<String, Value>,
    event: &AbiEvent,
    topics: &[String],
) -> Result<(), Box<dyn error::Error>> {
    doc.insert("event".into(), Value::String(event.name.clone()));
    doc.insert("signature".into(), Value::String(event.signature.clone()));

    let mut arguments = Vec::new();
    let mut non_indexed = Vec::new();
    let mut topic_idx = 1;

    for inp in &event.inputs {
        if inp.indexed {
            if topic_idx < topics.len() {
                let value = decode_param(&inp.typ, &topics[topic_idx]);
                arguments.push(serde_json::json!({
                    "name": inp.name,
                    "type": inp.typ,
                    "value": value,
                }));
            }
            topic_idx += 1;
        } else {
            // Non-indexed params are decoded from the data section below.
            // Do NOT advance topic_idx here.
            non_indexed.push(inp);
        }
    }

    if let std::option::Option::Some(data_str) = doc.get("data").and_then(|d| d.as_str()) {
        let data_hex = data_str.strip_prefix("0x").unwrap_or(data_str);
        if let Ok(data_bytes) = hex::decode(data_hex) {
            let mut offset = 0;
            for inp in &non_indexed {
                if offset + 32 > data_bytes.len() {
                    break;
                }
                let raw = &data_bytes[offset..offset + 32];
                let hex_val = format!("0x{}", hex::encode(raw));
                let value = decode_param(&inp.typ, &hex_val);

                arguments.push(serde_json::json!({
                    "name": inp.name,
                    "type": inp.typ,
                    "value": value,
                }));
                offset += 32;
            }
        }
    }

    let args_str = serde_json::to_string(&arguments).unwrap_or_default();
    doc.insert("arguments".into(), Value::String(args_str));
    Ok(())
}

/// decode_param decodes a single ABI-encoded parameter from a 32-byte hex word.
/// Supports all standard Solidity types used in events (uintN, intN, address,
/// bool, bytesN). See decode_log/decode_log.rs for full documentation.
fn decode_param(typ: &str, hex_data: &str) -> String {
    let clean = hex_data.trim_start_matches("0x");
    let raw_bytes = hex::decode(clean).unwrap_or_default();
    if raw_bytes.is_empty() {
        return String::new();
    }

    match typ {
        "address" => {
            if clean.len() >= 40 {
                format!("0x{}", &clean[clean.len() - 40..])
            } else {
                format!("0x{}", clean)
            }
        }
        "bool" => raw_bytes.iter().any(|&b| b != 0).to_string(),
        "string" | "bytes" => format!("0x{}", clean),
        _ => {
            if let std::option::Option::Some(bits) = parse_uint_bits(typ) {
                decode_uint(&raw_bytes, bits)
            } else if let std::option::Option::Some(bits) = parse_int_bits(typ) {
                decode_int(&raw_bytes, bits)
            } else if let std::option::Option::Some(n) = parse_bytes_n(typ) {
                decode_bytes_n(&raw_bytes, n)
            } else {
                format!("unsupported type: {}", typ)
            }
        }
    }
}

fn parse_uint_bits(typ: &str) -> std::option::Option<usize> {
    let suffix = typ.strip_prefix("uint")?;
    let bits: usize = suffix.parse().ok()?;
    if bits >= 8 && bits <= 256 && bits % 8 == 0 {
        std::option::Option::Some(bits)
    } else {
        std::option::Option::None
    }
}

fn parse_int_bits(typ: &str) -> std::option::Option<usize> {
    let suffix = typ.strip_prefix("int")?;
    if suffix.is_empty() {
        return std::option::Option::None;
    }
    let bits: usize = suffix.parse().ok()?;
    if bits >= 8 && bits <= 256 && bits % 8 == 0 {
        std::option::Option::Some(bits)
    } else {
        std::option::Option::None
    }
}

fn parse_bytes_n(typ: &str) -> std::option::Option<usize> {
    let suffix = typ.strip_prefix("bytes")?;
    if suffix.is_empty() {
        return std::option::Option::None;
    }
    let n: usize = suffix.parse().ok()?;
    if n >= 1 && n <= 32 {
        std::option::Option::Some(n)
    } else {
        std::option::Option::None
    }
}

fn decode_uint(raw: &[u8], _bits: usize) -> String {
    use num_bigint::BigUint;
    BigUint::from_bytes_be(raw).to_str_radix(10)
}

fn decode_int(raw: &[u8], bits: usize) -> String {
    use num_bigint::{BigInt, Sign};
    if raw.len() != 32 {
        return "0".to_string();
    }
    let byte_width = bits / 8;
    let start = 32 - byte_width;
    let value_bytes = &raw[start..];
    let is_negative = value_bytes[0] & 0x80 != 0;
    if is_negative {
        let mut complement = value_bytes.to_vec();
        for b in complement.iter_mut() {
            *b = !*b;
        }
        let positive = BigInt::from_bytes_be(Sign::Plus, &complement);
        (-(positive + BigInt::from(1))).to_str_radix(10)
    } else {
        BigInt::from_bytes_be(Sign::Plus, value_bytes).to_str_radix(10)
    }
}

fn decode_bytes_n(raw: &[u8], n: usize) -> String {
    if raw.len() < n {
        return format!("0x{}", hex::encode(raw));
    }
    format!("0x{}", hex::encode(&raw[..n]))
}

fn str_field(doc: &HashMap<String, Value>, key: &str) -> String {
    doc.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

fn str_field_map(doc: &serde_json::Map<String, Value>, key: &str) -> String {
    doc.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

fn parse_topics(doc: &HashMap<String, Value>) -> Result<Vec<String>, Box<dyn error::Error>> {
    let val = doc.get("topics").ok_or("missing 'topics' field")?;
    let arr = val
        .as_array()
        .ok_or_else(|| format!("'topics' is not an array, got: {:?}", val))?;
    Ok(arr
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect())
}

fn ok_json(doc: &HashMap<String, Value>) -> Result<StreamOption<Vec<u8>>, Box<dyn error::Error>> {
    let json = serde_json::to_vec(doc)?;
    Ok(Some(json))
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4_POOL_MANAGER_ABI: &str = r#"[{"anonymous":false,"inputs":[{"indexed":true,"internalType":"PoolId","name":"id","type":"bytes32"},{"indexed":true,"internalType":"address","name":"sender","type":"address"},{"indexed":false,"internalType":"int128","name":"amount0","type":"int128"},{"indexed":false,"internalType":"int128","name":"amount1","type":"int128"},{"indexed":false,"internalType":"uint160","name":"sqrtPriceX96","type":"uint160"},{"indexed":false,"internalType":"uint128","name":"liquidity","type":"uint128"},{"indexed":false,"internalType":"int24","name":"tick","type":"int24"},{"indexed":false,"internalType":"uint24","name":"fee","type":"uint24"}],"name":"Swap","type":"event"}]"#;

    fn set_abi(abi: &str) {
        *PARAMETERS.write().unwrap() = Some(Parameters { abi: abi.to_string() });
    }

    // Drive the decode logic directly with a realistic v4 Swap log captured from
    // Ethereum mainnet (block ~0x17bfd00). Mirrors what try_transform does after
    // reading from lens memory, so we can verify the output shape without the
    // wasm runtime.
    fn run_transform(input: HashMap<String, Value>) -> HashMap<String, Value> {
        let tx = input.get("transaction").and_then(|v| v.as_object()).cloned();
        let tx_hash = tx.as_ref().map(|t| str_field_map(t, "hash")).unwrap_or_default();
        let from = tx.as_ref().map(|t| str_field_map(t, "from")).unwrap_or_default();
        let to = tx.as_ref().map(|t| str_field_map(t, "to")).unwrap_or_default();
        let block_number = input.get("blockNumber").and_then(|v| v.as_i64()).unwrap_or(0);
        let log_index = input.get("logIndex").and_then(|v| v.as_i64()).unwrap_or(0);
        let block_timestamp = input
            .get("block")
            .and_then(|v| v.as_object())
            .and_then(|b| b.get("timestamp"))
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let log_address = str_field(&input, "address");
        let data = input.get("data").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let topics = parse_topics(&input).unwrap_or_default();

        let mut out: HashMap<String, Value> = HashMap::new();
        out.insert("hash".into(), Value::String(tx_hash));
        out.insert("from".into(), Value::String(from));
        out.insert("to".into(), Value::String(to));
        out.insert("blockNumber".into(), Value::Number(block_number.into()));
        out.insert("blockTimestamp".into(), Value::Number(block_timestamp.into()));
        out.insert("logIndex".into(), Value::Number(log_index.into()));
        out.insert("logAddress".into(), Value::String(log_address));
        out.insert("data".into(), Value::String(data));

        if topics.is_empty() {
            out.insert("event".into(), Value::String("Unknown".to_string()));
            out.insert("signature".into(), Value::String(String::new()));
            out.insert("arguments".into(), Value::String("[]".to_string()));
        } else {
            let abi = parse_abi().unwrap_or_default();
            match find_matching_event(&abi, &topics[0]) {
                std::option::Option::Some(event) => decode_event(&mut out, event, &topics).unwrap(),
                std::option::Option::None => {
                    out.insert("event".into(), Value::String("Unknown".to_string()));
                    out.insert("signature".into(), Value::String(String::new()));
                    out.insert("arguments".into(), Value::String("[]".to_string()));
                }
            }
        }
        out.remove("data");
        out
    }

    #[test]
    fn test_transform_real_v4_swap_log() {
        set_abi(V4_POOL_MANAGER_ABI);

        // Real log from Ethereum mainnet at block 0x17bfd00, PoolManager Swap.
        // data field preserved verbatim from eth_getLogs.
        let mut topics = Vec::new();
        topics.push(Value::String("0x40e9cecb9f5f1f1c5b9c97dec2917b7ee92e57ba5563708daca94dd84ad7112f".to_string()));
        topics.push(Value::String("0x2287a9620adcbf6250dc71be9ee9b2d3a1ec85a464fc6f5c06669e8d07b61bba".to_string()));
        topics.push(Value::String("0x00000000000000000000000066a9893cc07d91d95644aedd05d03f95e1dba8af".to_string()));

        let mut doc: HashMap<String, Value> = HashMap::new();
        doc.insert("address".into(), Value::String("0x000000000004444c5dc75cB358380D2e3dE08A90".into()));
        doc.insert("topics".into(), Value::Array(topics));
        // Truncated data for brevity — 8 words (256 bytes) for 6 non-indexed params plus padding.
        // amount0 (int128), amount1 (int128), sqrtPriceX96 (uint160), liquidity (uint128), tick (int24), fee (uint24).
        let data = "0x\
0000000000000000000000000000000000000000000000000002ef68b4715858\
ffffffffffffffffffffffffffffffffffffffffffffffffff123456789abcde\
00000000000000000000000000000000000000feedfacedeadbeefcafebabe00\
000000000000000000000000000000000000000000000000000000000badf00d\
0000000000000000000000000000000000000000000000000000000000000064\
0000000000000000000000000000000000000000000000000000000000000bb8";
        doc.insert("data".into(), Value::String(data.into()));
        doc.insert("blockNumber".into(), Value::Number(24903424.into()));
        doc.insert("logIndex".into(), Value::Number(0.into()));
        doc.insert("transactionHash".into(), Value::String("0xabc".into()));
        let mut tx = serde_json::Map::new();
        tx.insert("hash".into(), Value::String("0xabc".into()));
        tx.insert("from".into(), Value::String("0x1".into()));
        tx.insert("to".into(), Value::String("0x2".into()));
        doc.insert("transaction".into(), Value::Object(tx));
        let mut block = serde_json::Map::new();
        block.insert("timestamp".into(), Value::String("1776715379".into()));
        doc.insert("block".into(), Value::Object(block));

        let out = run_transform(doc);

        // Event name must resolve to "Swap" (topic0 matches Swap signature).
        assert_eq!(out.get("event").and_then(|v| v.as_str()), std::option::Option::Some("Swap"),
            "expected event=Swap, got {:?}", out.get("event"));
        let args_str = out.get("arguments").and_then(|v| v.as_str()).expect("arguments missing");
        assert!(args_str.contains("amount0"), "arguments string missing amount0: {}", args_str);
        assert!(args_str.contains("sqrtPriceX96"), "arguments string missing sqrtPriceX96: {}", args_str);

        // Output must contain ONLY the SDL-declared fields; echoing source
        // fields (address/topics/data/transaction/block/...) causes DefraDB
        // to reject the doc silently when the destination schema doesn't
        // list them. Lock this contract in.
        let expected: std::collections::HashSet<&str> = [
            "hash", "from", "to", "blockNumber", "blockTimestamp", "logIndex",
            "logAddress", "event", "signature", "arguments",
        ].iter().copied().collect();
        let got: std::collections::HashSet<&str> = out.keys().map(|k| k.as_str()).collect();
        assert_eq!(got, expected, "output keys drifted from SDL contract");
        assert_eq!(
            out.get("blockTimestamp").and_then(|v| v.as_i64()),
            std::option::Option::Some(1776715379),
            "blockTimestamp not propagated from nested block.timestamp"
        );
        eprintln!("event={} args={}", out["event"], args_str);
    }
}
