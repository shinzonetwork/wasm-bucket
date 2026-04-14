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
    let mut doc = match unsafe { lens_sdk::try_from_mem::<HashMap<String, Value>>(ptr)? } {
        Some(v) => v,
        None => return ok_json(&HashMap::new()),
        EndOfStream => return Ok(EndOfStream),
    };

    // Extract tx context from the nested transaction relation
    let tx = doc.get("transaction").and_then(|v| v.as_object());
    let tx_hash = tx.map(|t| str_field_map(t, "hash")).unwrap_or_default();
    let from = tx.map(|t| str_field_map(t, "from")).unwrap_or_default();
    let to = tx.map(|t| str_field_map(t, "to")).unwrap_or_default();

    let block_number = doc.get("blockNumber").and_then(|v| v.as_i64()).unwrap_or(0);
    let log_address = str_field(&doc, "address");

    let topics = parse_topics(&doc).unwrap_or_default();

    doc.insert("hash".into(), Value::String(tx_hash));
    doc.insert("blockNumber".into(), Value::Number(block_number.into()));
    doc.insert("from".into(), Value::String(from));
    doc.insert("to".into(), Value::String(to));
    doc.insert("logAddress".into(), Value::String(log_address));

    if topics.is_empty() {
        doc.insert("event".into(), Value::String("Unknown".to_string()));
        doc.insert("signature".into(), Value::String(String::new()));
        doc.insert("arguments".into(), Value::Array(Vec::new()));
    } else {
        let abi = parse_abi().unwrap_or_default();
        match find_matching_event(&abi, &topics[0]) {
            std::option::Option::Some(event) => decode_event(&mut doc, event, &topics)?,
            std::option::Option::None => {
                doc.insert("event".into(), Value::String("Unknown".to_string()));
                doc.insert("signature".into(), Value::String(String::new()));
                doc.insert("arguments".into(), Value::Array(Vec::new()));
            }
        }
    }

    ok_json(&doc)
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
            // Collect non-indexed params; they're decoded from the data section below.
            // Do NOT advance topic_idx here: topics only contain indexed params.
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

    doc.insert("arguments".into(), Value::Array(arguments));
    Ok(())
}

/// decode_param decodes a single ABI-encoded parameter from a 32-byte hex word.
///
/// Supports all standard Solidity types used in events:
///   - uintN where N is a multiple of 8 from 8 to 256: unsigned big integer as decimal string
///   - intN where N is a multiple of 8 from 8 to 256: signed two's complement as decimal string
///   - address: last 20 bytes as 0x-prefixed hex
///   - bool: "true" or "false"
///   - bytesN where N is 1 to 32: first N bytes as 0x-prefixed hex
///   - bytes, string (dynamic): returned as the raw 32-byte hex (actual data requires
///     offset lookup which only happens for non-indexed params; indexed dynamic types
///     are actually the keccak256 hash of the value, not the value itself)
fn decode_param(typ: &str, hex_data: &str) -> String {
    let clean = hex_data.trim_start_matches("0x");

    // Parse the 32-byte word as raw bytes once
    let raw_bytes = hex::decode(clean).unwrap_or_default();
    if raw_bytes.is_empty() {
        return String::new();
    }

    match typ {
        "address" => {
            // Last 20 bytes (address is right-aligned in 32-byte word)
            if clean.len() >= 40 {
                format!("0x{}", &clean[clean.len() - 40..])
            } else {
                format!("0x{}", clean)
            }
        }
        "bool" => {
            // Bool is 0 or 1, right-aligned
            let is_true = raw_bytes.iter().any(|&b| b != 0);
            is_true.to_string()
        }
        "string" | "bytes" => {
            // For indexed params, this is keccak256(value). For non-indexed, this is
            // actually an offset pointer (we receive 32 bytes at a time, not the full data).
            // Return the raw hex; callers that need actual strings should use the data
            // section directly, which isn't currently implemented for dynamic types.
            format!("0x{}", clean)
        }
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

/// Parse "uintN" where N is 8, 16, ..., 256. Returns N on success.
fn parse_uint_bits(typ: &str) -> std::option::Option<usize> {
    let suffix = typ.strip_prefix("uint")?;
    let bits: usize = suffix.parse().ok()?;
    if bits >= 8 && bits <= 256 && bits % 8 == 0 {
        std::option::Option::Some(bits)
    } else {
        std::option::Option::None
    }
}

/// Parse "intN" where N is 8, 16, ..., 256. Returns N on success.
fn parse_int_bits(typ: &str) -> std::option::Option<usize> {
    let suffix = typ.strip_prefix("int")?;
    // Must not be "int" with no suffix, and must not match "uintN"
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

/// Parse "bytesN" where N is 1..32. Returns N on success.
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

/// Decode a uintN value from a 32-byte word. Unsigned values are right-aligned.
fn decode_uint(raw: &[u8], _bits: usize) -> String {
    use num_bigint::BigUint;
    // The entire 32-byte word is the big-endian unsigned integer
    // (smaller uints are just zero-padded on the left)
    let value = BigUint::from_bytes_be(raw);
    value.to_str_radix(10)
}

/// Decode an intN value from a 32-byte word using two's complement.
/// Negative values have leading 0xFF bytes indicating sign extension.
fn decode_int(raw: &[u8], bits: usize) -> String {
    use num_bigint::{BigInt, Sign};
    if raw.len() != 32 {
        return "0".to_string();
    }

    // The sign bit is bit (bits-1) within the low (bits/8) bytes of the 32-byte word.
    // For the ABI, intN values are sign-extended to the full 32 bytes, so the leading
    // byte (raw[0]) being 0xFF means negative for any bit width.
    let byte_width = bits / 8;
    let start = 32 - byte_width;
    let value_bytes = &raw[start..];

    // Check high bit of the first (most significant) byte of the actual value
    let is_negative = value_bytes[0] & 0x80 != 0;

    if is_negative {
        // Two's complement: flip all bits, add 1, then negate
        let mut complement = value_bytes.to_vec();
        for b in complement.iter_mut() {
            *b = !*b;
        }
        let positive = BigInt::from_bytes_be(Sign::Plus, &complement);
        let one = BigInt::from(1);
        let result = -(positive + one);
        result.to_str_radix(10)
    } else {
        let value = BigInt::from_bytes_be(Sign::Plus, value_bytes);
        value.to_str_radix(10)
    }
}

/// Decode a bytesN value from a 32-byte word (left-aligned, zero-padded on the right).
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

    // Helper: build a 32-byte hex word from the right-aligned value's hex.
    fn pad32(hex: &str) -> String {
        let clean = hex.trim_start_matches("0x");
        let padding = "0".repeat(64 - clean.len());
        format!("0x{}{}", padding, clean)
    }

    // Helper: build a 32-byte hex word for negative two's-complement int.
    // 0xFF..FF is -1, 0xFF..00 is -256, etc.
    fn neg32(leading: &str) -> String {
        let clean = leading.trim_start_matches("0x");
        let trailing = "ff".repeat(32 - clean.len() / 2);
        format!("0x{}{}", trailing, clean)
    }

    #[test]
    fn test_type_parsers() {
        assert_eq!(parse_uint_bits("uint8"), std::option::Option::Some(8));
        assert_eq!(parse_uint_bits("uint256"), std::option::Option::Some(256));
        assert_eq!(parse_uint_bits("uint160"), std::option::Option::Some(160));
        assert_eq!(parse_uint_bits("uint7"), std::option::Option::None); // not multiple of 8
        assert_eq!(parse_uint_bits("int256"), std::option::Option::None); // int, not uint
        assert_eq!(parse_uint_bits("uint"), std::option::Option::None); // no bit width

        assert_eq!(parse_int_bits("int128"), std::option::Option::Some(128));
        assert_eq!(parse_int_bits("int24"), std::option::Option::Some(24));
        assert_eq!(parse_int_bits("int256"), std::option::Option::Some(256));
        assert_eq!(parse_int_bits("uint256"), std::option::Option::None); // uint, not int
        assert_eq!(parse_int_bits("int"), std::option::Option::None);

        assert_eq!(parse_bytes_n("bytes1"), std::option::Option::Some(1));
        assert_eq!(parse_bytes_n("bytes32"), std::option::Option::Some(32));
        assert_eq!(parse_bytes_n("bytes4"), std::option::Option::Some(4));
        assert_eq!(parse_bytes_n("bytes"), std::option::Option::None);
        assert_eq!(parse_bytes_n("bytes33"), std::option::Option::None);
    }

    #[test]
    fn test_decode_uint256_zero() {
        let hex = pad32("0");
        assert_eq!(decode_param("uint256", &hex), "0");
    }

    #[test]
    fn test_decode_uint256_one() {
        let hex = pad32("1");
        assert_eq!(decode_param("uint256", &hex), "1");
    }

    #[test]
    fn test_decode_uint256_large() {
        // A value > 2^128 that the old u128-based code would overflow on.
        // 2^128 = 0x100000000000000000000000000000000 (33 hex chars = 17 bytes)
        let hex = "0x0000000000000000000000000000000100000000000000000000000000000000";
        let expected = "340282366920938463463374607431768211456"; // 2^128
        assert_eq!(decode_param("uint256", hex), expected);
    }

    #[test]
    fn test_decode_uint160() {
        // sqrtPriceX96 from a real Uniswap v3 swap (example value)
        let hex = pad32("0100000000000000000000000000000000000000"); // 2^160 - 1? no, smaller
        let result = decode_param("uint160", &hex);
        // 0x01 followed by 20 bytes of zeros = 2^152... but padded to 32 bytes total
        // Actually pad32 pads to 32 bytes = 64 hex chars total. "01" + 19*"00" = 40 chars, padded to 64 = 24 leading zeros.
        // Value is 0x01_00000000000000000000000000000000000000 = 2^152
        assert_eq!(result, "5708990770823839524233143877797980545530986496");
    }

    #[test]
    fn test_decode_uint24() {
        // Uniswap v4 fee tier: 3000 (0.3%)
        let hex = pad32("bb8"); // 3000 in hex
        assert_eq!(decode_param("uint24", &hex), "3000");
    }

    #[test]
    fn test_decode_int24_positive() {
        // Uniswap v4 tick: 100
        let hex = pad32("64"); // 100 in hex
        assert_eq!(decode_param("int24", &hex), "100");
    }

    #[test]
    fn test_decode_int24_negative() {
        // Uniswap v4 tick: -100
        // -100 as int24 = 0xFFFF9C (three bytes). Sign-extended to 32 bytes:
        // 32 bytes = 64 hex chars. All 0xFF except last byte 0x9C.
        let hex = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff9c";
        assert_eq!(decode_param("int24", hex), "-100");
    }

    #[test]
    fn test_decode_int128_positive() {
        let hex = pad32("64"); // 100
        assert_eq!(decode_param("int128", &hex), "100");
    }

    #[test]
    fn test_decode_int128_negative_one() {
        // -1 as int128 = 0xFF..FF (16 bytes), sign-extended to 32 bytes
        let hex = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert_eq!(decode_param("int128", hex), "-1");
    }

    #[test]
    fn test_decode_int256_large_negative() {
        // -2 as int256
        let hex = "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe";
        assert_eq!(decode_param("int256", hex), "-2");
    }

    #[test]
    fn test_decode_address() {
        let hex = "0x000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
        // USDC address right-aligned
        assert_eq!(decode_param("address", hex), "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
    }

    #[test]
    fn test_decode_bool_true() {
        let hex = pad32("1");
        assert_eq!(decode_param("bool", &hex), "true");
    }

    #[test]
    fn test_decode_bool_false() {
        let hex = pad32("0");
        assert_eq!(decode_param("bool", &hex), "false");
    }

    #[test]
    fn test_decode_bytes32() {
        let hex = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        assert_eq!(decode_param("bytes32", hex), hex);
    }

    #[test]
    fn test_decode_bytes4() {
        // Function selector stored as bytes4 (left-aligned in 32-byte word)
        let hex = "0x12345678000000000000000000000000000000000000000000000000000000";
        // That's only 62 chars + "0x" = 64 total. Let me use exactly 32 bytes.
        let hex = "0x1234567800000000000000000000000000000000000000000000000000000000";
        assert_eq!(decode_param("bytes4", hex), "0x12345678");
    }

    #[test]
    fn test_decode_unsupported_type() {
        let hex = pad32("1");
        assert_eq!(decode_param("tuple", &hex), "unsupported type: tuple");
    }
}
