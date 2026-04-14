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

#[unsafe(no_mangle)]
pub extern "C" fn transform() -> *mut u8 {
    match try_transform() {
        Ok(Some(json)) => lens_sdk::to_mem(lens_sdk::JSON_TYPE_ID, &json),
        Ok(None) => lens_sdk::nil_ptr(),
        Ok(EndOfStream) => lens_sdk::to_mem(lens_sdk::EOS_TYPE_ID, &[]),
        Err(e) => lens_sdk::to_mem(lens_sdk::ERROR_TYPE_ID, e.to_string().as_bytes()),
    }
}

fn try_transform() -> Result<StreamOption<Vec<u8>>, Box<dyn error::Error>> {
    let ptr = unsafe { next() };
    let mut doc = match unsafe { lens_sdk::try_from_mem::<HashMap<String, Value>>(ptr)? } {
        Some(v) => v,
        None => return try_transform(),
        EndOfStream => return Ok(EndOfStream),
    };

    let input_data = match doc.get("input").and_then(|v| v.as_str()) {
        std::option::Option::Some(d) if d.len() >= 10 => d.to_string(),
        _ => return ok_json(&doc),
    };

    let selector = &input_data[..10];
    let functions = parse_abi()?;

    doc.insert("hash".into(), Value::String(str_field(&doc, "hash")));
    doc.insert("block".into(), Value::String(
        doc.get("blockNumber")
            .and_then(|v| v.as_i64())
            .unwrap_or_default()
            .to_string(),
    ));

    if let std::option::Option::Some(func) = find_matching_function(&functions, selector) {
        decode_function(&mut doc, &func, &input_data)?;
    }

    ok_json(&doc)
}

struct AbiFunction {
    name: String,
    signature: String,
    selector: String,
    inputs: Vec<AbiInput>,
}

struct AbiInput {
    name: String,
    typ: String,
}

fn parse_abi() -> Result<Vec<AbiFunction>, Box<dyn error::Error>> {
    let params = get_params()?;
    let items: Vec<Value> = serde_json::from_str(&params.abi)?;

    let functions = items
        .iter()
        .filter(|item| item["type"] == "function")
        .filter_map(|item| {
            let name = item["name"].as_str()?;
            let inputs = item["inputs"].as_array()?;

            let abi_inputs: Vec<AbiInput> = inputs
                .iter()
                .filter_map(|inp| {
                    std::option::Option::Some(AbiInput {
                        name: inp["name"].as_str()?.to_string(),
                        typ: inp["type"].as_str()?.to_string(),
                    })
                })
                .collect();

            let types: Vec<&str> = abi_inputs.iter().map(|i| i.typ.as_str()).collect();
            let sig = format!("{}({})", name, types.join(","));

            let mut hasher = Keccak256::new();
            hasher.update(sig.as_bytes());
            let full_hash = hex::encode(hasher.finalize());
            let selector = format!("0x{}", &full_hash[..8]);

            std::option::Option::Some(AbiFunction {
                name: name.to_string(),
                signature: sig,
                selector,
                inputs: abi_inputs,
            })
        })
        .collect();

    Ok(functions)
}

fn find_matching_function<'a>(functions: &'a [AbiFunction], selector: &str) -> std::option::Option<&'a AbiFunction> {
    let sel_lower = selector.to_lowercase();
    functions.iter().find(|f| f.selector.to_lowercase() == sel_lower)
}

fn decode_function(
    doc: &mut HashMap<String, Value>,
    func: &AbiFunction,
    input_data: &str,
) -> Result<(), Box<dyn error::Error>> {
    doc.insert("function".into(), Value::String(func.name.clone()));
    doc.insert("signature".into(), Value::String(func.signature.clone()));

    let calldata_hex = input_data[10..].to_string();
    let calldata = match hex::decode(&calldata_hex) {
        Ok(b) => b,
        Err(_) => {
            doc.insert("arguments".into(), Value::Array(Vec::new()));
            return Ok(());
        }
    };

    let mut arguments = Vec::new();
    let mut offset = 0;

    for inp in &func.inputs {
        if offset + 32 > calldata.len() {
            break;
        }
        let raw = &calldata[offset..offset + 32];
        let hex_val = format!("0x{}", hex::encode(raw));
        let value = decode_param(&inp.typ, &hex_val);

        arguments.push(serde_json::json!({
            "name": inp.name,
            "type": inp.typ,
            "value": value,
        }));
        offset += 32;
    }

    doc.insert("arguments".into(), Value::Array(arguments));
    Ok(())
}

/// decode_param decodes a single ABI-encoded parameter from a 32-byte hex word.
///
/// Supports all standard Solidity types used in function calls:
///   - uintN where N is a multiple of 8 from 8 to 256: unsigned big integer as decimal string
///   - intN where N is a multiple of 8 from 8 to 256: signed two's complement as decimal string
///   - address: last 20 bytes as 0x-prefixed hex
///   - bool: "true" or "false"
///   - bytesN where N is 1 to 32: first N bytes as 0x-prefixed hex
///   - bytes, string (dynamic): returned as the raw 32-byte hex. Full dynamic decoding
///     (following the offset pointer to the tail of the calldata) is not implemented.
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
        "bool" => {
            let is_true = raw_bytes.iter().any(|&b| b != 0);
            is_true.to_string()
        }
        "string" | "bytes" => {
            // Dynamic types in calldata use offset-pointer encoding. Reading the
            // 32-byte slot gets the offset, not the value. Return raw hex so the
            // document flows through without silent corruption.
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

fn ok_json(doc: &HashMap<String, Value>) -> Result<StreamOption<Vec<u8>>, Box<dyn error::Error>> {
    let json = serde_json::to_vec(doc)?;
    Ok(Some(json))
}

#[cfg(test)]
mod tests {
    // Use fully-qualified std Option paths; the parent module imports
    // StreamOption::{Some, None} which shadows std::option::Option variants.
    use super::{decode_param, parse_bytes_n, parse_int_bits, parse_uint_bits};
    use std::option::Option as StdOption;

    fn pad32(hex: &str) -> String {
        let clean = hex.trim_start_matches("0x");
        let padding = "0".repeat(64 - clean.len());
        format!("0x{}{}", padding, clean)
    }

    #[test]
    fn test_type_parsers() {
        assert_eq!(parse_uint_bits("uint8"), StdOption::Some(8));
        assert_eq!(parse_uint_bits("uint256"), StdOption::Some(256));
        assert_eq!(parse_uint_bits("uint160"), StdOption::Some(160));
        assert_eq!(parse_uint_bits("uint7"), StdOption::None);
        assert_eq!(parse_uint_bits("int256"), StdOption::None);

        assert_eq!(parse_int_bits("int128"), StdOption::Some(128));
        assert_eq!(parse_int_bits("int24"), StdOption::Some(24));
        assert_eq!(parse_int_bits("uint256"), StdOption::None);

        assert_eq!(parse_bytes_n("bytes4"), StdOption::Some(4));
        assert_eq!(parse_bytes_n("bytes32"), StdOption::Some(32));
        assert_eq!(parse_bytes_n("bytes33"), StdOption::None);
    }

    #[test]
    fn test_decode_uint256_large() {
        // 2^128, which the old u128-based decoder would have overflowed.
        let hex = "0x0000000000000000000000000000000100000000000000000000000000000000";
        assert_eq!(decode_param("uint256", hex), "340282366920938463463374607431768211456");
    }

    #[test]
    fn test_decode_uint24_fee_tier() {
        assert_eq!(decode_param("uint24", &pad32("bb8")), "3000");
    }

    #[test]
    fn test_decode_int24_negative() {
        let hex = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff9c";
        assert_eq!(decode_param("int24", hex), "-100");
    }

    #[test]
    fn test_decode_address() {
        let hex = "0x000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
        assert_eq!(decode_param("address", hex), "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
    }

    #[test]
    fn test_decode_bool() {
        assert_eq!(decode_param("bool", &pad32("1")), "true");
        assert_eq!(decode_param("bool", &pad32("0")), "false");
    }

    #[test]
    fn test_decode_bytes4_selector() {
        let hex = "0x1234567800000000000000000000000000000000000000000000000000000000";
        assert_eq!(decode_param("bytes4", hex), "0x12345678");
    }

    #[test]
    fn test_decode_unsupported_returns_tagged() {
        assert_eq!(decode_param("tuple", &pad32("1")), "unsupported type: tuple");
    }
}
