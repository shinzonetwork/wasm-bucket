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
extern "C" {
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

#[no_mangle]
pub extern "C" fn alloc(size: usize) -> *mut u8 {
    lens_sdk::alloc(size)
}

#[no_mangle]
pub extern "C" fn set_param(ptr: *mut u8) -> *mut u8 {
    match try_set_param(ptr) {
        Ok(_) => lens_sdk::nil_ptr(),
        Err(e) => lens_sdk::to_mem(lens_sdk::ERROR_TYPE_ID, e.to_string().as_bytes()),
    }
}

fn try_set_param(ptr: *mut u8) -> Result<(), Box<dyn error::Error>> {
    let parameter = lens_sdk::try_from_mem::<Parameters>(ptr)?.ok_or(ParametersNotSet)?;
    *PARAMETERS.write()? = Some(parameter);
    Ok(())
}

#[no_mangle]
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
    let mut doc = match lens_sdk::try_from_mem::<HashMap<String, Value>>(ptr)? {
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

fn decode_param(typ: &str, hex_data: &str) -> String {
    let clean = hex_data.trim_start_matches("0x");
    match typ {
        "uint256" | "uint128" | "uint64" | "uint32" | "uint16" | "uint8" => {
            u128::from_str_radix(clean, 16)
                .map(|v| v.to_string())
                .unwrap_or_else(|_| {
                    // value too large for u128, return as hex
                    format!("0x{}", clean)
                })
        }
        "int256" | "int128" | "int64" | "int32" | "int16" | "int8" => {
            i128::from_str_radix(clean, 16)
                .map(|v| v.to_string())
                .unwrap_or_else(|_| format!("0x{}", clean))
        }
        "address" => {
            if clean.len() >= 40 {
                format!("0x{}", &clean[clean.len() - 40..])
            } else {
                format!("0x{}", clean)
            }
        }
        "bool" => clean.ends_with('1').to_string(),
        "bytes32" | "bytes20" | "bytes16" | "bytes4" => format!("0x{}", clean),
        _ => format!("0x{}", clean),
    }
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
