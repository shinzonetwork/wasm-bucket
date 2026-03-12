// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Lens: decode
//
// 1:1 lens. Receives a transaction document with nested logs:
//   { hash, from, to, input, blockNumber, logs: [{address, topics, data}] }
//
// Decodes the function call from `input` (via function_abi) and decodes
// each log as an event (via event_abi), adding:
//   - function: String (function name)
//   - signature: String (function signature)
//   - arguments: [{name, type, value}] (function call args)
//   - events: [{event, signature, address, arguments}] (decoded logs)

use std::collections::HashMap;
use std::sync::RwLock;

use lens_sdk::StreamOption;
use lens_sdk::error::LensError;
use serde::Deserialize;
use serde_json::Value;
use sha3::{Digest, Keccak256};

#[derive(Deserialize, Clone)]
pub struct Parameters {
    pub function_abi: String,
    pub event_abi: String,
}

static PARAMETERS: RwLock<Option<Parameters>> = RwLock::new(None);

lens_sdk::define!(PARAMETERS: Parameters, try_transform);

fn try_transform(
    iter: &mut dyn Iterator<Item = lens_sdk::Result<Option<HashMap<String, Value>>>>,
) -> Result<StreamOption<HashMap<String, Value>>, Box<dyn std::error::Error>> {
    let params = PARAMETERS.read()?
        .clone()
        .ok_or(LensError::ParametersNotSetError)?;

    for item in iter {
        let mut doc = match item? {
            Some(v) => v,
            None => return Ok(StreamOption::None),
        };

        // Decode function call from `input`
        let fn_abi = parse_function_abi(&params.function_abi)?;
        let input_str = doc.get("input").and_then(|v| v.as_str()).map(|s| s.to_string());
        if let Some(input_str) = input_str {
            if input_str.len() >= 10 {
                let selector = input_str[..10].to_lowercase();
                if let Some(func) = fn_abi.iter().find(|f| f.selector == selector) {
                    let fn_name = func.name.clone();
                    let fn_sig = func.signature.clone();
                    let fn_args = decode_function_args(func, &input_str);
                    doc.insert("function".into(), Value::String(fn_name));
                    doc.insert("signature".into(), Value::String(fn_sig));
                    doc.insert("arguments".into(), fn_args);
                }
            }
        }

        // Decode events from `logs`
        let ev_abi = parse_event_abi(&params.event_abi)?;
        let events: Vec<Value> = doc
            .get("logs")
            .and_then(|v| v.as_array())
            .map(|logs| {
                logs.iter()
                    .filter_map(|log| decode_log(&ev_abi, log))
                    .collect()
            })
            .unwrap_or_default();
        doc.insert("events".into(), Value::Array(events));

        return Ok(StreamOption::Some(doc));
    }

    Ok(StreamOption::EndOfStream)
}

// ---- ABI structs ----

struct AbiFunction {
    name: String,
    signature: String,
    selector: String,
    inputs: Vec<AbiParam>,
}

struct AbiEvent {
    name: String,
    signature: String,
    selector: String,
    inputs: Vec<AbiParam>,
}

struct AbiParam {
    name: String,
    typ: String,
    indexed: bool,
}

fn parse_function_abi(abi_str: &str) -> Result<Vec<AbiFunction>, Box<dyn std::error::Error>> {
    let items: Vec<Value> = serde_json::from_str(abi_str)?;
    Ok(items
        .iter()
        .filter(|i| i["type"] == "function")
        .filter_map(|i| {
            let name = i["name"].as_str()?;
            let inputs = parse_params(i["inputs"].as_array()?, false);
            let types: Vec<&str> = inputs.iter().map(|p| p.typ.as_str()).collect();
            let sig = format!("{}({})", name, types.join(","));
            let selector = format!("0x{}", &keccak_hex(&sig)[2..10]);
            Some(AbiFunction { name: name.to_string(), signature: sig, selector, inputs })
        })
        .collect())
}

fn parse_event_abi(abi_str: &str) -> Result<Vec<AbiEvent>, Box<dyn std::error::Error>> {
    let items: Vec<Value> = serde_json::from_str(abi_str)?;
    Ok(items
        .iter()
        .filter(|i| i["type"] == "event")
        .filter_map(|i| {
            let name = i["name"].as_str()?;
            let inputs = parse_params(i["inputs"].as_array()?, true);
            let types: Vec<&str> = inputs.iter().map(|p| p.typ.as_str()).collect();
            let sig = format!("{}({})", name, types.join(","));
            let selector = keccak_hex(&sig);
            Some(AbiEvent { name: name.to_string(), signature: sig, selector, inputs })
        })
        .collect())
}

fn parse_params(arr: &[Value], with_indexed: bool) -> Vec<AbiParam> {
    arr.iter()
        .filter_map(|v| {
            Some(AbiParam {
                name: v["name"].as_str()?.to_string(),
                typ: v["type"].as_str()?.to_string(),
                indexed: if with_indexed { v["indexed"].as_bool().unwrap_or(false) } else { false },
            })
        })
        .collect()
}

fn keccak_hex(s: &str) -> String {
    let mut h = Keccak256::new();
    h.update(s.as_bytes());
    format!("0x{}", hex::encode(h.finalize()))
}

// ---- Decoding ----

fn decode_function_args(func: &AbiFunction, input: &str) -> Value {
    let calldata = match hex::decode(&input[10..]) {
        Ok(b) => b,
        Err(_) => return Value::String("[]".to_string()),
    };
    let mut args = Vec::new();
    let mut offset = 0;
    for param in &func.inputs {
        if offset + 32 > calldata.len() { break; }
        let hex_val = format!("0x{}", hex::encode(&calldata[offset..offset + 32]));
        let value = decode_param(&param.typ, &hex_val);
        args.push(serde_json::json!({"name": param.name, "type": param.typ, "value": value}));
        offset += 32;
    }
    Value::String(serde_json::to_string(&args).unwrap_or_default())
}

fn decode_log(abi: &[AbiEvent], log: &Value) -> Option<Value> {
    let topics: Vec<String> = log
        .get("topics")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    if topics.is_empty() { return None; }

    let event = abi.iter().find(|e| e.selector == topics[0])?;
    let address = log.get("address").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let mut args: Vec<Value> = Vec::new();
    let mut topic_idx = 1usize;
    let mut non_indexed: Vec<&AbiParam> = Vec::new();

    for param in &event.inputs {
        if param.indexed {
            if topic_idx < topics.len() {
                let value = decode_param(&param.typ, &topics[topic_idx]);
                args.push(serde_json::json!({"name": param.name, "type": param.typ, "value": value}));
            }
            topic_idx += 1;
        } else {
            non_indexed.push(param);
        }
    }

    if let Some(data_str) = log.get("data").and_then(|v| v.as_str()) {
        let clean = data_str.strip_prefix("0x").unwrap_or(data_str);
        if let Ok(bytes) = hex::decode(clean) {
            let mut offset = 0;
            for param in &non_indexed {
                if offset + 32 > bytes.len() { break; }
                let hex_val = format!("0x{}", hex::encode(&bytes[offset..offset + 32]));
                let value = decode_param(&param.typ, &hex_val);
                args.push(serde_json::json!({"name": param.name, "type": param.typ, "value": value}));
                offset += 32;
            }
        }
    }

    Some(serde_json::json!({
        "event": event.name,
        "signature": event.signature,
        "address": address,
        "arguments": args,
    }))
}

fn decode_param(typ: &str, hex_data: &str) -> String {
    let clean = hex_data.trim_start_matches("0x");
    match typ {
        "uint256" | "uint128" | "uint64" | "uint32" | "uint16" | "uint8" => {
            u128::from_str_radix(clean, 16)
                .map(|v| v.to_string())
                .unwrap_or_else(|_| format!("0x{}", clean))
        }
        "int256" | "int128" | "int64" | "int32" | "int16" | "int8" => {
            i128::from_str_radix(clean, 16)
                .map(|v| v.to_string())
                .unwrap_or_else(|_| format!("0x{}", clean))
        }
        "address" => {
            if clean.len() >= 40 { format!("0x{}", &clean[clean.len() - 40..]) }
            else { format!("0x{}", clean) }
        }
        "bool" => clean.ends_with('1').to_string(),
        _ => format!("0x{}", clean),
    }
}
