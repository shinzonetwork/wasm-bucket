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

#[no_mangle]
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
    let mut doc = match lens_sdk::try_from_mem::<HashMap<String, Value>>(ptr)? {
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
        doc.insert("arguments".into(), Value::String("[]".to_string()));
    } else {
        let abi = parse_abi().unwrap_or_default();
        match find_matching_event(&abi, &topics[0]) {
            std::option::Option::Some(event) => decode_event(&mut doc, event, &topics)?,
            std::option::Option::None => {
                doc.insert("event".into(), Value::String("Unknown".to_string()));
                doc.insert("signature".into(), Value::String(String::new()));
                doc.insert("arguments".into(), Value::String("[]".to_string()));
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
            non_indexed.push(inp);
            topic_idx += 1;
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

fn decode_param(typ: &str, hex_data: &str) -> String {
    let clean = hex_data.trim_start_matches("0x");
    match typ {
        "uint256" => u128::from_str_radix(clean, 16)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "0".to_string()),
        "address" => {
            if clean.len() >= 40 {
                format!("0x{}", &clean[clean.len() - 40..])
            } else {
                format!("0x{}", clean)
            }
        }
        "bool" => clean.ends_with('1').to_string(),
        "bytes32" => format!("0x{}", clean),
        _ => format!("unsupported type: {}", typ),
    }
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
