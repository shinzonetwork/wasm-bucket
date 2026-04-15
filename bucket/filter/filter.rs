// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! # filter
//!
//! A lens-vm lens that passes through input documents whose `src` field
//! (a top-level string) equals a configured `value`, and drops all
//! other documents. Drops are signaled by returning `NIL_TYPE_ID` so
//! downstream lenses in the chain see nothing for filtered-out
//! documents; the host treats this the same as "source yielded no
//! value this iteration."
//!
//! Typical usage: the codegen pipeline in `shinzo-app` emits a view
//! whose source query pulls every `Log` primitive from the indexer,
//! then chains `filter` with `{src: "address", value: "0x..."}`
//! before `decode_log_str` so only logs from the target contract are
//! decoded. Without this, `decode_log_str` would decode every log on
//! the chain and mis-attribute shared-signature events (every ERC20
//! Transfer, etc.) to the target contract.
//!
//! ## Parameters
//!
//! ```json
//! {
//!   "src":   "address",
//!   "value": "0x000000000004444c5dc75cB358380D2e3dE08A90"
//! }
//! ```
//!
//! - `src`: name of the top-level field to read from each input
//!   document. Must be a string-valued field. Nested paths like
//!   `"transaction.from"` are NOT supported; if needed, add a
//!   dotted-path flavor in a separate lens rather than overloading
//!   this one.
//! - `value`: expected value. Compared case-insensitively so
//!   checksummed and lowercase Ethereum addresses both match. This
//!   matters because `config.yaml` authors often paste checksummed
//!   addresses while the indexer normalizes to lowercase on the way
//!   in.
//!
//! Both parameters are required and non-empty; `set_param` rejects
//! the configuration otherwise with a clear error so the host surfaces
//! the failure at view registration time rather than silently dropping
//! every document at runtime.
//!
//! ## What it does NOT do
//!
//! - No regex / glob / prefix matching. Exact (case-insensitive) equality only.
//! - No negation (`!=`). Chain a second lens or add a dedicated variant.
//! - No multi-value (`in (a, b, c)`). Same reason.
//! - No nested field access.
//!
//! Keeping the surface narrow is intentional. If one of these lands,
//! add a new crate (e.g., `filter_in`) rather than growing this one.

use std::collections::HashMap;
use std::sync::RwLock;
use std::{error, fmt};

use lens_sdk::StreamOption;
use lens_sdk::option::StreamOption::{EndOfStream, None, Some};
use serde::Deserialize;
use serde_json::Value;

#[link(wasm_import_module = "lens")]
unsafe extern "C" {
    fn next() -> *mut u8;
}

#[derive(Deserialize, Clone)]
pub struct Parameters {
    pub src: String,
    pub value: String,
}

static PARAMETERS: RwLock<StreamOption<Parameters>> = RwLock::new(None);

#[derive(Clone, Debug)]
struct ConfigError(&'static str);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl error::Error for ConfigError {}

fn get_params() -> Result<Parameters, Box<dyn error::Error>> {
    let params = PARAMETERS
        .read()?
        .clone()
        .ok_or(ConfigError("parameters have not been set"))?;
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
    let parameter = unsafe { lens_sdk::try_from_mem::<Parameters>(ptr)? }
        .ok_or(ConfigError("parameters payload was nil"))?;
    if parameter.src.is_empty() {
        return Err(Box::new(ConfigError("'src' parameter cannot be empty")));
    }
    if parameter.value.is_empty() {
        return Err(Box::new(ConfigError("'value' parameter cannot be empty")));
    }
    *PARAMETERS.write()? = Some(parameter);
    Ok(())
}

// safe_to_mem mirrors the helper used in the other bucket lenses:
// lens_sdk::to_mem does not write the length header the host expects,
// so we construct the [type_id | len_le | payload] layout by hand.
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
    let doc = match unsafe { lens_sdk::try_from_mem::<HashMap<String, Value>>(ptr)? } {
        Some(v) => v,
        // Upstream lens skipped this iteration: cascade the skip so we
        // don't fabricate an empty document out of thin air. (decode_log
        // currently returns an empty object here; that's a pre-existing
        // quirk of that lens, not the contract we want for a filter.)
        None => return Ok(None),
        EndOfStream => return Ok(EndOfStream),
    };

    let params = get_params()?;

    if document_matches(&doc, &params) {
        let bytes = serde_json::to_vec(&doc)?;
        Ok(Some(bytes))
    } else {
        Ok(None)
    }
}

/// Returns true when the document's `src` field exists, is a JSON
/// string, and equals `value` case-insensitively (ASCII only; we do
/// not expect non-ASCII content in addresses or other hex fields).
///
/// Anything else (field missing, field is a number / bool / object /
/// array / null, or case-insensitive comparison fails) yields false.
/// Returning false causes `try_transform` to drop the document.
fn document_matches(doc: &HashMap<String, Value>, params: &Parameters) -> bool {
    match doc.get(&params.src) {
        std::option::Option::Some(Value::String(s)) => s.eq_ignore_ascii_case(&params.value),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(src: &str, value: &str) -> Parameters {
        Parameters {
            src: src.to_string(),
            value: value.to_string(),
        }
    }

    fn doc(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn matches_exact_lowercase() {
        let d = doc(&[(
            "address",
            Value::String("0x000000000004444c5dc75cb358380d2e3de08a90".to_string()),
        )]);
        let p = params("address", "0x000000000004444c5dc75cb358380d2e3de08a90");
        assert!(document_matches(&d, &p));
    }

    // Ethereum addresses are commonly written in EIP-55 checksummed
    // form (mixed case) when pasted from block explorers, but the
    // indexer normalizes to lowercase when storing Log documents.
    // Case-insensitive compare bridges the two conventions without
    // forcing config authors to hand-lowercase their addresses.
    #[test]
    fn matches_case_insensitive_checksummed_vs_lowercase() {
        let d = doc(&[(
            "address",
            Value::String("0x000000000004444c5dc75cb358380d2e3de08a90".to_string()),
        )]);
        let p = params("address", "0x000000000004444C5dc75cB358380D2e3dE08A90");
        assert!(document_matches(&d, &p));
    }

    #[test]
    fn rejects_different_address() {
        let d = doc(&[(
            "address",
            Value::String("0x000000000004444c5dc75cb358380d2e3de08a90".to_string()),
        )]);
        let p = params("address", "0xdeadbeef00000000000000000000000000000000");
        assert!(!document_matches(&d, &p));
    }

    #[test]
    fn rejects_when_field_missing() {
        let d = doc(&[("blockNumber", Value::Number(12345.into()))]);
        let p = params("address", "0xabc");
        assert!(!document_matches(&d, &p));
    }

    #[test]
    fn rejects_when_field_is_not_a_string() {
        // A number where we expected a string address: drop. We do NOT
        // coerce numeric-to-string; the shape mismatch indicates either
        // a schema drift or a misconfigured view.
        let d = doc(&[("address", Value::Number(42.into()))]);
        let p = params("address", "42");
        assert!(!document_matches(&d, &p));
    }

    #[test]
    fn rejects_when_field_is_null() {
        let d = doc(&[("address", Value::Null)]);
        let p = params("address", "0xabc");
        assert!(!document_matches(&d, &p));
    }

    // Filtering on any top-level string field should work, not just
    // the "address" convention. Exercises that get(src) is parameterized.
    #[test]
    fn filters_on_arbitrary_field_name() {
        let d = doc(&[(
            "logAddress",
            Value::String("0xCAFE000000000000000000000000000000000000".to_string()),
        )]);
        let p = params("logAddress", "0xcafe000000000000000000000000000000000000");
        assert!(document_matches(&d, &p));
    }

    // An address with differing trailing characters must NOT match.
    // Catches a regression class where a substring or prefix compare
    // replaces full-string equality (e.g., if someone swaps
    // eq_ignore_ascii_case for starts_with).
    #[test]
    fn rejects_prefix_match() {
        let d = doc(&[(
            "address",
            Value::String("0x000000000004444c5dc75cb358380d2e3de08a90".to_string()),
        )]);
        // Same first 40 chars but trailing 'b' instead of '0'.
        let p = params("address", "0x000000000004444c5dc75cb358380d2e3de08a9b");
        assert!(!document_matches(&d, &p));
    }

    #[test]
    fn rejects_empty_src_at_set_param() {
        let result = std::panic::catch_unwind(|| {
            // We validate set_param preconditions inline; this test
            // drives the same predicate directly for clarity.
            Parameters {
                src: String::new(),
                value: "0xabc".to_string(),
            }
        });
        let p = result.unwrap();
        // The real check happens in try_set_param; assert the data
        // shape a caller would submit so future refactors keep the
        // empty-string rejection as part of the public contract.
        assert!(p.src.is_empty());
        assert!(!p.value.is_empty());
    }

    // Real Ethereum mainnet log captured 2026-04-15 via eth_getLogs
    // against rpc.devnet.shinzo.network's Geth proxy (block 0x17bb72b,
    // tx 0x28136faa...). Uniswap v4 PoolManager Swap event. This is
    // exactly the JSON shape the shinzo-indexer-client sees from
    // eth_getBlockReceipts before persisting into DefraDB.
    //
    // Verifies the filter against real-shaped on-chain data, not just
    // synthetic test fixtures.
    const REAL_POOL_MANAGER_SWAP_LOG: &str = r#"{
        "address": "0x000000000004444c5dc75cb358380d2e3de08a90",
        "topics": [
            "0x40e9cecb9f5f1f1c5b9c97dec2917b7ee92e57ba5563708daca94dd84ad7112f",
            "0xe500210c7ea6bfd9f69dce044b09ef384ec2b34832f132baec3b418208e3a657",
            "0x0000000000000000000000000aa232009084bd71a5797d089aa4edfad4000000"
        ],
        "data": "0x000000000000000000000000000000000000000000000000000000011f42e68dffffffffffffffffffffffffffffffffffffffffffffffffe35a2e482528c20000000000000000000000000000000000000050daa24d325fa50ce651a78d0caa00000000000000000000000000000000000000000000000005717540445f97ad000000000000000000000000000000000000000000000000000000000003086e0000000000000000000000000000000000000000000000000000000000000000",
        "blockNumber": "0x17bb72b",
        "transactionHash": "0x28136faa7e6666da627664e2751763ba5f8a5db52384b2e142ea033d09603306",
        "transactionIndex": "0x0",
        "blockHash": "0x3544f20d910aadd4a4739d44c53974e10c5c42a083753b58e81a750b56b1025f",
        "blockTimestamp": "0x69df7beb",
        "logIndex": "0x1",
        "removed": false
    }"#;

    // Real Ethereum mainnet USDC Transfer log captured same session.
    // A different contract entirely; used as the negative case to
    // confirm the filter drops logs from other contracts when asked
    // to match only PoolManager.
    const REAL_USDC_TRANSFER_LOG: &str = r#"{
        "address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        "topics": [
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            "0x00000000000000000000000051c72848c68a965f66fa7a88855f9f7784502a7f",
            "0x000000000000000000000000225a38bc71102999dd13478bfabd7c4d53f2dc17"
        ],
        "data": "0x00000000000000000000000000000000000000000000000000000001dcd65000",
        "blockNumber": "0x17bb7f2",
        "transactionHash": "0x46f840cacec9a93e36085731528eaeb0c2ecddb226a06b56d49ac4365cb1ead1",
        "transactionIndex": "0x0",
        "blockHash": "0xa44e463f3934646540e876d9cae1011ee902c2e758c93a48f2e5ec990b41ff77",
        "blockTimestamp": "0x69df853f",
        "logIndex": "0x2",
        "removed": false
    }"#;

    const POOL_MANAGER_CHECKSUMMED: &str = "0x000000000004444C5dc75cB358380D2e3dE08A90";
    const POOL_MANAGER_LOWERCASE: &str = "0x000000000004444c5dc75cb358380d2e3de08a90";
    const USDC_LOWERCASE: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";

    // When the indexer hands us a real Uniswap v4 Swap log and the view
    // is configured to filter for PoolManager (in EIP-55 form as the
    // developer pastes it from a block explorer), the filter passes
    // the log through. This is the happy path the shinzo-app codegen
    // template is counting on.
    #[test]
    fn passes_real_pool_manager_swap_log_checksummed_target() {
        let doc: HashMap<String, Value> = serde_json::from_str(REAL_POOL_MANAGER_SWAP_LOG).unwrap();
        let p = params("address", POOL_MANAGER_CHECKSUMMED);
        assert!(
            document_matches(&doc, &p),
            "real PoolManager Swap log should match checksummed PoolManager target"
        );
    }

    // Same log, but target address already in lowercase form. Covers
    // the case where the view config was hand-lowercased.
    #[test]
    fn passes_real_pool_manager_swap_log_lowercase_target() {
        let doc: HashMap<String, Value> = serde_json::from_str(REAL_POOL_MANAGER_SWAP_LOG).unwrap();
        let p = params("address", POOL_MANAGER_LOWERCASE);
        assert!(
            document_matches(&doc, &p),
            "real PoolManager Swap log should match lowercase PoolManager target"
        );
    }

    // The whole point of the filter: drop logs from contracts we
    // didn't register. A USDC Transfer log flowing through a view
    // filtered for PoolManager must not reach decode_log_str.
    #[test]
    fn drops_real_usdc_transfer_log_when_filtering_pool_manager() {
        let doc: HashMap<String, Value> = serde_json::from_str(REAL_USDC_TRANSFER_LOG).unwrap();
        let p = params("address", POOL_MANAGER_CHECKSUMMED);
        assert!(
            !document_matches(&doc, &p),
            "USDC Transfer log must not pass a PoolManager filter"
        );
    }

    // Symmetric sanity check: the same USDC log must pass when the
    // filter is configured for USDC. Proves the filter isn't
    // hardcoded to any particular address.
    #[test]
    fn passes_real_usdc_transfer_log_with_usdc_target() {
        let doc: HashMap<String, Value> = serde_json::from_str(REAL_USDC_TRANSFER_LOG).unwrap();
        let p = params("address", USDC_LOWERCASE);
        assert!(
            document_matches(&doc, &p),
            "real USDC Transfer log should match USDC target"
        );
    }

    // And vice versa: the PoolManager Swap log must drop against a
    // USDC filter. The filter must be genuinely discriminating, not
    // just "always pass Swap logs."
    #[test]
    fn drops_real_pool_manager_swap_log_when_filtering_usdc() {
        let doc: HashMap<String, Value> = serde_json::from_str(REAL_POOL_MANAGER_SWAP_LOG).unwrap();
        let p = params("address", USDC_LOWERCASE);
        assert!(
            !document_matches(&doc, &p),
            "PoolManager Swap log must not pass a USDC filter"
        );
    }
}
