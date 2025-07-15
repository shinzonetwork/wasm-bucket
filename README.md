# wasm-bucket

**wasm_bucket** is a lightweight collection of standalone Rust-based WebAssembly modules.  
Each folder contains a self-contained `.rs` file compiled directly into a `.wasm` file.

Ideal for sharing, testing, or loading minimal WASM modules.

Each module is:
- A standalone `.rs` file inside `bucket/<module>/<module>.rs`
- Compiled to `.wasm`

## 📁 Project Structure

    wasm_bucket/
    ├── bucket/
    │ ├── module_name/
    │ │ ├── module_name.rs
    │ │ └── module_name.wasm ← (compiled output)
    │ └── ...
    └── README.md
