//! Standalone `uniffi-bindgen` entry point for `umbra-ffi` (TODO B.4
//! Phase 1). Generates Kotlin (and other UniFFI-supported language)
//! bindings from the compiled `libumbra_native` cdylib in library mode —
//! no separate `.udl` file, matching this crate's proc-macro-based
//! `uniffi::setup_scaffolding!()` export style (`src/lib.rs`).
//!
//! Usage (from the crate or workspace root, after `cargo build -p
//! umbra-ffi`):
//!
//! ```sh
//! cargo run -p umbra-ffi --bin uniffi-bindgen -- generate \
//!     --library target/debug/libumbra_native.so \
//!     --language kotlin \
//!     --out-dir /tmp/umbra-kotlin-bindings
//! ```

fn main() {
    uniffi::uniffi_bindgen_main();
}
