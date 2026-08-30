//! # Umbra Hardware Security Bridge
//!
//! The sole crate permitted to use `unsafe` (CONTRIBUTING §2, ADR-012):
//! direct physical-hardware communication only — `mlock` page locking,
//! TPM/Secure Enclave, FIDO2/YubiKey USB-NFC raw drivers, hardware TRNG.
//!
//! Rules for every future `unsafe` block (ADR-012):
//!
//! 1. Encapsulated behind a 100% Safe public API.
//! 2. `// SAFETY:` justification documenting the compiler invariants
//!    (`-D clippy::undocumented_unsafe_blocks`).
//! 3. Scanned with `cargo-geiger` / `cargo-deny` in CI.
//!
//! The skeleton ships no `unsafe`; see [`token`] for the safe driver API.

#![deny(unsafe_code)]

pub mod token;

pub use token::{HardwareError, HardwareSecurityKey};
