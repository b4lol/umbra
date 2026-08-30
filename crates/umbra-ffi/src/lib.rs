//! # Umbra FFI Bridge
//!
//! Type-safe bridge surface between the Android Jetpack Compose UI and the
//! Rust core (SPECIFICATION.md §3). The trait mirrors the documented
//! `UmbraCoreController` interface; UniFFI scaffolding generation
//! (`uniffi-bindgen`, Kotlin bindings) lands with TODO B.4 — this crate
//! pins the API so call sites can be written against it today.

#![forbid(unsafe_code)]

pub mod controller;

pub use controller::{CoreControllerError, IdentityKeys, StubController, UmbraCoreController};
