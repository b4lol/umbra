//! # Umbra FFI Bridge
//!
//! Type-safe bridge surface between the Android Jetpack Compose UI and the
//! Rust core (docs/SPECIFICATION.md §3). The trait mirrors the documented
//! `UmbraCoreController` interface. UniFFI scaffolding generation
//! (TODO B.4 Phase 1) is real: `uniffi::setup_scaffolding!()` below exports
//! [`controller::LiveController`] directly (UniFFI binds concrete types,
//! not `dyn Trait` objects — the `UmbraCoreController` trait itself stays
//! a Rust-internal abstraction), and `uniffi-bindgen` generates real
//! Kotlin bindings from the resulting `libumbra_native.so`
//! (`cargo run -p umbra-ffi --bin uniffi-bindgen -- generate --library
//! <path-to-.so> --language kotlin --out-dir <dir>`).

pub mod controller;
#[cfg(feature = "tor")]
pub mod session;

pub use controller::{
    CoreControllerError, IdentityKeys, LiveController, StubController, UmbraCoreController,
};

#[cfg(feature = "tor")]
pub use session::SessionEvent;

uniffi::setup_scaffolding!();
