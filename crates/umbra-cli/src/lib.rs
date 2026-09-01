//! # Umbra CLI
//!
//! Command-line front end library surface: CLI definitions, sandbox
//! helpers, clipboard manager, and the TUI. The `umbra` binary in
//! `main.rs` is a thin wrapper.

pub mod cli;
pub mod clipboard;
pub mod keystore;
pub mod notify;
pub mod pairing;
pub mod peers;
pub mod pipeline;
pub mod sandbox;
#[cfg(feature = "tor")]
pub mod serve;
#[cfg(feature = "tor")]
pub mod tor_send;
pub mod tui;
