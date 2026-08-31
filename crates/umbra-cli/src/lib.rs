//! # Umbra CLI
//!
//! Command-line front end library surface: CLI definitions, sandbox
//! helpers, clipboard manager, and the TUI. The `umbra` binary in
//! `main.rs` is a thin wrapper.

pub mod cli;
pub mod clipboard;
pub mod notify;
pub mod sandbox;
pub mod tui;
