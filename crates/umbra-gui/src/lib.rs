//! # Umbra Linux GUI (reserved)
//!
//! GTK4 + Libadwaita, Wayland-only graphical front end (ROADMAP Phase 3,
//! TODO B.3, ADR-027 deferral).
//!
//! Scope when implemented (CLIENT_SECURITY / DECISIONS ADR-004):
//!
//! - `WAYLAND_DISPLAY` enforcement at startup: refuse to run under X11.
//! - `mlock` swap-leak prevention on all sensitive buffers.
//! - Decoy Vault (Duress PIN) entry integration.
//! - Scratch-to-Reveal dynamic masking for message previews.
//!
//! The GTK4/Libadwaita dependencies are deliberately not declared in the
//! MVP workspace (ADR-027); this crate reserves the module slot.
