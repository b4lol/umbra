//! # Umbra Linux GUI
//!
//! GTK4 + Libadwaita, Wayland-only graphical front end (ROADMAP Phase 3,
//! TODO B.3, ADR-027 deferral).
//!
//! First increment landed (TODO B.3, 2026-09-13, see
//! `docs/superpowers/specs/2026-09-13-gui-wayland-skeleton-design.md`):
//! the [`wayland`] module's Wayland-only enforcement check, wired into
//! the `umbra-gui` binary's `main()` before GTK/Adwaita ever
//! initializes. The binary otherwise opens an empty placeholder window
//! — no keystore, no session, no sandboxing yet (all deferred to their
//! own future increments; see the design doc's "Out of scope"
//! section).
//!
//! Scope when fully implemented (CLIENT_SECURITY / DECISIONS ADR-004):
//!
//! - `WAYLAND_DISPLAY` enforcement at startup: refuse to run under X11.
//! - `mlock` swap-leak prevention on all sensitive buffers.
//! - Decoy Vault (Duress PIN) entry integration.
//! - Scratch-to-Reveal dynamic masking for message previews.

pub mod wayland;
