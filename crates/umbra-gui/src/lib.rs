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
//! Second increment landed (TODO B.3, 2026-09-13, see
//! `docs/superpowers/specs/2026-09-13-gui-keystore-unlock-design.md`):
//! a keystore-unlock flow, wired into a real `--keystore PATH` +
//! password-entry flow in `main.rs`. Still no messaging, peer list, or
//! sandboxing yet.
//!
//! AF_UNIX Engine/UI separation LANDED (TODO B.3.1, 2026-09-15, see
//! `docs/superpowers/specs/2026-09-15-engine-ui-separation-design.md`):
//! the keystore-unlock computation moved OUT of this process entirely,
//! into a separate, sandboxed `umbra-engine` process spawned and
//! talked to over a private `AF_UNIX` socket ([`engine_client`]). This
//! process no longer links `umbra-cli`/`umbra-crypto` at all — the
//! identity's private key material now lives only in the Engine's own
//! address space.
//!
//! Scope when fully implemented (CLIENT_SECURITY / DECISIONS ADR-004):
//!
//! - `WAYLAND_DISPLAY` enforcement at startup: refuse to run under X11.
//! - `mlock` swap-leak prevention on all sensitive buffers.
//! - Decoy Vault (Duress PIN) entry integration.
//! - Scratch-to-Reveal dynamic masking for message previews.

pub mod engine_client;
pub mod scratch_reveal;
pub mod wayland;
