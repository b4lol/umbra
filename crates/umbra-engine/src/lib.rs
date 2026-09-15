//! # `umbra-engine`
//!
//! The Engine half of TODO B.3.1's first increment (`docs/PROJECT.md`'s
//! "Discrete Process Isolation / Rule of Separation" principle): a
//! minimal, sandboxed process that owns keystore/decoy-vault secret
//! material on behalf of `umbra-gui`, served over one `AF_UNIX` socket
//! connection. See
//! `docs/superpowers/specs/2026-09-15-engine-ui-separation-design.md`.
//!
//! This increment implements exactly one operation, `"unlock"` — the
//! only secret-touching operation `umbra-gui` has today. [`protocol`]
//! defines the wire format; [`dispatch`] (added in a later task of
//! this same plan) implements `"unlock"`; [`run`] (also added later)
//! owns the socket/sandbox lifecycle.

pub mod protocol;
