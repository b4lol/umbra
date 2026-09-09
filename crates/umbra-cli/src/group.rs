//! `umbra group` subcommands: PQ-MLS group ("cell") management
//! (TODO B.2). Currently `create`/`export-keypackage`/`add`/`send`;
//! later tasks in the same plan add invite/join/receive operations to
//! this same enum.
//!
//! # `add`/`send`'s transport scope (ruled, binding — see the SDD
//! ledger's "Rulings before Task 8 dispatch" entry, extended unchanged
//! to `send` at Task 10 dispatch)
//!
//! `umbra-group` itself (`add_member`/`send_group_message`) is
//! transport-agnostic — it never dials anything directly, only calls a
//! caller-supplied `connect` closure. THIS module supplies that
//! closure, and its real, functioning implementation covers ONLY
//! [`PeerTransportAddress::Onion`] (via a bootstrapped
//! [`umbra_net::tor::TorTransport`], `#[cfg(feature = "tor")]`,
//! mirroring `tor_send.rs`'s own bootstrap pattern but with NO PQXDH
//! handshake — group frames carry their own MLS-level encryption, so
//! the stream is handed straight to `deliver_to_members` once opened).
//! [`PeerTransportAddress::Mesh`]/[`PeerTransportAddress::Nym`] (and a
//! peer record with no address on file at all, which `peer_lookup`
//! itself already reports as `None`) return a clear, explicit
//! [`umbra_group::GroupError`] rather than attempting real mesh/Nym
//! dialing — an intentional, ruled scope bound for this task (not full
//! multi-transport CLI maturity), not an oversight. Building without
//! the `tor` feature also returns a clear error for onion addresses
//! (mirrors `Command::Send`'s existing `#[cfg(not(feature = "tor"))]`
//! fallback in `cli.rs`), rather than a confusing "not yet implemented"
//! message that would misleadingly suggest the transport itself is
//! unbuilt everywhere.
//!
//! `send`'s `connect` closure is textually identical to `add`'s own
//! (same match on [`PeerTransportAddress`], same error messages) but is
//! NOT factored into one shared helper: `add_member`'s and
//! `send_group_message`'s own `F`/`Fut` type parameters are distinct
//! (different call sites, both generic), so a shared closure-building
//! helper would need to return `impl Fn(&PeerTransportAddress) -> impl
//! Future<...>` at two independent call sites with the closure's
//! captures (`&transport`) tied to a local borrow — attempted and found
//! to fight the borrow checker for no real gain over the current, small
//! (and already-reviewed, for `add`) duplication. Kept as two small
//! copies rather than forced into one generic.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use umbra_group::delivery::PeerTransportAddress;

use crate::cli::{Cli, CliError};

/// Upper bound for stdin under `mlockall`, matching the Tor-/mesh-send
/// ceiling (`tor_send::MAX_TOR_MESSAGE`/`mesh_send::MAX_MESH_MESSAGE`)
/// — no group-message-specific throughput characteristic has been
/// measured yet, so the same conservative bound applies (this crate
/// has no single shared "message size ceiling" constant to reuse
/// instead; each send path defines its own copy of the same value).
pub const MAX_GROUP_MESSAGE: usize = 64 * 1024;

/// `umbra group` subcommands.
#[derive(Debug, Subcommand)]
pub enum GroupCommand {
    /// Creates a new PQ-MLS group ("cell") with the caller as its
    /// sole initial member, generating this peer's group identity
    /// first if one does not already exist.
    Create {
        /// Group name; used as the persisted group-state file's name
        /// (`<keystore-dir>/groups/<name>.enc`).
        #[arg(long)]
        name: String,
    },

    /// Generates a fresh MLS `KeyPackage` for this peer's group
    /// identity and prints its base64-encoded wire form on `stdout`
    /// (one line) — the group-membership analog of `umbra
    /// export-pairing`, for out-of-band delivery to whoever will add
    /// this peer to a group.
    ExportKeypackage,

    /// Adds a peer (identified by a stored peer record name and their
    /// exported `KeyPackage` blob) to an existing group: commits the
    /// addition, persists the updated state, and attempts to deliver
    /// the resulting Commit/Welcome frames to the group's members (see
    /// this module's own docs for the exact, ruled transport scope —
    /// real delivery is currently Tor-only).
    Add {
        /// Group name (matches the `--name` used at `umbra group
        /// create`).
        #[arg(long)]
        group: String,
        /// Peer record name being added ([A-Za-z0-9_-]+), resolved
        /// from the peers/ directory next to the keystore.
        #[arg(long)]
        peer: String,
        /// The peer's base64-encoded `KeyPackage` blob, as printed by
        /// their own `umbra group export-keypackage`.
        #[arg(long)]
        keypackage: String,
    },

    /// Encrypts stdin (bounded, see [`MAX_GROUP_MESSAGE`]) as an MLS
    /// application message under the named group's current epoch state
    /// and attempts to deliver it to every member of the group's
    /// roster (see this module's own docs for the exact, ruled
    /// transport scope — real delivery is currently Tor-only).
    Send {
        /// Group name (matches the `--name` used at `umbra group
        /// create`).
        #[arg(long)]
        group: String,
    },
}

/// Dispatches a parsed `umbra group` subcommand.
///
/// Takes `command` by reference (rather than by value) so callers can
/// dispatch from a `match cli.command { ref sub, .. }` arm without
/// moving `cli.command` out from under a later `&cli` borrow in the
/// same arm (`cli.rs`'s top-level dispatch borrows `cli` as a whole to
/// reach `--keystore`/`--passphrase-file`).
///
/// # Errors
///
/// Returns [`CliError`] on failure.
pub fn dispatch(command: &GroupCommand, cli: &Cli) -> Result<(), CliError> {
    match command {
        GroupCommand::Create { name } => create(cli, name),
        GroupCommand::ExportKeypackage => export_keypackage(cli),
        GroupCommand::Add {
            group,
            peer,
            keypackage,
        } => add(cli, group, peer, keypackage),
        GroupCommand::Send { group } => send(cli, group),
    }
}

/// Resolves the keystore directory the same way `cli.rs`'s
/// `load_peer_record` does: the parent of `--keystore PATH`, or `.` if
/// `--keystore` was not given.
fn keystore_dir(cli: &Cli) -> PathBuf {
    cli.keystore
        .as_ref()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// `umbra group create --name NAME`.
fn create(cli: &Cli, name: &str) -> Result<(), CliError> {
    let passphrase = crate::cli::load_passphrase(cli)?;
    umbra_group::create::create_group(&keystore_dir(cli), &passphrase, name)?;
    Ok(())
}

/// `umbra group export-keypackage`: prints the fresh key package's
/// base64 blob on `stdout` (mirrors `export_pairing`'s exact style —
/// one line, nothing else).
fn export_keypackage(cli: &Cli) -> Result<(), CliError> {
    let passphrase = crate::cli::load_passphrase(cli)?;
    let blob = umbra_group::keypackage::export_keypackage(&keystore_dir(cli), &passphrase)?;
    crate::cli::output::line(&blob);
    Ok(())
}

/// Builds a `peer_lookup` closure resolving an Umbra peer name to a
/// [`PeerTransportAddress`], from the peers/ directory next to the
/// keystore — the same directory and record format `Send`'s own
/// dispatch (`cli.rs`'s `load_peer_record`) already uses via
/// `crate::peers::load_peer`.
///
/// Checks `onion`, then `mesh_addr`, then `nym_addr`, in that priority
/// order (Tor is the only one with real delivery support in this
/// module — see the module docs — but this still reports the address
/// kind honestly rather than only ever returning `Onion`, so a caller
/// gets an accurate "not yet implemented for this transport" error
/// instead of a misleading "no address on file" one when a peer only
/// has a mesh/Nym address recorded). Returns `None` (no address on
/// file) for an unknown peer name or a peer record with none of the
/// three set.
fn peer_lookup(peers_dir: PathBuf) -> impl Fn(&str) -> Option<PeerTransportAddress> {
    move |name: &str| {
        let record = crate::peers::load_peer(&peers_dir, name).ok()?;
        if let Some(onion) = record.onion {
            Some(PeerTransportAddress::Onion(onion))
        } else if let Some(mesh_addr) = record.mesh_addr {
            Some(PeerTransportAddress::Mesh(mesh_addr))
        } else {
            record.nym_addr.map(PeerTransportAddress::Nym)
        }
    }
}

/// `umbra group add --group NAME --peer NAME --keypackage BLOB`.
///
/// Drives `umbra_group::add::add_member` (an async fn, per Task 7's
/// delivery design) from this synchronous CLI dispatch via a
/// dedicated Tokio runtime — mirrors `tor_send.rs`'s own
/// `runtime.block_on(async move { ... })` pattern.
fn add(cli: &Cli, group: &str, peer: &str, keypackage: &str) -> Result<(), CliError> {
    let passphrase = crate::cli::load_passphrase(cli)?;
    let keystore_dir = keystore_dir(cli);
    let peers_dir = keystore_dir.join("peers");
    let lookup = peer_lookup(peers_dir);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(CliError::Io)?;

    runtime.block_on(add_member_over_tor(
        cli,
        &keystore_dir,
        &passphrase,
        group,
        peer,
        keypackage,
        lookup,
    ))?;

    crate::cli::output::line(&format!("added {peer} to group {group}"));
    Ok(())
}

/// Builds the real, `#[cfg(feature = "tor")]`-gated `connect` closure
/// (bootstraps a [`umbra_net::tor::TorTransport`] and opens a stream —
/// NO PQXDH handshake, per the module docs) and drives `add_member`
/// with it.
///
/// # Errors
///
/// Returns [`CliError`] if `--keystore PATH` is missing, if the Tor
/// storage directory cannot be created, if bootstrapping Tor fails, or
/// if `add_member` itself fails.
#[cfg(feature = "tor")]
async fn add_member_over_tor(
    cli: &Cli,
    keystore_dir: &Path,
    passphrase: &[u8],
    group: &str,
    peer: &str,
    keypackage: &str,
    peer_lookup: impl Fn(&str) -> Option<PeerTransportAddress>,
) -> Result<(), CliError> {
    let keystore_file = cli
        .keystore
        .clone()
        .ok_or_else(|| CliError::Keystore("missing --keystore PATH".into()))?;
    let tor_base = crate::serve::tor_base_from_keystore(&keystore_file)?;
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&tor_base)
            .map_err(CliError::Io)?;
    }
    let transport = umbra_net::tor::TorTransport::bootstrap_persistent(&tor_base)
        .await
        .map_err(|error| CliError::Keystore(format!("tor transport bootstrap failed: {error}")))?;

    let connect = |address: &PeerTransportAddress| {
        let transport = &transport;
        // Cloned into an owned value BEFORE the `async move` block: the
        // block must not borrow from `address`'s caller-side reference,
        // whose lifetime does not satisfy the `Fn(&PeerTransportAddress)
        // -> Fut` bound's implied HRTB (verified: borrowing directly
        // here is rejected by the borrow checker as "lifetime may not
        // live long enough").
        let address = address.clone();
        async move {
            match address {
                PeerTransportAddress::Onion(addr) => {
                    let onion_addr = umbra_net::addr::OnionAddr::parse(&addr).map_err(|error| {
                        umbra_group::GroupError::Malformed(format!("invalid onion address: {error}"))
                    })?;
                    let stream = transport.open_stream(&onion_addr).await.map_err(|error| {
                        umbra_group::GroupError::Malformed(format!("tor connect failed: {error}"))
                    })?;
                    Ok(Box::new(stream) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>)
                }
                // Ruled scope bound (module docs): real mesh/Nym group
                // delivery is not yet implemented — return a clear,
                // explicit error rather than attempting to dial.
                PeerTransportAddress::Mesh(_) | PeerTransportAddress::Nym(_) => {
                    Err(umbra_group::GroupError::Malformed(
                        "group delivery not yet implemented for this transport".into(),
                    ))
                }
            }
        }
    };

    umbra_group::add::add_member(
        keystore_dir,
        passphrase,
        group,
        peer,
        keypackage,
        peer_lookup,
        connect,
    )
    .await?;
    Ok(())
}

/// Fallback for builds without the `tor` build feature: every address
/// kind returns a clear, explicit error (an onion address specifically
/// names the missing feature — mirrors `Command::Send`'s existing
/// `#[cfg(not(feature = "tor"))]` fallback in `cli.rs` — a mesh/Nym
/// address gets the same "not yet implemented" message the `tor`-build
/// variant above gives them, since real delivery for those transports
/// is out of scope for this task regardless of build features).
///
/// # Errors
///
/// Returns [`CliError`] if `add_member` itself fails (its own
/// `connect` closure never succeeds here, so this is reachable only
/// via the non-delivery failure paths — malformed key package, missing
/// group/identity, etc. — delivery failures themselves are non-fatal,
/// see `umbra_group::add`'s own module docs).
#[cfg(not(feature = "tor"))]
async fn add_member_over_tor(
    _cli: &Cli,
    keystore_dir: &Path,
    passphrase: &[u8],
    group: &str,
    peer: &str,
    keypackage: &str,
    peer_lookup: impl Fn(&str) -> Option<PeerTransportAddress>,
) -> Result<(), CliError> {
    let connect = |address: &PeerTransportAddress| {
        // Resolved to a `&'static str` OUTSIDE the `async move` block
        // (same reasoning as the `tor`-feature variant above's
        // `address.clone()`: the block must not borrow anything tied
        // to `address`'s caller-side lifetime).
        let message: &'static str = match address {
            PeerTransportAddress::Onion(_) => {
                "this binary was built without the tor feature; rebuild with --features tor"
            }
            PeerTransportAddress::Mesh(_) | PeerTransportAddress::Nym(_) => {
                "group delivery not yet implemented for this transport"
            }
        };
        async move { Err(umbra_group::GroupError::Malformed(message.into())) }
    };

    umbra_group::add::add_member(
        keystore_dir,
        passphrase,
        group,
        peer,
        keypackage,
        peer_lookup,
        connect,
    )
    .await?;
    Ok(())
}

/// `umbra group send --group NAME`: reads stdin (bounded, mirrors
/// `mesh_send.rs`/`tor_send.rs`'s own stdin-bound idiom exactly) and
/// drives `umbra_group::send::send_group_message` (an async fn, per
/// Task 7's delivery design) from this synchronous CLI dispatch via a
/// dedicated Tokio runtime — mirrors `add`'s own
/// `runtime.block_on(async move { ... })` pattern.
fn send(cli: &Cli, group: &str) -> Result<(), CliError> {
    // NOTE: unlike `mesh_send::run`/`tor_send::run`, this does not call
    // `umbra_hardware::process::harden_process()` itself before reading
    // stdin — mirrors this file's own `add`/`create`/`export_keypackage`
    // functions, none of which harden memory either (`Command::Group`'s
    // own dispatch arm in `cli.rs` does not call it beforehand, unlike
    // several other top-level commands' arms). Consistent with the
    // existing pattern in this file rather than introduced fresh here.
    let mut plaintext =
        zeroize::Zeroizing::new(Vec::with_capacity(MAX_GROUP_MESSAGE.saturating_add(1)));
    std::io::stdin()
        .lock()
        .take((MAX_GROUP_MESSAGE as u64).saturating_add(1))
        .read_to_end(&mut plaintext)
        .map_err(CliError::Io)?;
    if plaintext.len() > MAX_GROUP_MESSAGE {
        return Err(CliError::Io(std::io::Error::other(format!(
            "stdin exceeds the {MAX_GROUP_MESSAGE}-byte group-send ceiling"
        ))));
    }
    if plaintext.is_empty() {
        return Err(CliError::Io(std::io::Error::other(
            "empty stdin: nothing to send",
        )));
    }

    let passphrase = crate::cli::load_passphrase(cli)?;
    let keystore_dir = keystore_dir(cli);
    let peers_dir = keystore_dir.join("peers");
    let lookup = peer_lookup(peers_dir);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(CliError::Io)?;

    runtime.block_on(send_group_message_over_tor(
        cli,
        &keystore_dir,
        &passphrase,
        group,
        &plaintext,
        lookup,
    ))?;

    crate::cli::output::line(&format!("sent message to group {group}"));
    Ok(())
}

/// Builds the real, `#[cfg(feature = "tor")]`-gated `connect` closure
/// (bootstraps a [`umbra_net::tor::TorTransport`] and opens a stream —
/// NO PQXDH handshake, per the module docs) and drives
/// `send_group_message` with it.
///
/// # Errors
///
/// Returns [`CliError`] if `--keystore PATH` is missing, if the Tor
/// storage directory cannot be created, if bootstrapping Tor fails, or
/// if `send_group_message` itself fails.
#[cfg(feature = "tor")]
async fn send_group_message_over_tor(
    cli: &Cli,
    keystore_dir: &Path,
    passphrase: &[u8],
    group: &str,
    plaintext: &[u8],
    peer_lookup: impl Fn(&str) -> Option<PeerTransportAddress>,
) -> Result<(), CliError> {
    let keystore_file = cli
        .keystore
        .clone()
        .ok_or_else(|| CliError::Keystore("missing --keystore PATH".into()))?;
    let tor_base = crate::serve::tor_base_from_keystore(&keystore_file)?;
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&tor_base)
            .map_err(CliError::Io)?;
    }
    let transport = umbra_net::tor::TorTransport::bootstrap_persistent(&tor_base)
        .await
        .map_err(|error| CliError::Keystore(format!("tor transport bootstrap failed: {error}")))?;

    let connect = |address: &PeerTransportAddress| {
        let transport = &transport;
        // Cloned into an owned value BEFORE the `async move` block: see
        // `add_member_over_tor`'s identical comment for why.
        let address = address.clone();
        async move {
            match address {
                PeerTransportAddress::Onion(addr) => {
                    let onion_addr = umbra_net::addr::OnionAddr::parse(&addr).map_err(|error| {
                        umbra_group::GroupError::Malformed(format!("invalid onion address: {error}"))
                    })?;
                    let stream = transport.open_stream(&onion_addr).await.map_err(|error| {
                        umbra_group::GroupError::Malformed(format!("tor connect failed: {error}"))
                    })?;
                    Ok(Box::new(stream) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>)
                }
                // Ruled scope bound (module docs): real mesh/Nym group
                // delivery is not yet implemented — return a clear,
                // explicit error rather than attempting to dial.
                PeerTransportAddress::Mesh(_) | PeerTransportAddress::Nym(_) => {
                    Err(umbra_group::GroupError::Malformed(
                        "group delivery not yet implemented for this transport".into(),
                    ))
                }
            }
        }
    };

    umbra_group::send::send_group_message(keystore_dir, passphrase, group, plaintext, peer_lookup, connect)
        .await?;
    Ok(())
}

/// Fallback for builds without the `tor` build feature: every address
/// kind returns a clear, explicit error (mirrors `add_member_over_tor`'s
/// own `#[cfg(not(feature = "tor"))]` fallback exactly).
///
/// # Errors
///
/// Returns [`CliError`] if `send_group_message` itself fails (its own
/// `connect` closure never succeeds here, so this is reachable only via
/// the non-delivery failure paths — missing group/identity, etc. —
/// delivery failures themselves are non-fatal, see
/// `umbra_group::send`'s own module docs).
#[cfg(not(feature = "tor"))]
async fn send_group_message_over_tor(
    _cli: &Cli,
    keystore_dir: &Path,
    passphrase: &[u8],
    group: &str,
    plaintext: &[u8],
    peer_lookup: impl Fn(&str) -> Option<PeerTransportAddress>,
) -> Result<(), CliError> {
    let connect = |address: &PeerTransportAddress| {
        // Resolved to a `&'static str` OUTSIDE the `async move` block
        // (same reasoning as `add_member_over_tor`'s non-`tor` fallback).
        let message: &'static str = match address {
            PeerTransportAddress::Onion(_) => {
                "this binary was built without the tor feature; rebuild with --features tor"
            }
            PeerTransportAddress::Mesh(_) | PeerTransportAddress::Nym(_) => {
                "group delivery not yet implemented for this transport"
            }
        };
        async move { Err(umbra_group::GroupError::Malformed(message.into())) }
    };

    umbra_group::send::send_group_message(keystore_dir, passphrase, group, plaintext, peer_lookup, connect)
        .await?;
    Ok(())
}
