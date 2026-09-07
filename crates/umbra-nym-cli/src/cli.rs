//! `umbra-nym` CLI surface (TODO B.1): the `send-nym`/`serve-nym`
//! subcommands wiring together the Nym transport (Task 7), the PQXDH
//! stream-to-single-message bridge (Task 8), and this crate's own
//! Seccomp profile (Task 12 — needed by `serve-nym` only; `send-nym`'s
//! ephemeral client stays on the narrower default profile) onto
//! `umbra-cli`'s reused keystore and
//! peer-record infrastructure — consumed as an EXTERNAL crate
//! (`umbra_cli::keystore`, `umbra_cli::peers`, `umbra_cli::sandbox`),
//! since `umbra-nym-cli` is a separate Cargo workspace (see
//! `Cargo.toml`'s package description for why: `nym-sdk`'s SQLite
//! dependency chain conflicts with the main workspace's Tor feature).
//!
//! `send-nym` mirrors `umbra-cli`'s `mesh_send.rs` structure (bounded
//! stdin read, sandbox, one-shot session); `serve-nym` mirrors
//! `serve.rs`'s structure (identity seeds loaded once, sandbox, runtime,
//! connect, unbounded accept loop). Argument conventions (`--keystore`,
//! `--passphrase-file` holding the passphrase's first line, the peer
//! record resolved from a `peers/` directory next to the keystore) are
//! copied from `umbra-cli`'s own `cli.rs` rather than invented fresh.
//!
//! # Stdout contract for `serve-nym`
//!
//! `umbra-cli`'s NDJSON "ready"/"text" event emission (`emit_event`) is
//! a small, PRIVATE `fn` duplicated independently in each of
//! `serve.rs`, `mesh_serve.rs`, `tor_send.rs`, and `mesh_send.rs` — not
//! a shared, reusable export. This module follows that same
//! established convention: [`emit_event`] below is this crate's own
//! copy, byte-for-byte matching `serve.rs`'s line format, so tooling
//! built against `umbra serve`'s NDJSON output works unchanged against
//! `umbra-nym serve-nym`. Each stdout line is one JSON object plus a
//! trailing `\n`:
//!
//! - `{"event":"ready","data":"<base64url-nopad>"}` — emitted exactly
//!   once, right after the mixnet client finishes connecting. The
//!   `data` field decodes (base64url, no padding) to the UTF-8 string
//!   `nym:<identity>.<encryption>@<gateway>` (this process's own Nym
//!   address, prefixed the same way `serve.rs` prefixes its `ready`
//!   event with `onion:`).
//! - `{"event":"text","data":"<base64url-nopad>"}` — emitted once per
//!   successfully decrypted inbound message. `data` decodes to the raw
//!   plaintext bytes (no prefix).
//!
//! Per-connection failures (a bad handshake, a corrupt frame) are
//! logged to stderr as plain text and do NOT stop the loop, mirroring
//! `serve.rs::run`'s accept loop; a fatal transport-level failure (the
//! mixnet client's own stream ending) stops the loop and returns an
//! error.
//!
//! Both flows call `umbra_hardware::process::harden_process()`
//! (mlockall/MCL_FUTURE + non-dumpable, ADR-025) as their literal FIRST
//! step, before any secret material (identity seeds, peer PQXDH keys,
//! plaintext) touches RAM — matching `serve.rs`/`tor_send.rs`/
//! `mesh_send.rs`'s own ordering exactly.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use clap::{Parser, Subcommand};
use umbra_crypto::keys::IdentityBundle;
use umbra_net::{PeerPqxdhKeys, TransportError};

use crate::addr::NymPeerAddr;
use crate::client::{NymClient, NymNetwork, STREAM_ENDED};
use crate::transport::NymTransport as _;

/// Upper bound on the plaintext `send-nym` accepts from stdin, matching
/// `umbra_net::messenger::MAX_TEXT_MESSAGE` exactly. `send_via_nym`
/// (Task 8) has no runtime check enforcing this bound on its own
/// plaintext argument — a message beyond `MAX_TEXT_MESSAGE` would be
/// silently rejected deep inside `receive_message` on the FAR end
/// instead, which would look like a hang, not a clear error. Checking
/// it here, before ever touching the network, gives the operator an
/// immediate, actionable error.
const MAX_SEND_MESSAGE: usize = umbra_net::messenger::MAX_TEXT_MESSAGE;

/// `umbra-nym`: standalone CLI for Umbra's Nym Mixnet adapter.
#[derive(Debug, Parser)]
#[command(name = "umbra-nym", version, about)]
pub struct Cli {
    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Command,
}

/// `umbra-nym` subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Sends one message (read from stdin) to a named peer over the
    /// Nym mixnet, then exits. Uses a fresh, ephemeral Nym identity for
    /// this one send (Task 8's duplex-bridge finding: PQXDH lets a
    /// sender complete and transmit using only the recipient's
    /// asynchronously-known prekey bundle, so no reply — and thus no
    /// persistent Nym address for the sender — is ever needed). That
    /// identity is generated in memory and never written to disk, so
    /// `send-nym` has no config directory and deliberately exposes no
    /// flag to give it one. Like `umbra send`'s own Tor/mesh outbound
    /// paths, the caller's KEYSTORE IDENTITY is never read for a send:
    /// `--keystore` is used only to locate the `peers/` directory next
    /// to it.
    SendNym {
        /// Keystore file path; used only to locate the `peers/`
        /// directory next to it (`<parent>/peers`) — the identity it
        /// holds is never read for a send, mirroring `umbra send`'s
        /// own Tor/mesh outbound paths.
        #[arg(long, value_name = "PATH")]
        keystore: PathBuf,
        /// Peer record name ([A-Za-z0-9_-]+), resolved from the
        /// `peers/` directory next to `--keystore`.
        #[arg(long)]
        peer: String,
        /// Peer's Nym address (`identity.encryption@gateway`);
        /// overrides the address stored in the peer record.
        #[arg(long, value_name = "ADDRESS")]
        nym_addr: Option<String>,
        /// Use Nym's production mainnet instead of the Sandbox
        /// testnet.
        #[arg(long)]
        mainnet: bool,
    },
    /// Serves inbound messages over the Nym mixnet: connects a
    /// persistent Nym client rooted at `--nym-config` and loops,
    /// printing one NDJSON line per event on stdout (see this module's
    /// docs for the exact format) until the process is terminated.
    ServeNym {
        /// Keystore file path (see `umbra keygen`/`umbra init`).
        #[arg(long, value_name = "PATH")]
        keystore: PathBuf,
        /// File containing the keystore passphrase (first line;
        /// mode-0600), matching `umbra`'s own `--passphrase-file`
        /// convention.
        #[arg(long, value_name = "PATH")]
        passphrase_file: PathBuf,
        /// Directory for this client's PERSISTENT Nym storage
        /// (identity keys, gateway registration, SURB/reply-surb
        /// state) — survives process restarts, the Nym-address
        /// equivalent of a stable `.onion` keystore. Created with
        /// `0700` permissions if missing.
        #[arg(long, value_name = "PATH")]
        nym_config: PathBuf,
        /// Use Nym's production mainnet instead of the Sandbox
        /// testnet.
        #[arg(long)]
        mainnet: bool,
    },
}

/// Resolves the peer-record directory NEXT TO the keystore
/// (`<keystore parent>/peers`), mirroring `umbra-cli`'s own
/// `cli.rs::load_peer_record` convention exactly.
fn peers_dir_from_keystore(keystore: &Path) -> PathBuf {
    keystore
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("peers")
}

/// Reads the keystore passphrase from `path` (first line only — a
/// trailing newline from editors or `echo` is not part of the
/// passphrase). Mirrors `umbra-cli`'s own `cli.rs::load_passphrase`
/// exactly; duplicated here since this is a separate crate with its
/// own CLI surface and no shared dependency for it.
fn load_passphrase(path: &Path) -> std::io::Result<zeroize::Zeroizing<Vec<u8>>> {
    let contents = std::fs::read(path)?;
    let first_line_end = contents
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(contents.len());
    let line = contents.get(..first_line_end).unwrap_or(&contents).to_vec();
    Ok(zeroize::Zeroizing::new(line))
}

/// Emits one NDJSON event line on stdout — see this module's docs for
/// the exact `serve-nym` stdout contract. Copied from `umbra-cli`'s
/// `serve.rs` private `emit_event` (base64url, no padding, identical
/// `data` field encoding) rather than shared, since that helper is
/// private to each of `umbra-cli`'s own binaries — this crate follows
/// the same established duplication convention.
fn emit_event(event: &str, data: Option<&[u8]>) -> std::io::Result<()> {
    let mut line = format!("{{\"event\":\"{event}\"");
    if let Some(bytes) = data {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        line.push_str(&format!(",\"data\":\"{b64}\""));
    }
    line.push_str("}\n");
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(line.as_bytes())
        .and_then(|()| stdout.flush())
}

/// Runs the `send-nym` flow: loads the named peer's record (the
/// caller's OWN keystore identity is never read — see the module docs
/// and `SendNym`'s own doc comment), reads one message from `input`
/// (bounded to [`MAX_SEND_MESSAGE`]), and delivers it as exactly one
/// Nym message over a fresh, EPHEMERAL, in-memory Nym identity
/// ([`NymClient::connect_ephemeral`]) — no config directory, no
/// `StoragePaths`, and no transport identity material written to disk
/// at any point, so there is nothing to clean up afterwards.
///
/// # Errors
///
/// Returns an error on I/O, oversized/empty stdin, peer record,
/// sandbox, or Nym transport failure.
pub fn run_send_nym(
    keystore: &Path,
    peer_name: &str,
    nym_addr_override: Option<&str>,
    mainnet: bool,
    input: &mut impl std::io::Read,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Memory hardening FIRST (ADR-025): mirrors `tor_send.rs`/`mesh_send.rs`/
    // `serve.rs`, all of which call this as their literal first step, before
    // any secret (here: the peer's PQXDH keys, the plaintext) touches RAM.
    umbra_hardware::process::harden_process()?;

    let peer = umbra_cli::peers::load_peer(&peers_dir_from_keystore(keystore), peer_name)?;

    let nym_addr = nym_addr_override
        .map(str::to_string)
        .or_else(|| peer.nym_addr.clone())
        .ok_or("no Nym address recorded or given for this peer")?;
    let peer_addr = NymPeerAddr::parse(&nym_addr)?;
    let peer_keys = PeerPqxdhKeys::from_parts(
        &peer.ik_arr,
        &peer.spk_arr,
        peer.spk_signature.clone(),
        peer.dsa.clone(),
        &peer.kem_arr,
    )?;

    let mut plaintext =
        zeroize::Zeroizing::new(Vec::with_capacity(MAX_SEND_MESSAGE.saturating_add(1)));
    input
        .take((MAX_SEND_MESSAGE as u64).saturating_add(1))
        .read_to_end(&mut plaintext)?;
    if plaintext.len() > MAX_SEND_MESSAGE {
        return Err(format!("stdin exceeds the {MAX_SEND_MESSAGE}-byte send-nym ceiling").into());
    }
    if plaintext.is_empty() {
        return Err("empty stdin: nothing to send".into());
    }

    // Network selection resolved HERE, on the main thread, BEFORE the
    // Tokio runtime (and its worker threads) exists: the Sandbox arm
    // populates the process environment on first use, and doing that
    // while worker threads could be reading it would be a data race no
    // `Once` can prevent. See `NymNetwork::details`.
    let network = if mainnet {
        NymNetwork::Mainnet
    } else {
        NymNetwork::Sandbox
    }
    .details();

    // `send-nym` needs NO filesystem access from here on: the peer
    // record was already read above, stdin's descriptor is already
    // open (Landlock does not revoke open descriptors), and the
    // ephemeral Nym identity below never touches disk. So the grant is
    // empty except for /etc.
    umbra_cli::sandbox::restrict_filesystem_with_exceptions(
        &[],
        // /etc is READ-ONLY: public resolver/config content only. Every
        // other network-touching flow in this project grants exactly
        // this (`umbra-cli`'s `serve.rs` and `tor_send.rs`) and the Nym
        // flows need it for the same class of reason: `nym-sdk` reaches
        // the network through `reqwest` → `rustls-platform-verifier` →
        // `rustls-native-certs`, which reads the system TLS trust store
        // (`/etc/ssl/certs`) while connecting negotiates TLS to Nym's
        // API/gateway endpoints.
        &[std::path::Path::new("/etc")],
    )?;
    // The DEFAULT profile, not `restrict_syscalls_nym()`: the three
    // extra base syscalls that one adds (`mkdir`/`unlink`/`chmod`) exist
    // solely for `nym-sdk`'s persistent SQLite storage backend and
    // `nym-pemstore`'s key-file writing, neither of which an ephemeral
    // client uses. Verified against the live Sandbox testnet: a full
    // `connect_ephemeral` + send round trip succeeds under this
    // narrower profile.
    umbra_cli::sandbox::restrict_syscalls()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let client = NymClient::connect_ephemeral(network).await?;
        crate::bridge::send_via_nym(&client, peer_addr, &peer_keys, &plaintext).await?;
        client.disconnect().await;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
}

/// Runs the `serve-nym` flow: loads the caller's identity seeds once,
/// connects a PERSISTENT Nym client rooted at `nym_config`, and loops
/// accepting inbound messages until the process is terminated —
/// mirroring `umbra-cli`'s own `serve.rs::run`'s structure (memory
/// hardening, identity load, sandbox, connect, loop). A fresh [`IdentityBundle`] is derived
/// from the loaded seeds for EVERY inbound message (no Argon2 re-run;
/// `IdentityBundle::from_seeds` is cheap), mirroring `serve.rs`'s own
/// `inbound_loop`, which does the same per accepted stream rather than
/// building the bundle once outside the loop.
///
/// # Errors
///
/// Returns an error on keystore, sandbox, or fatal Nym transport
/// failure (the mixnet client's own stream ending). Per-message
/// decode/handshake failures are logged to stderr and the loop
/// continues, matching `serve.rs`'s per-connection failure handling.
pub fn run_serve_nym(
    keystore: &Path,
    passphrase_file: &Path,
    nym_config: &Path,
    mainnet: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Memory hardening FIRST (ADR-025), before the passphrase or the
    // identity seeds it decrypts ever touch RAM — mirrors `serve.rs::run`'s
    // own ordering exactly (its step 1, before the keystore is even opened).
    umbra_hardware::process::harden_process()?;

    let passphrase = load_passphrase(passphrase_file)?;
    let seeds = std::sync::Arc::new(umbra_cli::keystore::load_seeds(keystore, &passphrase)?);

    // Network selection resolved HERE, on the main thread, BEFORE the
    // Tokio runtime (and its worker threads) exists — see
    // `NymNetwork::details` and `run_send_nym`'s matching comment.
    let network = if mainnet {
        NymNetwork::Mainnet
    } else {
        NymNetwork::Sandbox
    }
    .details();

    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(nym_config)?;
    }
    umbra_cli::sandbox::restrict_filesystem_with_exceptions(
        &[nym_config],
        // /etc is READ-ONLY: public resolver/config content only. Same
        // grant, and the same reason, as `run_send_nym` above and as
        // `umbra-cli`'s own `serve.rs`/`tor_send.rs`: `nym-sdk`'s
        // `reqwest` → `rustls-platform-verifier` → `rustls-native-certs`
        // chain reads the system TLS trust store (`/etc/ssl/certs`)
        // during `NymClient::connect`.
        &[std::path::Path::new("/etc")],
    )?;
    crate::sandbox::restrict_syscalls_nym()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let mut client = NymClient::connect(nym_config, network).await?;
        emit_event(
            "ready",
            Some(format!("nym:{}", client.address()).as_bytes()),
        )?;

        loop {
            let bundle = IdentityBundle::from_seeds(&seeds);
            match crate::bridge::receive_via_nym(&mut client, bundle).await {
                Ok(plaintext) => {
                    let plaintext = zeroize::Zeroizing::new(plaintext);
                    emit_event("text", Some(&plaintext))?;
                }
                // The FATAL case: the SDK's own `MixnetClient` stream
                // ended, so no further message will ever arrive.
                // Compared against `client.rs`'s `STREAM_ENDED`
                // constant — the same value that impl constructs — so
                // the two cannot drift apart.
                Err(TransportError::Nym(ref message)) if message == STREAM_ENDED => {
                    return Err(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                        "nym transport: {message}"
                    )));
                }
                Err(error) => {
                    eprintln!("umbra-nym: inbound session failed: {error}");
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{Cli, Command};
    use clap::Parser as _;

    #[test]
    fn send_nym_parses_required_flags() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let cli = Cli::try_parse_from([
            "umbra-nym",
            "send-nym",
            "--keystore",
            "/tmp/ks",
            "--peer",
            "alice",
        ])?;
        match cli.command {
            Command::SendNym {
                keystore,
                peer,
                nym_addr,
                mainnet,
            } => {
                assert_eq!(keystore, std::path::PathBuf::from("/tmp/ks"));
                assert_eq!(peer, "alice");
                assert_eq!(nym_addr, None);
                assert!(!mainnet);
            }
            Command::ServeNym { .. } => return Err("expected SendNym".into()),
        }
        Ok(())
    }

    #[test]
    fn serve_nym_parses_required_flags() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let cli = Cli::try_parse_from([
            "umbra-nym",
            "serve-nym",
            "--keystore",
            "/tmp/ks",
            "--passphrase-file",
            "/tmp/pass",
            "--nym-config",
            "/tmp/nym",
            "--mainnet",
        ])?;
        match cli.command {
            Command::ServeNym {
                keystore,
                passphrase_file,
                nym_config,
                mainnet,
            } => {
                assert_eq!(keystore, std::path::PathBuf::from("/tmp/ks"));
                assert_eq!(passphrase_file, std::path::PathBuf::from("/tmp/pass"));
                assert_eq!(nym_config, std::path::PathBuf::from("/tmp/nym"));
                assert!(mainnet);
            }
            Command::SendNym { .. } => return Err("expected ServeNym".into()),
        }
        Ok(())
    }

    #[test]
    fn send_nym_requires_peer() {
        let result = Cli::try_parse_from(["umbra-nym", "send-nym", "--keystore", "/tmp/ks"]);
        assert!(result.is_err());
    }
}
