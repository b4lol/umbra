//! Command definitions and dispatch (clap 4, derive API).

use clap::{Parser, Subcommand};
use std::path::Path;

use umbra_crypto::keys::IdentityBundle;
use umbra_hardware::memory::GuardedBuffer;

#[cfg(feature = "tor")]
use crate::tui;

/// Rule-of-Silence output helpers: only requested data hits `stdout`.
pub mod output {
    use std::fmt::Write as _;
    use std::io::Write as _;

    /// Writes a line of requested data to `stdout`.
    ///
    /// Write failures (for example, `EPIPE` when the consumer closed the
    /// pipe, as with `umbra keygen | head`) are swallowed silently instead
    /// of panicking — standard Unix pipe etiquette and Zero-Panic doctrine.
    pub fn line(text: &str) {
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{text}");
        let _ = stdout.flush();
    }

    /// Hex-encodes bytes without external dependencies.
    pub fn hex(bytes: &[u8]) -> String {
        let capacity = bytes.len().checked_mul(2).unwrap_or(bytes.len());
        let mut out = String::with_capacity(capacity);
        for byte in bytes {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}

/// `umbra` — zero-metadata, post-quantum anonymous communication.
#[derive(Debug, Parser)]
#[command(name = "umbra", version, about)]
pub struct Cli {
    /// Emit machine-readable NDJSON instead of key=value lines
    /// (ADR-022: parseable JSON streams for `jq`/`awk` pipelines).
    /// Honored by `keygen`, `send` (pipe path) and `recv` (NDJSON
    /// events). `serve` and the `send --onion` path emit NDJSON
    /// UNCONDITIONALLY (the flag is ignored there); other commands
    /// ignore the flag.
    #[arg(long, global = true)]
    pub json: bool,

    /// Keystore file path for commands that need persisted identity.
    #[arg(long, global = true, value_name = "PATH")]
    pub keystore: Option<std::path::PathBuf>,

    /// File containing the keystore passphrase (first line; interactive
    /// prompts land with the TUI
    /// is not supported in MVP — use a mode-0600 file).
    #[arg(long, global = true, value_name = "PATH")]
    pub passphrase_file: Option<std::path::PathBuf>,

    /// PKCS#11 module path for hardware-key-gated keystores (e.g.
    /// `/usr/lib64/pkcs11/libsofthsm2.so` for SoftHSM2, or the vendor
    /// module path for a real hardware token). Required, together with
    /// `--hw-pin-file` and `--hw-key-label`, for `init` to create a
    /// hardware-gated keystore, or to unlock one that already exists.
    /// Accepted as a trust boundary at the same level as
    /// `--keystore`/`--passphrase-file` (ADR-034's addendum) — this flag
    /// `dlopen`s whatever `.so` it points to, with no signature or
    /// provenance verification. Loading a PKCS#11 module happens after
    /// this process's `mlockall(MCL_FUTURE)` (ADR-025) runs — a
    /// constrained `RLIMIT_MEMLOCK` may cause the module's `dlopen` to
    /// fail with `ENOMEM`; raise the limit if that happens.
    #[arg(long, global = true, value_name = "PATH")]
    pub hw_module: Option<std::path::PathBuf>,

    /// File containing the hardware token's PIN (first line; same
    /// convention as `--passphrase-file` — never pass a PIN as a plain
    /// argument, it would leak via shell history and
    /// `/proc/<pid>/cmdline`).
    #[arg(long, global = true, value_name = "PATH")]
    pub hw_pin_file: Option<std::path::PathBuf>,

    /// Label of the token-held HMAC key to use (as passed to
    /// `umbra_hwkey::generate_hmac_key`/`challenge_response`).
    #[arg(long, global = true, value_name = "LABEL")]
    pub hw_key_label: Option<String>,

    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Command,
}

/// Umbra subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generates a fresh identity bundle and prints its public parts.
    Keygen,
    /// Encrypts stdin for a named peer. WITHOUT `--onion`: sealed frames
    /// to stdout (pipe transport). WITH `--onion` — explicit or stored in
    /// the peer record, which FORCES the Tor transport (requires the
    /// `tor` build feature) — delivered over embedded Arti to the peer's
    /// onion service; NDJSON events on stdout.
    Send {
        /// Peer record name ([A-Za-z0-9_-]+), resolved from the peers/
        /// directory next to the keystore.
        #[arg(long)]
        peer: String,
        /// Peer's `.onion` address; overrides the value stored with the
        /// peer record. Transport switches from pipe to embedded Tor.
        #[arg(long)]
        onion: Option<String>,
        /// Use the Wi-Fi Direct mesh transport (must be explicit — mesh
        /// mode has NO onion routing, docs/THREAT_MODEL.md "Off-Grid Mesh";
        /// a stored peer-record mesh address is never used unless this
        /// flag is passed). Mutually exclusive with `--onion`. Requires
        /// the `mesh` build feature.
        #[cfg(feature = "mesh")]
        #[arg(long, conflicts_with = "onion")]
        mesh: bool,
        /// Overrides the peer record's stored mesh address. Only
        /// meaningful with `--mesh`.
        #[cfg(feature = "mesh")]
        #[arg(long, requires = "mesh")]
        mesh_addr: Option<String>,
        /// Path to `wpa_supplicant`'s P2P `ctrl_interface` socket.
        /// Required when `--mesh` selects the mesh transport.
        #[cfg(feature = "mesh")]
        #[arg(long)]
        wpa_ctrl: Option<std::path::PathBuf>,
        /// Censorship circumvention (ADR-030 unmanaged PT model);
        /// Tor-transport only.
        #[cfg(feature = "tor")]
        #[command(flatten)]
        pt: crate::pt::PtArgs,
    },
    /// Decrypts a sealed pipe stream from stdin; plaintext to stdout.
    ///
    /// NOTE: the responder side does not authenticate the initiator —
    /// verify the SAS code out of band (umbra pairing-sas).
    Recv,
    /// Hosts the persistent inbound onion service (requires the `tor`
    /// build feature): bootstraps embedded Arti with a stable `.onion`
    /// address, applies the sandbox with the Tor-storage exception, and
    /// emits received messages as NDJSON on stdout.
    #[cfg(feature = "tor")]
    Serve {
        /// Onion service nickname (letters/digits; arti-validated).
        #[arg(long)]
        nickname: String,
        /// Censorship circumvention (ADR-030 unmanaged PT model).
        #[command(flatten)]
        pt: crate::pt::PtArgs,
    },
    /// Opens the interactive terminal client: live inbound onion feed,
    /// compose-and-send over Tor, peer selection. (Requires the `tor`
    /// build feature.)
    #[cfg(feature = "tor")]
    Tui {
        /// Onion service nickname for the inbound identity (persistent
        /// across runs under the Tor tree).
        #[arg(long, default_value = "umbra-tui")]
        nickname: String,
        /// Censorship circumvention (ADR-030 unmanaged PT model).
        #[command(flatten)]
        pt: crate::pt::PtArgs,
    },
    /// Creates a new persistent identity keystore.
    Init,
    /// Prints the 32-byte identity fingerprint (hex) of this identity,
    /// or of a stored peer record. Compare out of band.
    Fingerprint {
        /// Peer record name; omit to print this identity's fingerprint.
        #[arg(long)]
        peer: Option<String>,
    },
    /// Prints the base64url pairing payload for this identity.
    ExportPairing,
    /// Prints the shared 6-digit SAS code for two pairing payloads.
    PairingSas {
        /// Own base64url pairing payload (may legitimately start with
        /// '-': the base64url alphabet contains '-').
        #[arg(long, allow_hyphen_values = true)]
        own_payload: String,
        /// Peer base64url pairing payload (may legitimately start with
        /// '-': the base64url alphabet contains '-').
        #[arg(long, allow_hyphen_values = true)]
        peer_payload: String,
    },
    /// Stores a peer's pairing payload under a name and prints the shared
    /// SAS code (verify it with the peer over a trusted channel).
    Pair {
        /// Friendly name for the peer ([A-Za-z0-9_-]+).
        #[arg(long)]
        peer_name: String,
        /// Peer base64url pairing payload (may legitimately start with
        /// '-': the base64url alphabet contains '-').
        #[arg(long, allow_hyphen_values = true)]
        peer_payload: String,
        /// Peer's `.onion` service address (published by `umbra serve`);
        /// stored with the record for `send --peer`.
        #[arg(long)]
        onion: Option<String>,
        /// Peer's Wi-Fi Direct P2P Device Address (`aa:bb:cc:dd:ee:ff`);
        /// stored with the record for `send --mesh` (requires the
        /// `mesh` build feature to be USED, but is always storable).
        #[arg(long)]
        mesh_addr: Option<String>,
        /// Peer's Nym mixnet client address; stored with the record for
        /// `send --nym`.
        #[arg(long)]
        nym_addr: Option<String>,
    },
    /// Waits for an incoming Wi-Fi Direct connection from ANY paired
    /// peer (mesh has no onion identity to publish — see
    /// docs/THREAT_MODEL.md "Off-Grid Mesh") and decrypts one message.
    /// Requires the `mesh` build feature.
    #[cfg(feature = "mesh")]
    ServeMesh {
        /// Path to `wpa_supplicant`'s P2P `ctrl_interface` socket.
        #[arg(long)]
        wpa_ctrl: std::path::PathBuf,
    },
    /// PQ-MLS group ("cell") management (TODO B.2): create, and (in
    /// later tasks of the same plan) invite/join/send/receive.
    #[command(subcommand)]
    Group(crate::group::GroupCommand),
}

/// Top-level CLI error.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Protocol/crypto layer failure.
    #[error(transparent)]
    Protocol(#[from] umbra_protocol::ProtocolError),

    /// Hardware/memory-guard layer failure.
    #[error(transparent)]
    Hardware(#[from] umbra_hardware::HardwareError),

    /// Sandboxing (Landlock) failure.
    #[error(transparent)]
    Sandbox(#[from] landlock::RulesetError),

    /// Seccomp filter failure.
    #[error("seccomp failure: {0}")]
    Seccomp(String),

    /// Notification backend failure.
    #[error("notification failure: {0}")]
    Notify(String),

    /// Keystore / pairing failure.
    #[error("keystore failure: {0}")]
    Keystore(String),

    /// Crypto-layer failure inside the keystore path.
    #[error(transparent)]
    Crypto(#[from] umbra_crypto::CryptoError),

    /// Hardware-key (PKCS#11) layer failure.
    #[error(transparent)]
    HardwareKey(#[from] umbra_hwkey::HwKeyError),

    /// PQ-MLS group ("cell") layer failure (TODO B.2).
    #[error(transparent)]
    Group(#[from] umbra_group::GroupError),

    /// TUI failure.
    #[cfg(feature = "tor")]
    #[error(transparent)]
    Tui(#[from] tui::TuiError),

    /// Standard-stream I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Pipe-transport framing/handshake failure.
    #[error("pipe transport failure: {0}")]
    Pipe(String),
}

/// Applies ADR-025 memory hardening BEFORE any keystore read, so identity
/// secrets are born under `mlockall` with core dumps already disabled.
///
/// # Errors
///
/// Returns [`CliError::Hardware`] on kernel refusal.
fn harden_memory() -> Result<(), CliError> {
    umbra_hardware::process::harden_process()?;
    Ok(())
}

/// Applies the fail-closed Landlock zero-filesystem sandbox (ADR-007) and
/// the Seccomp allowlist AFTER keystore/peer-record reads are complete.
///
/// # Errors
///
/// Returns [`CliError::Sandbox`] or [`CliError::Seccomp`] on kernel refusal.
fn harden_sandbox() -> Result<(), CliError> {
    let _status = crate::sandbox::restrict_filesystem()?;
    // Seccomp is applied LAST: the Landlock syscalls above have already
    // run; afterwards the allowlist gates everything.
    crate::sandbox::restrict_syscalls()?;
    Ok(())
}

/// Executes the parsed command.
///
/// # Errors
///
/// Returns [`CliError`] on failure; diagnostics are printed by `main`.
pub fn run() -> Result<(), CliError> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen => keygen(cli.json),
        Command::Init => init_with(&cli),
        Command::Send {
            ref peer,
            ref onion,
            #[cfg(feature = "mesh")]
            ref mesh,
            #[cfg(feature = "mesh")]
            ref mesh_addr,
            #[cfg(feature = "mesh")]
            ref wpa_ctrl,
            #[cfg(feature = "tor")]
            ref pt,
        } => {
            // Peer records are public material: read them before the
            // flow split; memory locks and the sandbox are applied per
            // branch (the Tor path does NOT load the keystore identity —
            // its initiator is per-session ephemeral by design).
            let peer_record = load_peer_record(&cli, peer)?;
            #[cfg(feature = "mesh")]
            if *mesh {
                let address = mesh_addr
                    .as_deref()
                    .or(peer_record.mesh_addr.as_deref())
                    .ok_or_else(|| {
                        CliError::Keystore(
                            "--mesh requires either --mesh-addr or a stored peer mesh address"
                                .into(),
                        )
                    })?;
                let ctrl_path = wpa_ctrl
                    .as_ref()
                    .ok_or_else(|| CliError::Keystore("--mesh requires --wpa-ctrl PATH".into()))?;
                return crate::mesh_send::run(
                    ctrl_path,
                    address,
                    &peer_record,
                    &mut std::io::stdin().lock(),
                );
            }
            match onion.as_deref().or(peer_record.onion.as_deref()) {
                #[cfg(feature = "tor")]
                Some(address) => {
                    let keystore = cli
                        .keystore
                        .as_ref()
                        .ok_or_else(|| CliError::Keystore("missing --keystore PATH".into()))?
                        .clone();
                    crate::tor_send::run(
                        &keystore,
                        &peer_record,
                        address,
                        &mut std::io::stdin().lock(),
                        pt,
                    )
                }
                #[cfg(not(feature = "tor"))]
                Some(_address) => Err(CliError::Keystore(
                    "this binary was built without the tor feature; rebuild with \
                     --features tor"
                        .into(),
                )),
                None => {
                    // PT options are meaningless on the pipe transport —
                    // reject them loudly instead of silently ignoring.
                    #[cfg(feature = "tor")]
                    if pt.pt_socks.is_some() || !pt.bridges.is_empty() {
                        return Err(CliError::Keystore(
                            "--pt-socks/--bridge require the Tor transport (--onion)".into(),
                        ));
                    }
                    // Pipe path: memory locks BEFORE the identity load
                    // (ADR-025), sandbox after the reads.
                    harden_memory()?;
                    let bundle = load_identity(&cli)?;
                    harden_sandbox()?;
                    let mode = pipeline_mode(cli.json);
                    crate::pipeline::send_stream(
                        bundle,
                        &peer_record,
                        &mut std::io::stdin().lock(),
                        &mut std::io::stdout().lock(),
                        mode,
                    )
                }
            }
        }
        Command::Recv => {
            harden_memory()?;
            let bundle = load_identity(&cli)?;
            harden_sandbox()?;
            let mode = pipeline_mode(cli.json);
            crate::pipeline::recv_stream(
                bundle,
                &mut std::io::stdin().lock(),
                &mut std::io::stdout().lock(),
                mode,
            )
        }
        #[cfg(feature = "tor")]
        Command::Tui {
            ref nickname,
            ref pt,
        } => {
            // Ordering mirrors `serve`: memory locks BEFORE secrets,
            // identity + peer reads BEFORE the sandbox, the Tor tree as
            // the sanctioned read+write exception, Seccomp last.
            harden_memory()?;
            let keystore = cli
                .keystore
                .as_ref()
                .ok_or_else(|| CliError::Keystore("missing --keystore PATH".into()))?
                .clone();
            let passphrase = zeroize::Zeroizing::new(load_passphrase(&cli)?);
            let seeds = std::sync::Arc::new(crate::keystore::load_seeds(&keystore, &passphrase)?);
            // PT configuration is read PRE-sandbox alongside the peer
            // records (bridge lines are operational secrets; ADR-030).
            let pt_config = crate::pt::load_config(&keystore, pt)?;
            let peers_dir = crate::serve::tor_base_from_keystore(&keystore)?
                .parent()
                .map_or_else(|| std::path::PathBuf::from("peers"), |p| p.join("peers"));
            let mut peers = Vec::new();
            for name in crate::peers::list_names(&peers_dir)? {
                let identity = crate::peers::load_peer(&peers_dir, &name)?;
                peers.push((name, identity));
            }
            // Group state material (TODO B.2): the shared accept loop's
            // group branch decrypts `groups/*.enc` and
            // `keypackages/store.enc` AFTER the sandbox, so the passphrase is
            // captured here — pre-sandbox, mirroring `serve::run`.
            let group = std::sync::Arc::new(crate::serve::group_context_from_keystore(
                &keystore,
                &passphrase,
            )?);
            let tor_base = crate::serve::tor_base_from_keystore(&keystore)?;
            {
                use std::os::unix::fs::DirBuilderExt as _;
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&tor_base)
                    .map_err(CliError::Io)?;
            }
            // The two group-state directories must EXIST before the
            // ruleset pins them (Landlock's PathFd opens each path at
            // rule-add time), same as `tor_base` above. The grant stays
            // narrow: directories only, and the keystore FILE itself is
            // still unreachable post-sandbox (see
            // `serve::prepare_group_paths`).
            let (groups_dir, keypackages_dir) = crate::serve::prepare_group_paths(&keystore)?;
            crate::sandbox::restrict_filesystem_with_exceptions(
                &[
                    tor_base.as_path(),
                    groups_dir.as_path(),
                    keypackages_dir.as_path(),
                ],
                &[std::path::Path::new("/etc")],
            )?;
            crate::sandbox::restrict_syscalls()?;
            crate::tui::run(crate::tui::TuiConfig {
                seeds,
                peers,
                tor_base,
                nickname: nickname.clone(),
                pt: pt_config,
                group,
            })
        }
        #[cfg(feature = "tor")]
        Command::Serve {
            ref nickname,
            ref pt,
        } => {
            let keystore = cli
                .keystore
                .as_ref()
                .ok_or_else(|| CliError::Keystore("missing --keystore PATH".into()))?
                .clone();
            let passphrase = zeroize::Zeroizing::new(load_passphrase(&cli)?);
            crate::serve::run(&keystore, &passphrase, nickname, pt)
        }
        #[cfg(feature = "mesh")]
        Command::ServeMesh { ref wpa_ctrl } => {
            harden_memory()?;
            let bundle = load_identity(&cli)?;
            crate::mesh_serve::run(wpa_ctrl, bundle)
        }
        Command::ExportPairing => export_pairing(),
        Command::Fingerprint { ref peer } => match peer {
            Some(name) => {
                // Peer records are public key material only (like
                // `pair`); no memory hardening is required for them.
                let record = load_peer_record(&cli, name)?;
                let fp = umbra_crypto::kdf::identity_fingerprint(&record.ik_arr, &record.dsa);
                output::line(&output::hex(&fp));
                Ok(())
            }
            None => {
                harden_memory()?;
                let bundle = load_identity(&cli)?;
                harden_sandbox()?;
                let fp = umbra_crypto::kdf::identity_fingerprint(
                    &bundle.x25519.public_bytes(),
                    &bundle.dsa.public_bytes(),
                );
                output::line(&output::hex(&fp));
                Ok(())
            }
        },
        Command::PairingSas {
            own_payload,
            peer_payload,
        } => {
            let code = crate::pairing::pairing_sas(&own_payload, &peer_payload);
            output::line(&code.to_string());
            Ok(())
        }
        Command::Pair {
            ref peer_name,
            ref peer_payload,
            ref onion,
            ref mesh_addr,
            ref nym_addr,
        } => pair(
            &cli,
            peer_name,
            peer_payload,
            onion.as_deref(),
            mesh_addr.as_deref(),
            nym_addr.as_deref(),
        ),
        Command::Group(ref sub) => crate::group::dispatch(sub, &cli),
    }
}

/// Resolves a named peer record from the peers/ directory next to the
/// keystore.
fn load_peer_record(cli: &Cli, peer_name: &str) -> Result<crate::pairing::PeerIdentity, CliError> {
    let keystore_dir = cli
        .keystore
        .as_ref()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    crate::peers::load_peer(&keystore_dir.join("peers"), peer_name)
}

/// Maps the `--json` flag onto the pipe output framing.
fn pipeline_mode(json: bool) -> crate::pipeline::OutputMode {
    if json {
        crate::pipeline::OutputMode::Json
    } else {
        crate::pipeline::OutputMode::Binary
    }
}

/// Reads the keystore passphrase from `--passphrase-file` (FIRST LINE —
/// a trailing newline from editors or `echo` is not part of the
/// passphrase).
pub(crate) fn load_passphrase(cli: &Cli) -> Result<zeroize::Zeroizing<Vec<u8>>, CliError> {
    let path = cli.passphrase_file.as_ref().ok_or_else(|| {
        CliError::Keystore(
            "missing --passphrase-file (interactive prompts land with the TUI)".into(),
        )
    })?;
    let contents = std::fs::read(path).map_err(|e| {
        CliError::Keystore(format!(
            "cannot read passphrase file {}: {e}",
            path.display()
        ))
    })?;
    let first_line_end = contents
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(contents.len());
    let line = contents.get(..first_line_end).unwrap_or(&contents).to_vec();
    Ok(zeroize::Zeroizing::new(line))
}

/// Reads the hardware token's PIN from `--hw-pin-file` (first line —
/// same convention as [`load_passphrase`]).
fn load_hw_pin(cli: &Cli) -> Result<zeroize::Zeroizing<Vec<u8>>, CliError> {
    let path = cli
        .hw_pin_file
        .as_ref()
        .ok_or_else(|| CliError::Keystore("missing --hw-pin-file".into()))?;
    let contents = std::fs::read(path)
        .map_err(|e| CliError::Keystore(format!("cannot read PIN file {}: {e}", path.display())))?;
    let first_line_end = contents
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(contents.len());
    let line = contents.get(..first_line_end).unwrap_or(&contents).to_vec();
    Ok(zeroize::Zeroizing::new(line))
}

/// Computes the hardware-key HMAC response from `--hw-module`,
/// `--hw-pin-file`, and `--hw-key-label` — all three are required
/// together; a single combined error names whichever are missing.
fn hw_key_response(cli: &Cli) -> Result<zeroize::Zeroizing<[u8; 32]>, CliError> {
    let mut missing = Vec::new();
    if cli.hw_module.is_none() {
        missing.push("--hw-module");
    }
    if cli.hw_pin_file.is_none() {
        missing.push("--hw-pin-file");
    }
    if cli.hw_key_label.is_none() {
        missing.push("--hw-key-label");
    }
    if !missing.is_empty() {
        return Err(CliError::Keystore(format!(
            "hardware-key keystore requires all of --hw-module, --hw-pin-file, \
             --hw-key-label (missing: {})",
            missing.join(", ")
        )));
    }
    let module = cli
        .hw_module
        .as_ref()
        .ok_or_else(|| CliError::Keystore("missing --hw-module".into()))?;
    let label = cli
        .hw_key_label
        .as_ref()
        .ok_or_else(|| CliError::Keystore("missing --hw-key-label".into()))?;
    let pin = load_hw_pin(cli)?;
    let response = umbra_hwkey::challenge_response(
        module,
        &pin,
        label,
        crate::keystore::HARDWARE_KEY_CHALLENGE,
    )?;
    Ok(zeroize::Zeroizing::new(response))
}

/// Loads a keystore path + passphrase, returning the identity bundle.
fn load_identity(cli: &Cli) -> Result<IdentityBundle, CliError> {
    let path = cli
        .keystore
        .as_ref()
        .ok_or_else(|| CliError::Keystore("missing --keystore PATH".into()))?;
    let passphrase = load_passphrase(cli)?;
    if crate::keystore::is_hardware_key_gated(path)? {
        let response = hw_key_response(cli)?;
        crate::keystore::load_with_hardware_key(path, &passphrase, response.as_slice())
    } else {
        crate::keystore::load(path, &passphrase)
    }
}

/// Implements `umbra init`: new persistent identity keystore.
fn init_with(cli: &Cli) -> Result<(), CliError> {
    // Process hardening (mlockall) is intentionally NOT enforced here, for
    // the same reason `keygen` skips it: constrained environments (CI
    // sanitizers, hardened containers with low RLIMIT_MEMLOCK or pre-5.13
    // kernels) must still be able to create an identity keystore. This was
    // tried during this increment's final review and reverted after it
    // broke `mlockall` with ENOMEM in this project's own CI-like sandbox —
    // empirical confirmation, not just a hypothetical risk.
    let path = cli
        .keystore
        .as_ref()
        .ok_or_else(|| CliError::Keystore("missing --keystore PATH".into()))?;
    let passphrase = load_passphrase(cli)?;
    let hw_flags_present =
        cli.hw_module.is_some() || cli.hw_pin_file.is_some() || cli.hw_key_label.is_some();
    if hw_flags_present {
        let response = hw_key_response(cli)?;
        crate::keystore::save_with_hardware_key(
            path,
            &passphrase,
            response.as_slice(),
            &IdentityBundle::generate(),
        )?;
    } else {
        crate::keystore::save(path, &passphrase, &IdentityBundle::generate())?;
    }
    Ok(())
}

/// Implements `umbra pair`: store peer record + print the shared SAS code.
fn pair(
    cli: &Cli,
    peer_name: &str,
    peer_payload: &str,
    onion: Option<&str>,
    mesh_addr: Option<&str>,
    nym_addr: Option<&str>,
) -> Result<(), CliError> {
    // The peer record lives next to the keystore.
    let keystore_dir = cli
        .keystore
        .as_ref()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let peers_dir = keystore_dir.join("peers");
    crate::peers::save_peer(
        &peers_dir,
        peer_name,
        peer_payload,
        onion,
        mesh_addr,
        nym_addr,
    )?;

    // SAS: own payload (from the keystore identity) vs the peer payload.
    let bundle = load_identity(cli)?;
    let own_payload = crate::pairing::payload_for(&bundle)?;
    let code = crate::pairing::pairing_sas(&own_payload, peer_payload);
    output::line(&format!("sas={}", code));
    Ok(())
}

/// Implements `umbra export-pairing`: own payload on `stdout`.
fn export_pairing() -> Result<(), CliError> {
    let cli = Cli::parse();
    let bundle = load_identity(&cli)?;
    let payload = crate::pairing::payload_for(&bundle)?;
    output::line(&payload);
    Ok(())
}

/// Implements `umbra keygen`: fresh identity, public parts on `stdout`.
///
/// The process is hardened first (dumpable off, `RLIMIT_CORE = 0`,
/// `mlockall` with `MCL_FUTURE`), so both the guarded page and the
/// transient stack copy of the freshly generated bundle are RAM-locked,
/// non-dumpable, and swap-excluded (ADR-003/ADR-025). Residual gap: the
/// generator's return slot on the stack is not zeroized after the move
/// into the guard; zero-copy in-place generation is tracked in TODO A.1.
fn keygen(json: bool) -> Result<(), CliError> {
    // Process hardening (mlockall/Landlock) is intentionally NOT enforced
    // here: keygen emits PUBLIC material only and lives for milliseconds.
    // Constrained environments (CI sanitizers, hardened containers with
    // low RLIMIT_MEMLOCK or pre-5.13 kernels) must still be able to mint
    // identities. Secrets still spend their lifetime inside the guarded
    // buffer below, whose per-page mlock errors DO propagate.
    // The guarded buffer keeps the bundle alive (zeroized on drop) and
    // provides per-page mlock; it is intentionally not read afterwards.
    let _guarded = GuardedBuffer::new(IdentityBundle::generate()).map_err(CliError::from)?;
    let mut x25519 = [0u8; 32];
    let mut spk = [0u8; 32];
    let mut spk_signature = Vec::new();
    let mut kem = [0u8; 1184];
    let mut dsa = Vec::new();
    _guarded.with(|identity| {
        x25519 = identity.x25519.public_bytes();
        spk = identity.spk.public_bytes();
        spk_signature = identity.spk_signature.clone();
        kem = identity.kem.public_bytes();
        dsa = identity.dsa.public_bytes();
    });
    if json {
        // One NDJSON object; values are hex (a fixed safe charset, so no
        // JSON escaping is needed).
        let object = format!(
            "{{\"x25519-public\":\"{}\",\"spk-public\":\"{}\",\"spk-signature\":\"{}\",\"ml-kem-768-public\":\"{}\",\"ml-dsa-65-public\":\"{}\"}}",
            output::hex(&x25519),
            output::hex(&spk),
            output::hex(&spk_signature),
            output::hex(&kem),
            output::hex(&dsa),
        );
        output::line(&object);
    } else {
        output::line(&format!("x25519-public={}", output::hex(&x25519)));
        output::line(&format!("spk-public={}", output::hex(&spk)));
        output::line(&format!("spk-signature={}", output::hex(&spk_signature)));
        output::line(&format!("ml-kem-768-public={}", output::hex(&kem)));
        output::line(&format!("ml-dsa-65-public={}", output::hex(&dsa)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Regression: base64url pairing payloads may legitimately START
    /// with '-' (the base64url alphabet contains it); clap must not
    /// mistake them for flags. Observed in CI as `unexpected argument
    /// '-W' found` in ~1/64 of runs.
    #[test]
    fn hyphen_leading_pairing_payloads_parse() {
        let payload = "-W9wbGFjazEyMw";
        let cli = Cli::try_parse_from([
            "umbra",
            "pair",
            "--peer-name",
            "mirror",
            "--peer-payload",
            payload,
        ]);
        assert!(cli.is_ok(), "pair with hyphen-leading payload must parse");

        let cli = Cli::try_parse_from([
            "umbra",
            "pairing-sas",
            "--own-payload",
            payload,
            "--peer-payload",
            payload,
        ]);
        assert!(
            cli.is_ok(),
            "pairing-sas with hyphen-leading payloads must parse"
        );
    }

    /// Initializes a fresh SoftHSM2 token/key and returns a `Cli` value
    /// (with a `Command::Init` case, unused by callers that only read
    /// its fields) pre-populated with a fresh `--keystore`/
    /// `--passphrase-file`/`--hw-module`/`--hw-pin-file`/
    /// `--hw-key-label` set, plus the keystore path separately (so
    /// callers never need `.unwrap()` on `cli.keystore`). Must run
    /// under [`crate::hwkey_test_support::lock_token_dir`] — callers
    /// hold the guard for their whole test body.
    fn hardware_gated_test_cli(
        unique: &str,
    ) -> Result<(Cli, std::path::PathBuf), Box<dyn std::error::Error + Send + Sync>> {
        const TOKEN_DIR: &str = "/tmp/umbra-hwkey-softhsm-test-tokens";
        let _ = std::fs::remove_dir_all(TOKEN_DIR);
        std::fs::create_dir_all(TOKEN_DIR)?;
        let label = format!("umbra-cli-wiring-test-{unique}");
        let init = std::process::Command::new("softhsm2-util")
            .args([
                "--init-token",
                "--free",
                "--label",
                &label,
                "--pin",
                "1234",
                "--so-pin",
                "0000",
            ])
            .output()?;
        if !init.status.success() {
            return Err(format!(
                "softhsm2-util --init-token failed: {}",
                String::from_utf8_lossy(&init.stderr)
            )
            .into());
        }
        let module = crate::hwkey_test_support::softhsm2_module_path()?;
        let key_label = format!("{label}-key");
        umbra_hwkey::generate_hmac_key(&module, b"1234", &key_label)?;

        let pid = std::process::id();
        let passphrase_file =
            std::env::temp_dir().join(format!("umbra-cli-wiring-{unique}-{pid}-passphrase.txt"));
        std::fs::write(&passphrase_file, b"cli-wiring-test-passphrase\n")?;
        let pin_file =
            std::env::temp_dir().join(format!("umbra-cli-wiring-{unique}-{pid}-pin.txt"));
        std::fs::write(&pin_file, b"1234\n")?;
        let keystore_path =
            std::env::temp_dir().join(format!("umbra-cli-wiring-{unique}-{pid}-keystore.enc"));
        let _ = std::fs::remove_file(&keystore_path);

        let cli = Cli {
            json: false,
            keystore: Some(keystore_path.clone()),
            passphrase_file: Some(passphrase_file),
            hw_module: Some(module),
            hw_pin_file: Some(pin_file),
            hw_key_label: Some(key_label),
            command: Command::Init,
        };
        Ok((cli, keystore_path))
    }

    /// Round trip: `init_with` with all 3 hw flags creates a real
    /// hardware-gated keystore; `load_identity` with the same flags
    /// unlocks it twice, returning the same identity both times.
    #[test]
    fn hardware_key_cli_round_trip() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let _guard = crate::hwkey_test_support::lock_token_dir();
        let (cli, keystore_path) = hardware_gated_test_cli("roundtrip")?;
        init_with(&cli)?;
        assert!(
            crate::keystore::is_hardware_key_gated(&keystore_path)?,
            "init_with with all 3 hw flags must create a hardware-gated keystore"
        );

        let bundle_a = load_identity(&cli)?;
        let bundle_b = load_identity(&cli)?;
        assert_eq!(
            bundle_a.x25519.public_bytes(),
            bundle_b.x25519.public_bytes(),
            "loading the same hardware-gated file twice must return the same identity"
        );

        let _ = std::fs::remove_file(&keystore_path);
        const TOKEN_DIR: &str = "/tmp/umbra-hwkey-softhsm-test-tokens";
        let _ = std::fs::remove_dir_all(TOKEN_DIR);
        Ok(())
    }

    /// Some-but-not-all hw flags on `init_with` must fail with one
    /// combined, readable error naming every missing flag — and must
    /// not leave a partial keystore file behind.
    #[test]
    fn hardware_key_cli_partial_flags_error() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        let pid = std::process::id();
        let passphrase_file =
            std::env::temp_dir().join(format!("umbra-cli-wiring-partial-{pid}-passphrase.txt"));
        std::fs::write(&passphrase_file, b"whatever\n")?;
        let keystore_path =
            std::env::temp_dir().join(format!("umbra-cli-wiring-partial-{pid}-keystore.enc"));
        let _ = std::fs::remove_file(&keystore_path);

        let cli = Cli {
            json: false,
            keystore: Some(keystore_path.clone()),
            passphrase_file: Some(passphrase_file.clone()),
            hw_module: Some(std::path::PathBuf::from("/nonexistent/module.so")),
            hw_pin_file: None,
            hw_key_label: None,
            command: Command::Init,
        };
        let result = init_with(&cli);
        let error = result
            .err()
            .ok_or("expected an error for partial hw flags")?;
        let message = error.to_string();
        assert!(
            message.contains("missing: --hw-pin-file, --hw-key-label"),
            "error must name exactly the missing flags, got: {message}"
        );
        assert!(
            !keystore_path.exists(),
            "a rejected init must not leave a partial keystore file behind"
        );

        let _ = std::fs::remove_file(&passphrase_file);
        Ok(())
    }

    /// A plain keystore's `init_with`/`load_identity` behavior is
    /// unaffected by stray hw flags — `load_identity` must succeed via
    /// the passphrase-only path even when hw flags point at a module
    /// that does not exist (proving they are truly unused, not merely
    /// coincidentally valid).
    #[test]
    fn plain_keystore_ignores_stray_hw_flags()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pid = std::process::id();
        let passphrase_file =
            std::env::temp_dir().join(format!("umbra-cli-wiring-plain-{pid}-passphrase.txt"));
        std::fs::write(&passphrase_file, b"plain-test-passphrase\n")?;
        let keystore_path =
            std::env::temp_dir().join(format!("umbra-cli-wiring-plain-{pid}-keystore.enc"));
        let _ = std::fs::remove_file(&keystore_path);

        let cli_no_hw = Cli {
            json: false,
            keystore: Some(keystore_path.clone()),
            passphrase_file: Some(passphrase_file.clone()),
            hw_module: None,
            hw_pin_file: None,
            hw_key_label: None,
            command: Command::Init,
        };
        init_with(&cli_no_hw)?;
        assert!(
            !crate::keystore::is_hardware_key_gated(&keystore_path)?,
            "init_with with no hw flags must create a plain keystore"
        );

        let cli_with_stray_hw = Cli {
            hw_module: Some(std::path::PathBuf::from("/nonexistent/module.so")),
            hw_pin_file: Some(std::path::PathBuf::from("/nonexistent/pin.txt")),
            hw_key_label: Some("nonexistent-label".to_string()),
            ..cli_no_hw
        };
        let bundle = load_identity(&cli_with_stray_hw)?;
        assert_eq!(bundle.x25519.public_bytes().len(), 32);

        let _ = std::fs::remove_file(&keystore_path);
        let _ = std::fs::remove_file(&passphrase_file);
        Ok(())
    }

    /// `load_identity` against a hardware-gated file with NO hw flags
    /// must fail with the missing-flags error (proving it checks the
    /// file's own format before assuming passphrase-only), not a
    /// generic decryption failure.
    #[test]
    fn hardware_key_cli_load_without_flags_errors()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let _guard = crate::hwkey_test_support::lock_token_dir();
        let (cli, keystore_path) = hardware_gated_test_cli("noflags")?;
        init_with(&cli)?;

        let cli_no_hw = Cli {
            hw_module: None,
            hw_pin_file: None,
            hw_key_label: None,
            ..cli
        };
        let result = load_identity(&cli_no_hw);
        let error = result
            .err()
            .ok_or("expected an error loading a hardware-gated file without hw flags")?;
        let message = error.to_string();
        assert!(
            message.contains("missing: --hw-module, --hw-pin-file, --hw-key-label"),
            "error must name every missing hw flag, got: {message}"
        );

        let _ = std::fs::remove_file(&keystore_path);
        const TOKEN_DIR: &str = "/tmp/umbra-hwkey-softhsm-test-tokens";
        let _ = std::fs::remove_dir_all(TOKEN_DIR);
        Ok(())
    }
}
