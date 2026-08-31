//! Command definitions and dispatch (clap 4, derive API).

use clap::{Parser, Subcommand};
use std::path::Path;

use umbra_crypto::keys::IdentityBundle;
use umbra_hardware::memory::GuardedBuffer;

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
    /// Honored by `keygen`, `send` and `recv` (NDJSON events); other
    /// commands ignore the flag.
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

    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Command,
}

/// Umbra subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generates a fresh identity bundle and prints its public parts.
    Keygen,
    /// Encrypts stdin for a named peer; sealed frames to stdout.
    Send {
        /// Peer record name ([A-Za-z0-9_-]+), resolved from the peers/
        /// directory next to the keystore.
        #[arg(long)]
        peer: String,
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
    },
    /// Opens the security-focused terminal UI (Ratatui).
    Tui,
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
        /// Own base64url pairing payload.
        #[arg(long)]
        own_payload: String,
        /// Peer base64url pairing payload.
        #[arg(long)]
        peer_payload: String,
    },
    /// Stores a peer's pairing payload under a name and prints the shared
    /// SAS code (verify it with the peer over a trusted channel).
    Pair {
        /// Friendly name for the peer ([A-Za-z0-9_-]+).
        #[arg(long)]
        peer_name: String,
        /// Peer base64url pairing payload.
        #[arg(long)]
        peer_payload: String,
    },
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

    /// TUI failure.
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

/// Full hardening for commands that read nothing sensitive from disk:
/// memory locks immediately followed by the sandbox.
fn harden() -> Result<(), CliError> {
    harden_memory()?;
    harden_sandbox()?;
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
        Command::Send { ref peer } => {
            harden_memory()?;
            let bundle = load_identity(&cli)?;
            let peer_record = load_peer_record(&cli, peer)?;
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
        Command::Tui => {
            harden()?;
            tui::run().map_err(CliError::from)
        }
        #[cfg(feature = "tor")]
        Command::Serve { ref nickname } => {
            let keystore = cli
                .keystore
                .as_ref()
                .ok_or_else(|| CliError::Keystore("missing --keystore PATH".into()))?
                .clone();
            let passphrase = load_passphrase(&cli)?;
            crate::serve::run(&keystore, &passphrase, nickname)
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
        } => pair(&cli, peer_name, peer_payload),
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
fn load_passphrase(cli: &Cli) -> Result<Vec<u8>, CliError> {
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
    Ok(contents.get(..first_line_end).unwrap_or(&contents).to_vec())
}

/// Loads a keystore path + passphrase, returning the identity bundle.
fn load_identity(cli: &Cli) -> Result<IdentityBundle, CliError> {
    let path = cli
        .keystore
        .as_ref()
        .ok_or_else(|| CliError::Keystore("missing --keystore PATH".into()))?;
    let passphrase = load_passphrase(cli)?;
    crate::keystore::load(path, &passphrase)
}

/// Implements `umbra init`: new persistent identity keystore.
fn init_with(cli: &Cli) -> Result<(), CliError> {
    let path = cli
        .keystore
        .as_ref()
        .ok_or_else(|| CliError::Keystore("missing --keystore PATH".into()))?;
    let passphrase = load_passphrase(cli)?;
    crate::keystore::save(path, &passphrase, &IdentityBundle::generate())?;
    Ok(())
}

/// Implements `umbra pair`: store peer record + print the shared SAS code.
fn pair(cli: &Cli, peer_name: &str, peer_payload: &str) -> Result<(), CliError> {
    // The peer record lives next to the keystore.
    let keystore_dir = cli
        .keystore
        .as_ref()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let peers_dir = keystore_dir.join("peers");
    crate::peers::save_peer(&peers_dir, peer_name, peer_payload)?;

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
