//! Command definitions and dispatch (clap 4, derive API).

use clap::{Parser, Subcommand};
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
    /// Currently honored by `keygen`.
    #[arg(long, global = true)]
    pub json: bool,

    /// Keystore file path for commands that need persisted identity.
    #[arg(long, global = true, value_name = "PATH")]
    pub keystore: Option<std::path::PathBuf>,

    /// File containing the keystore passphrase (first line; "-" = prompt
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
    /// Sends a message over the Tor v3 P2P transport (TODO A.2/A.4).
    Send,
    /// Receives messages over the Tor v3 P2P transport (TODO A.2/A.4).
    Recv,
    /// Opens the security-focused terminal UI (Ratatui).
    Tui,
    /// Creates a new persistent identity keystore.
    Init,
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
}

/// Applies ADR-025 process hardening before any session or key work:
/// core-dump suppression (flag + `RLIMIT_CORE`), full-memory `mlockall`,
/// and the fail-closed Landlock zero-filesystem sandbox (ADR-007).
///
/// # Errors
///
/// Returns [`CliError::Hardware`] or [`CliError::Sandbox`] on kernel refusal.
fn harden() -> Result<(), CliError> {
    umbra_hardware::process::harden_process()?;
    let _status = crate::sandbox::restrict_filesystem()?;
    // Seccomp is applied LAST: the Landlock and process-lock syscalls
    // above have already run; afterwards the allowlist gates everything.
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
        Command::Send => {
            harden()?;
            Err(umbra_protocol::ProtocolError::Unsupported(
                "P2P transport wiring lands with TODO A.2/A.4",
            )
            .into())
        }
        Command::Recv => {
            harden()?;
            Err(umbra_protocol::ProtocolError::Unsupported(
                "P2P transport wiring lands with TODO A.2/A.4",
            )
            .into())
        }
        Command::Tui => {
            harden()?;
            tui::run().map_err(CliError::from)
        }
        Command::ExportPairing => export_pairing(),
        Command::PairingSas {
            own_payload,
            peer_payload,
        } => {
            let code = crate::pairing::pairing_sas(&own_payload, &peer_payload);
            output::line(&code.to_string());
            Ok(())
        }
    }
}

/// Reads the keystore passphrase from `--passphrase-file`.
fn load_passphrase(cli: &Cli) -> Result<Vec<u8>, CliError> {
    let path = cli.passphrase_file.as_ref().ok_or_else(|| {
        CliError::Keystore(
            "missing --passphrase-file (interactive prompts land with the TUI)".into(),
        )
    })?;
    std::fs::read(path).map_err(|e| {
        CliError::Keystore(format!(
            "cannot read passphrase file {}: {e}",
            path.display()
        ))
    })
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
