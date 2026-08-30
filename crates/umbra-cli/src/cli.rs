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
        Command::Keygen => keygen(),
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
    }
}

/// Implements `umbra keygen`: fresh identity, public parts on `stdout`.
///
/// The process is hardened first (dumpable off, `RLIMIT_CORE = 0`,
/// `mlockall` with `MCL_FUTURE`), so both the guarded page and the
/// transient stack copy of the freshly generated bundle are RAM-locked,
/// non-dumpable, and swap-excluded (ADR-003/ADR-025). Residual gap: the
/// generator's return slot on the stack is not zeroized after the move
/// into the guard; zero-copy in-place generation is tracked in TODO A.1.
fn keygen() -> Result<(), CliError> {
    harden()?;
    let guarded = GuardedBuffer::new(IdentityBundle::generate()).map_err(CliError::from)?;
    let mut x25519 = [0u8; 32];
    let mut spk = [0u8; 32];
    let mut spk_signature = Vec::new();
    let mut kem = [0u8; 1184];
    let mut dsa = Vec::new();
    guarded.with(|identity| {
        x25519 = identity.x25519.public_bytes();
        spk = identity.spk.public_bytes();
        spk_signature = identity.spk_signature.clone();
        kem = identity.kem.public_bytes();
        dsa = identity.dsa.public_bytes();
    });
    output::line(&format!("x25519-public={}", output::hex(&x25519)));
    output::line(&format!("spk-public={}", output::hex(&spk)));
    output::line(&format!("spk-signature={}", output::hex(&spk_signature)));
    output::line(&format!("ml-kem-768-public={}", output::hex(&kem)));
    output::line(&format!("ml-dsa-65-public={}", output::hex(&dsa)));
    Ok(())
}
