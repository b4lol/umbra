//! Command definitions and dispatch (clap 4, derive API).

use clap::{Parser, Subcommand};

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

    /// TUI failure.
    #[error(transparent)]
    Tui(#[from] tui::TuiError),
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
        Command::Send => Err(umbra_protocol::ProtocolError::Unsupported(
            "P2P transport wiring lands with TODO A.2/A.4",
        )
        .into()),
        Command::Recv => Err(umbra_protocol::ProtocolError::Unsupported(
            "P2P transport wiring lands with TODO A.2/A.4",
        )
        .into()),
        Command::Tui => tui::run().map_err(CliError::from),
    }
}

/// Implements `umbra keygen`: fresh identity, public parts on `stdout`.
fn keygen() -> Result<(), CliError> {
    let identity = umbra_crypto::keys::IdentityBundle::generate();
    let x25519 = identity.x25519.public_bytes();
    let kem = identity.kem.public_bytes();
    let dsa = identity.dsa.public_bytes();
    output::line(&format!("x25519-public={}", output::hex(&x25519)));
    output::line(&format!("ml-kem-768-public={}", output::hex(&kem)));
    output::line(&format!("ml-dsa-65-public={}", output::hex(&dsa)));
    Ok(())
}
