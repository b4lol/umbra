#![forbid(unsafe_code)]
//! `umbra-nym`: standalone CLI for Umbra's Nym Mixnet adapter (TODO B.1).
//! See ADR-032 in DECISIONS.md.

use clap::Parser as _;
use umbra_nym_cli::cli::{Cli, Command};

/// Entry point: parses arguments and dispatches to `send-nym`/`serve-nym`
/// (see `umbra_nym_cli::cli` for the flow implementations and the
/// `serve-nym` NDJSON stdout contract).
///
/// # Errors
///
/// Returns whatever error the dispatched flow returns.
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();
    match cli.command {
        Command::SendNym {
            keystore,
            peer,
            nym_addr,
            mainnet,
        } => {
            let mut stdin = std::io::stdin();
            umbra_nym_cli::cli::run_send_nym(
                &keystore,
                &peer,
                nym_addr.as_deref(),
                mainnet,
                &mut stdin,
            )
        }
        Command::ServeNym {
            keystore,
            passphrase_file,
            nym_config,
            mainnet,
        } => umbra_nym_cli::cli::run_serve_nym(&keystore, &passphrase_file, &nym_config, mainnet),
    }
}
