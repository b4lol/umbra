//! `umbra group` subcommands: PQ-MLS group ("cell") management
//! (TODO B.2). Currently just `create`; later tasks in the same plan
//! add invite/join/send/receive operations to this same enum.

use std::path::{Path, PathBuf};

use clap::Subcommand;

use crate::cli::{Cli, CliError};

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
