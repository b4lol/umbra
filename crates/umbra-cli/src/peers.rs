//! Paired-peer record store (TODO A.3): one file per peer under a
//! `peers/` directory next to the keystore, containing the peer's
//! base64url pairing payload. The payload is self-authenticating
//! (SPK signature verified at parse).

use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::CliError;
use crate::pairing::parse_payload;

/// Resolves the record file for `name` under `peers_dir`.
fn record_path(peers_dir: &Path, name: &str) -> Result<PathBuf, CliError> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(CliError::Keystore(
            "peer name must be [A-Za-z0-9_-]+".into(),
        ));
    }
    Ok(peers_dir.join(format!("{name}.peer")))
}

/// Saves (or overwrites) a peer's pairing payload under `name`.
///
/// # Errors
///
/// Returns [`CliError`] on name validation or I/O failure.
pub fn save_peer(peers_dir: &Path, name: &str, payload_b64: &str) -> Result<(), CliError> {
    let path = record_path(peers_dir, name)?;
    fs::create_dir_all(peers_dir)
        .map_err(|e| CliError::Keystore(format!("cannot create {}: {e}", peers_dir.display())))?;
    fs::write(&path, format!("{payload_b64}\n"))
        .map_err(|e| CliError::Keystore(format!("cannot write {}: {e}", path.display())))
}

/// Loads a peer's pairing payload by name and parses it (verifying the
/// embedded SPK signature).
///
/// # Errors
///
/// Returns [`CliError`] on missing file or invalid payload.
pub fn load_peer(peers_dir: &Path, name: &str) -> Result<crate::pairing::PeerIdentity, CliError> {
    let path = record_path(peers_dir, name)?;
    let raw = fs::read_to_string(&path)
        .map_err(|e| CliError::Keystore(format!("cannot read {}: {e}", path.display())))?;
    parse_payload(raw.trim())
}
