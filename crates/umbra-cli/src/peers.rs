//! Paired-peer record store (TODO A.3): one file per peer under a
//! `peers/` directory next to the keystore, containing the peer's
//! base64url pairing payload and an optional `.onion` service address.
//! The payload is internally signed (its embedded SPK signature is
//! verified at parse); binding it to the *expected* peer happens out of
//! band via the SAS code.

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

/// Lists peer record NAMES found under `peers_dir` (sorted). A missing
/// directory is an empty list, not an error (fresh keystore).
///
/// # Errors
///
/// Returns [`CliError::Keystore`] if the directory exists but cannot be
/// read.
pub fn list_names(peers_dir: &Path) -> Result<Vec<String>, CliError> {
    let mut names = Vec::new();
    let entries = match fs::read_dir(peers_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(names),
        Err(e) => {
            return Err(CliError::Keystore(format!(
                "cannot read {}: {e}",
                peers_dir.display()
            )));
        }
    };
    for entry in entries {
        let path = entry
            .map_err(|e| CliError::Keystore(format!("peer entry: {e}")))?
            .path();
        if path.extension().is_some_and(|ext| ext == "peer")
            && let Some(stem) = path.file_stem().and_then(|stem| stem.to_str())
        {
            names.push(stem.to_string());
        }
    }
    names.sort();
    Ok(names)
}

/// Validates an `.onion` address or fails with a transport-flavored
/// error (shared by the record store and the outbound flow).
///
/// # Errors
///
/// Returns [`CliError::Io`] for an invalid address.
pub fn validate_onion(address: &str) -> Result<(), CliError> {
    // The unvalidated address is NOT echoed into the error: hostile
    // input must not reach stderr verbatim.
    umbra_net::addr::OnionAddr::parse(address)
        .map(|_addr| ())
        .map_err(|_e| {
            CliError::Io(std::io::Error::other(
                "invalid onion address (56-char base32 v3 expected)",
            ))
        })
}

/// Validates a Wi-Fi Direct P2P Device Address or fails with a
/// transport-flavored error (shared by the record store and the mesh
/// transport flow). Mirrors [`validate_onion`].
///
/// # Errors
///
/// Returns [`CliError::Io`] for an invalid address.
pub fn validate_mesh_addr(address: &str) -> Result<(), CliError> {
    umbra_net::addr::MeshPeerAddr::parse(address)
        .map(|_addr| ())
        .map_err(|_e| {
            CliError::Io(std::io::Error::other(
                "invalid mesh address (aa:bb:cc:dd:ee:ff expected)",
            ))
        })
}

/// Lightweight format check for a Nym mixnet address
/// (`identity.encryption@gateway`, three non-empty segments) — NOT the
/// authoritative parse (that lives in the separate `umbra-nym-cli`
/// crate, which alone depends on `nym-sdk`; see
/// docs/superpowers/specs/2026-09-06-nym-mixnet-design.md). Mirrors
/// [`validate_mesh_addr`].
///
/// # Errors
///
/// Returns [`CliError::Io`] for a string that doesn't have the
/// `<non-empty>.<non-empty>@<non-empty>` shape.
pub fn validate_nym_addr(addr: &str) -> Result<(), CliError> {
    let invalid = || {
        CliError::Io(std::io::Error::other(
            "invalid nym address (identity.encryption@gateway expected)",
        ))
    };
    let (identity_and_encryption, gateway) = addr.split_once('@').ok_or_else(invalid)?;
    let (identity, encryption) = identity_and_encryption
        .split_once('.')
        .ok_or_else(invalid)?;
    if identity.is_empty() || encryption.is_empty() || gateway.is_empty() {
        return Err(invalid());
    }
    Ok(())
}

/// Saves (or overwrites) a peer's pairing payload under `name`, with an
/// optional `.onion` service address, an optional Wi-Fi Direct mesh
/// address, and/or an optional Nym mixnet address. The payload is
/// parsed (SPK signature verified) and all addresses are validated
/// BEFORE anything touches disk, so a typo fails here instead of at
/// first use.
///
/// Record file format: line 1 = base64url payload, optional further
/// lines = `onion <address>`, `mesh <address>`, and/or `nym <address>`
/// (any order, any subset present).
///
/// # Errors
///
/// Returns [`CliError`] on name validation, invalid payload or address,
/// or I/O failure.
pub fn save_peer(
    peers_dir: &Path,
    name: &str,
    payload_b64: &str,
    onion: Option<&str>,
    mesh_addr: Option<&str>,
    nym_addr: Option<&str>,
) -> Result<(), CliError> {
    parse_payload(payload_b64)?;
    let mut contents = format!("{payload_b64}\n");
    if let Some(address) = onion {
        validate_onion(address)?;
        contents.push_str(&format!("onion {address}\n"));
    }
    if let Some(address) = mesh_addr {
        validate_mesh_addr(address)?;
        contents.push_str(&format!("mesh {address}\n"));
    }
    if let Some(address) = nym_addr {
        validate_nym_addr(address)?;
        contents.push_str(&format!("nym {address}\n"));
    }
    let path = record_path(peers_dir, name)?;
    fs::create_dir_all(peers_dir)
        .map_err(|e| CliError::Keystore(format!("cannot create {}: {e}", peers_dir.display())))?;
    fs::write(&path, contents)
        .map_err(|e| CliError::Keystore(format!("cannot write {}: {e}", path.display())))
}

/// Loads a peer's record by name and parses it (verifying the embedded
/// SPK signature and, when present, the `.onion` address). Unknown
/// record lines are rejected instead of silently ignored.
///
/// # Errors
///
/// Returns [`CliError`] on missing file, invalid payload, invalid
/// address, or an unknown record line.
pub fn load_peer(peers_dir: &Path, name: &str) -> Result<crate::pairing::PeerIdentity, CliError> {
    let path = record_path(peers_dir, name)?;
    let raw = fs::read_to_string(&path)
        .map_err(|e| CliError::Keystore(format!("cannot read {}: {e}", path.display())))?;
    let mut lines = raw.lines();
    let payload_line = lines.next().unwrap_or_default().trim();
    let mut identity = parse_payload(payload_line)?;
    for address_line in lines {
        let address_line = address_line.trim();
        if address_line.is_empty() {
            continue; // trailing newline
        }
        if let Some(address) = address_line.strip_prefix("onion ") {
            let address = address.trim();
            validate_onion(address)?;
            identity.onion = Some(address.to_string());
        } else if let Some(address) = address_line.strip_prefix("mesh ") {
            let address = address.trim();
            validate_mesh_addr(address)?;
            identity.mesh_addr = Some(address.to_string());
        } else if let Some(address) = address_line.strip_prefix("nym ") {
            let address = address.trim();
            validate_nym_addr(address)?;
            identity.nym_addr = Some(address.to_string());
        } else {
            return Err(CliError::Keystore(format!(
                "unknown peer-record line: {address_line}"
            )));
        }
    }
    Ok(identity)
}
