//! Unmanaged pluggable-transport wiring (TODO B.1, ADR-030): builds the
//! validated [`PtProxyConfig`] from CLI flags plus an optional bridges
//! file, so `serve`, `send --onion` and `tui` share one code path.
//!
//! Threat/scope notes:
//! - Bridge lines are operational secrets (they reveal the user's
//!   censorship-circumvention infrastructure). They are read PRE-sandbox
//!   alongside the peer records (ADR-025 ordering) and are never logged.
//! - The PT proxy endpoint is LOOPBACK-ONLY (enforced again inside
//!   `umbra_net::tor::PtProxyConfig`): a remote proxy would see plaintext
//!   Tor entry traffic.
//! - Plain bridges WITHOUT a PT proxy are not wired in this increment:
//!   `--bridge` requires `--pt-socks`, and the inverse fails closed too —
//!   a half-configured censorship path must be loud, never a silent no-op.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use umbra_net::tor::PtProxyConfig;

use crate::cli::CliError;

/// Shared clap arguments for the Tor flows (`serve`, `send`, `tui`).
#[derive(Debug, clap::Args)]
pub struct PtArgs {
    /// Loopback SOCKS5 endpoint of an OS-managed pluggable-transport
    /// proxy (ADR-030 unmanaged model — umbra never spawns PT binaries).
    /// Requires at least one `--bridge` line carrying a PT name.
    #[arg(long, value_name = "127.0.0.1:PORT")]
    pub pt_socks: Option<SocketAddr>,

    /// Bridge line in Tor "Bridge …" format (repeatable). Extends the
    /// `bridges` file next to the keystore (file lines come first).
    #[arg(long = "bridge", value_name = "LINE")]
    pub bridges: Vec<String>,
}

/// Resolves the bridges file NEXT TO the keystore: `<keystore
/// parent>/bridges` — co-located with peer records so the pre-sandbox
/// reads stay inside the identity directory.
///
/// # Errors
///
/// Returns [`CliError::Keystore`] if the keystore path has no parent.
fn bridges_file_from_keystore(keystore: &Path) -> Result<PathBuf, CliError> {
    let parent = keystore
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| CliError::Keystore("keystore path has no parent directory".into()))?;
    Ok(parent.join("bridges"))
}

/// Builds the validated PT proxy configuration from the CLI flags plus
/// the bridges file (read PRE-sandbox; a missing file is an empty list,
/// not an error). Returns `None` when no PT options were given at all.
///
/// Protocol names are DERIVED from the bridge lines (the token between
/// the optional `Bridge` keyword and the address) so the proxy protocol
/// list can never drift out of sync with the configured bridges.
///
/// # Errors
///
/// Fails closed ([`CliError::Keystore`]) on: `--bridge` without
/// `--pt-socks`, `--pt-socks` without any PT bridge line, an unreadable
/// bridges file, or [`PtProxyConfig`] validation failures (non-loopback
/// endpoint, malformed lines).
pub fn load_config(keystore: &Path, args: &PtArgs) -> Result<Option<PtProxyConfig>, CliError> {
    if args.pt_socks.is_none() {
        if args.bridges.is_empty() {
            return Ok(None);
        }
        // Bridges without a PT endpoint are silently useless in this
        // increment (plain-bridge mode is not wired) — fail loudly.
        return Err(CliError::Keystore(
            "--bridge requires --pt-socks (plain-bridge mode is not wired; ADR-030)".into(),
        ));
    }
    let proxy_addr = args
        .pt_socks
        .ok_or_else(|| CliError::Keystore("missing --pt-socks".into()))?;

    // File lines first, flag lines extend (documented precedence).
    let mut bridges = read_bridges_file(&bridges_file_from_keystore(keystore)?)?;
    bridges.extend(args.bridges.iter().cloned());

    let mut protocols: Vec<String> = Vec::new();
    for line in &bridges {
        if let Some(name) = pt_name_of(line)
            && !protocols.contains(&name)
        {
            protocols.push(name);
        }
    }
    if protocols.is_empty() {
        return Err(CliError::Keystore(
            "--pt-socks needs at least one PT bridge line (e.g. \"Bridge obfs4 …\")".into(),
        ));
    }
    PtProxyConfig::new(proxy_addr, protocols, bridges)
        .map(Some)
        .map_err(|e| CliError::Keystore(format!("PT configuration: {e}")))
}

/// Reads one bridge line per row; blank lines and `#` comments are
/// skipped. A MISSING file is an empty list (fresh setups have no
/// bridges), an unreadable one is an error.
fn read_bridges_file(path: &Path) -> Result<Vec<String>, CliError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(CliError::Keystore(format!(
                "cannot read {}: {e}",
                path.display()
            )));
        }
    };
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect())
}

/// Extracts the PT protocol name from a bridge line: the first token
/// after the optional `Bridge` keyword, unless that token is already an
/// address (a plain bridge — no PT involvement, returns `None`).
fn pt_name_of(line: &str) -> Option<String> {
    let mut tokens = line.split_whitespace();
    let first = tokens.next()?;
    let token = if first.eq_ignore_ascii_case("bridge") {
        tokens.next()?
    } else {
        first
    };
    // A token that parses as host:port is a plain-bridge address.
    if token.parse::<SocketAddr>().is_ok() {
        return None;
    }
    Some(token.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Made-up-but-well-formed obfs4 bridge line (arti doc example; NOT
    /// a real bridge — hermetic parse fixture only).
    const FICTITIOUS_BRIDGE: &str = "Bridge obfs4 192.0.2.55:38114 \
        316E643333645F6D79216558614D3931657A5F5F \
        cert=YXJlIGZyZXF1ZW50bHkgZnVsbCBvZiBsaXR0bGUgbWVzc2FnZXMgeW91IGNhbiBmaW5kLg \
        iat-mode=0";

    /// Argument builder keeping the test bodies terse.
    fn args(pt_socks: Option<&str>, bridges: &[&str]) -> PtArgs {
        PtArgs {
            pt_socks: pt_socks.map(|s| s.parse()).transpose().ok().flatten(),
            bridges: bridges.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    /// No PT options at all means no PT configuration (None, no I/O).
    #[test]
    fn no_options_means_no_config() -> Result<(), Box<dyn std::error::Error>> {
        let keystore = Path::new("unused/keystore");
        assert!(load_config(keystore, &args(None, &[]))?.is_none());
        Ok(())
    }

    /// Half-configured censorship paths fail closed in both directions.
    #[test]
    fn half_configured_fails_closed() {
        let keystore = Path::new("unused/keystore");
        assert!(load_config(keystore, &args(None, &[FICTITIOUS_BRIDGE])).is_err());
        assert!(load_config(keystore, &args(Some("127.0.0.1:9051"), &[])).is_err());
        // A PT endpoint with only PLAIN bridges (no PT names) fails too.
        assert!(
            load_config(
                Path::new("unused/keystore"),
                &args(Some("127.0.0.1:9051"), &["192.0.2.1:443"]),
            )
            .is_err()
        );
    }

    /// Flags alone build a validated config; non-loopback endpoints are
    /// rejected by the umbra-net constructor.
    #[test]
    fn flags_build_config() {
        let keystore = Path::new("unused/keystore");
        assert!(
            load_config(
                keystore,
                &args(Some("127.0.0.1:9051"), &[FICTITIOUS_BRIDGE])
            )
            .is_ok()
        );
        assert!(
            load_config(
                keystore,
                &args(Some("192.0.2.1:9051"), &[FICTITIOUS_BRIDGE])
            )
            .is_err()
        );
    }

    /// The bridges file (missing → empty; comments/blank lines skipped)
    /// combines with flag lines, file first.
    #[test]
    fn bridges_file_combines_with_flags() -> Result<(), Box<dyn std::error::Error>> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir =
            std::env::temp_dir().join(format!("umbra-pt-test-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let keystore = dir.join("keystore");

        // Missing file: flags alone decide.
        assert!(
            load_config(
                &keystore,
                &args(Some("127.0.0.1:9051"), &[FICTITIOUS_BRIDGE])
            )
            .is_ok()
        );

        // File with a comment, a blank line and one bridge.
        std::fs::write(
            dir.join("bridges"),
            format!("# operational bridges\n\n{FICTITIOUS_BRIDGE}\n"),
        )?;
        assert!(load_config(&keystore, &args(Some("127.0.0.1:9051"), &[])).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
