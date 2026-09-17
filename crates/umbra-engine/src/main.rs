//! `umbra-engine` binary entry point (TODO B.3.1): a thin `clap`
//! wrapper around [`umbra_engine::run`]. See that function's own docs
//! and `docs/superpowers/specs/2026-09-15-engine-ui-separation-design.md`
//! for the full design.

use std::path::PathBuf;

/// `umbra-engine`'s two CLI arguments, both chosen and supplied by its
/// `umbra-gui` parent process (never derived here).
#[derive(clap::Parser)]
#[command(name = "umbra-engine", version, about)]
struct Cli {
    /// The `AF_UNIX` socket path to bind and listen on.
    #[arg(long, value_name = "PATH")]
    socket: PathBuf,
    /// The canonicalized parent directory of the one keystore/decoy-vault
    /// file this session will ever unlock — the Landlock sandbox's
    /// read-only scope.
    #[arg(long, value_name = "PATH")]
    keystore_dir: PathBuf,
    /// The canonicalized parent directory of the hardware-key PKCS#11
    /// module (TODO B.3 FIDO2 wiring), granted read-only alongside
    /// `--keystore-dir`. Omit if this session's `umbra-gui` wasn't
    /// launched with `--hw-module`.
    #[arg(long, value_name = "PATH")]
    hw_module_dir: Option<PathBuf>,
    /// Directory for this identity's Tor storage (persistent onion
    /// service keys + descriptor cache). Granted read-write in the
    /// Engine's Landlock ruleset at startup (TODO B.3 GUI messaging
    /// design, Phase 2).
    #[arg(long, value_name = "PATH")]
    tor_dir: PathBuf,
}

fn main() {
    let cli = <Cli as clap::Parser>::parse();
    if let Err(error) = umbra_engine::run(
        &cli.socket,
        &cli.keystore_dir,
        cli.hw_module_dir.as_deref(),
        &cli.tor_dir,
    ) {
        eprintln!("umbra-engine: {error}");
        std::process::exit(1);
    }
}
