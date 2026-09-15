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
}

fn main() {
    let cli = <Cli as clap::Parser>::parse();
    if let Err(error) = umbra_engine::run(&cli.socket, &cli.keystore_dir) {
        eprintln!("umbra-engine: {error}");
        std::process::exit(1);
    }
}
