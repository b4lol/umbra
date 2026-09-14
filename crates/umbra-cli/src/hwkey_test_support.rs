//! Shared hermetic-test support for hardware-key (PKCS#11/SoftHSM2)
//! tests. Used by `keystore.rs`'s and `cli.rs`'s test modules, which
//! compile into the SAME `umbra_cli` lib test binary (a crate's
//! `#[cfg(test)]` code is one binary, regardless of how many source
//! files declare `mod tests`) — a lock private to just one of those two
//! test modules would NOT protect against the other one's concurrent
//! SoftHSM2 access, since SoftHSM2's on-disk token store is one fixed,
//! workspace-wide location (`SOFTHSM2_CONF`, forced via this
//! workspace's root `.cargo/config.toml`). This module exists
//! specifically to be shared between them.

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

/// Serializes ALL hardware-key hermetic tests in this crate's test
/// binary against each other. Rust's default test harness runs
/// `#[test]` functions from one binary on parallel threads; any two
/// hardware-key tests in this crate (whether declared in `keystore.rs`
/// or `cli.rs`) touching the shared SoftHSM2 token store at the same
/// time would race (observed directly during the keystore-format
/// increment: `Pkcs11(Pkcs11(GeneralError, Initialize))`). Holding this
/// lock for a test's entire SoftHSM2-touching body is the fix.
///
/// NOTE: this lock only protects tests within THIS crate's one lib test
/// binary. Safety against `umbra-hwkey`'s own separate test binary
/// (which shares the same on-disk token directory) rests on the
/// undocumented-by-cargo-but-currently-true invariant that stock
/// `cargo test` runs different test binaries SEQUENTIALLY, never
/// concurrently — this would break under `cargo-nextest` (which
/// deliberately parallelizes across binaries) or two concurrent `cargo
/// test` invocations (e.g. two worktree sessions building at once).
pub(crate) static TEST_TOKEN_LOCK: Mutex<()> = Mutex::new(());

/// Acquires [`TEST_TOKEN_LOCK`], recovering from poisoning rather than
/// panicking (a prior test's panic must not permanently wedge every
/// later hardware-key test in this binary).
pub(crate) fn lock_token_dir() -> MutexGuard<'static, ()> {
    match TEST_TOKEN_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Locates the SoftHSM2 PKCS#11 module: an explicit
/// `UMBRA_SOFTHSM2_MODULE` env var override first, then the common
/// Fedora (`/usr/lib64/pkcs11/`) and Debian/Ubuntu (`/usr/lib/softhsm/`)
/// install paths, in that order.
///
/// # Errors
///
/// Returns an error if none of the known paths exist and no override
/// is set.
pub(crate) fn softhsm2_module_path() -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    if let Ok(path) = std::env::var("UMBRA_SOFTHSM2_MODULE") {
        return Ok(PathBuf::from(path));
    }
    for candidate in [
        "/usr/lib64/pkcs11/libsofthsm2.so",
        "/usr/lib/softhsm/libsofthsm2.so",
    ] {
        if std::path::Path::new(candidate).exists() {
            return Ok(PathBuf::from(candidate));
        }
    }
    Err("no SoftHSM2 PKCS#11 module found at any known path; set UMBRA_SOFTHSM2_MODULE".into())
}
