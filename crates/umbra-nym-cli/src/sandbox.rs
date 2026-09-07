//! Nym-specific sandbox profile (TODO B.1). Filesystem needs are already
//! served by `umbra_cli::sandbox::restrict_filesystem_with_exceptions`
//! directly (already general-purpose, reused as-is — no wrapper needed).
//! This module adds ONLY the Seccomp profile.
//!
//! Sized from an OBSERVED real connection attempt against Nym's live
//! Sandbox testnet (Task 12), not assumed up front. The socket-family
//! part of the profile needed NO widening at all: `(AF_INET, SOCK_STREAM)`
//! and `(AF_UNIX, SOCK_STREAM)` — the exact same two rules the main
//! workspace's default `restrict_syscalls()` installs — were sufficient
//! for a full `NymClient::connect` round trip. The real gap was three
//! EXTRA BASE SYSCALLS: `nym-sdk`'s SQLite storage backend
//! (`nym-client-core-surb-storage`'s `StorageManager::init`) calls the
//! raw, non-`*at` `mkdir(2)` via `std::fs::create_dir_all` and the raw
//! `unlink(2)` via SQLite's unix VFS (`unixDelete` deleting a
//! not-yet-existing journal/WAL file), and `nym-pemstore`'s
//! `write_pem_file` (identity key persistence) finishes with
//! `std::fs::set_permissions`, which calls the raw `chmod(2)`. Arti's own
//! storage layer — what the upstream base list was originally sized for —
//! apparently never needed any of the three, using only the `*at` family
//! (`mkdirat`/`unlinkat`/`fchmodat`, all already on the list) instead. See
//! Task 12's report for the exact denial observed at each step.
//!
//! `umbra_cli::sandbox::install_filter` cannot express this: it hardcodes
//! a call to `umbra_cli::sandbox::allowed_syscalls()` internally with no
//! extension point, only a caller-supplied `socket()` rule set (by
//! design — see that function's own docs). Since the gap here is extra
//! BASE syscalls, not a wider socket rule, this module cannot reuse
//! `install_filter` and instead builds its own filter — but it DOES
//! reuse both `umbra_cli::sandbox::allowed_syscalls()` (now `pub`) for
//! the base list and `umbra_cli::sandbox::socket_rule` for the socket()
//! conditions, appending only the three additions on top. `umbra-cli`'s
//! `allowed_syscalls()` is the single source of truth for the shared
//! base list; nothing here is a copy of it.

use std::collections::BTreeMap;

use seccompiler::{
    apply_filter, BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch,
};
use umbra_cli::sandbox::{allowed_syscalls, socket_rule};

/// Builds and installs a Seccomp-BPF filter from
/// `umbra_cli::sandbox::allowed_syscalls()` plus the three Nym-specific
/// additions (`SYS_mkdir`, `SYS_unlink`, `SYS_chmod` — see the module
/// docs for why Task 12's empirical probe found them missing) and a
/// caller-supplied `socket()` rule set. Same fail-closed, non-killing
/// `Errno(EPERM)` design as `umbra_cli::sandbox::install_filter` —
/// duplicated here (rather than reused) only because that function has
/// no hook for extra base syscalls; see the module docs for why that
/// hook is needed.
fn install_filter_nym(
    socket_rules: Vec<SeccompRule>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(target_arch = "x86_64")]
    let arch = TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    let arch = TargetArch::aarch64;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Ok(());

    // The shared base list (single source of truth in umbra-cli) plus
    // the three Task 12 additions.
    let mut base = allowed_syscalls();
    base.extend_from_slice(&[libc::SYS_mkdir, libc::SYS_unlink, libc::SYS_chmod]);

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = base
        .into_iter()
        .map(|number| (number, Vec::new()))
        .collect();
    rules.insert(libc::SYS_socket, socket_rules);
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        arch,
    )?;
    let program: BpfProgram = filter.try_into()?;
    apply_filter(&program)?;
    Ok(())
}

/// Applies the Nym Seccomp-BPF allowlist to the calling thread.
///
/// The SAME socket kill-switch as the main workspace's default
/// `restrict_syscalls()` — only `(AF_INET, SOCK_STREAM)` and
/// `(AF_UNIX, SOCK_STREAM)` — widened by exactly three base syscalls
/// (`mkdir`, `unlink`, `chmod`) that Task 12's live Sandbox-testnet probe
/// found `nym-sdk`'s storage backend and `nym-pemstore`'s key persistence
/// need. IPv6 and UDP (including DNS `:53`) stay blocked, and a full
/// mixnet connection round trip never touched either — but note that
/// observation is specific to the environment Task 12 probed in, whose
/// `/etc/nsswitch.conf` resolves `hosts` through `resolve
/// [!UNAVAIL=return]` BEFORE `dns` — i.e. name resolution reaches
/// `systemd-resolved` over an AF_UNIX stream socket (`nss-resolve`) and
/// never falls through to the UDP-sending `dns` module at all. This is
/// a property of the deployment, not of Nym: a host whose resolver
/// stack talks UDP to `:53`
/// directly, or whose gateway is reachable only over IPv6, would need
/// this kill-switch widened the way `restrict_syscalls_mesh` widens it
/// for its own transport. It is deliberately NOT widened pre-emptively:
/// see ADR-031 on keeping each profile as narrow as its transport
/// actually requires.
///
/// Thread model: identical to `restrict_syscalls` — seccomp filters are
/// inherited across `clone`, so this MUST run before the Tokio runtime
/// (and its worker threads) is created.
///
/// # Errors
///
/// Returns an error if the filter cannot be built or installed (Seccomp
/// backend failure), or if a socket rule cannot be constructed.
pub fn restrict_syscalls_nym() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    install_filter_nym(vec![
        socket_rule(libc::AF_INET, libc::SOCK_STREAM)?,
        socket_rule(libc::AF_UNIX, libc::SOCK_STREAM)?,
    ])
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::restrict_syscalls_nym;

    /// Unique temp directory for this test process.
    fn temp_dir(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        std::env::temp_dir().join(format!(
            "umbra-nym-sandbox-test-{}-{nanos}-{name}",
            std::process::id()
        ))
    }

    /// Regression test for Task 12's three additions PLUS a proof that
    /// the socket kill-switch stays exactly as narrow as the default
    /// profile's (no accidental widening). Hermetic: no live network,
    /// mirrors the main workspace's `ipv6_and_udp_sockets_are_blocked`
    /// structure. In-process: the filter applies to the spawned thread
    /// only, so the test runner is unaffected.
    #[test]
    fn nym_profile_allows_raw_mkdir_unlink_chmod_and_default_sockets_only(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let handle =
            std::thread::spawn(|| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                restrict_syscalls_nym()?;

                // The three additions: exercised via std's SAFE wrappers,
                // which is exactly how nym-sdk/nym-pemstore trip the raw
                // (non-`*at`) syscalls in production.
                let dir = temp_dir("mkdir");
                std::fs::create_dir_all(&dir)?;
                // A second call on an ALREADY-EXISTING directory is the
                // exact shape nym-sdk's storage init hits (config_dir
                // pre-created by the caller) — this is what raw `mkdir`
                // being blocked broke before this profile existed.
                std::fs::create_dir_all(&dir)?;

                let file = dir.join("probe.txt");
                std::fs::write(&file, b"probe")?;
                let mut perms = std::fs::metadata(&file)?.permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(&file, perms)?;
                std::fs::remove_file(&file)?;

                // Socket kill-switch: identical to the default profile —
                // NOT a blanket opendoor.
                let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
                drop(listener);
                assert!(
                    std::net::UdpSocket::bind("127.0.0.1:0").is_err(),
                    "SOCK_DGRAM (e.g. DNS :53) must still be blocked"
                );
                assert!(
                    std::net::TcpListener::bind("[::1]:0").is_err(),
                    "AF_INET6 must still be blocked"
                );

                Ok(())
            });
        match handle.join() {
            Ok(result) => result,
            Err(_panic) => Err("worker thread panicked".into()),
        }
    }
}
